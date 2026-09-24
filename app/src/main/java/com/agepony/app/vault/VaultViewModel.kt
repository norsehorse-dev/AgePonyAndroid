package com.agepony.app.vault

import android.app.Application
import android.os.Build
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.agepony.app.security.BiometricGate
import com.agepony.app.security.BiometricGateException
import com.agepony.app.security.PasswordVault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

//
// Owns the Vault across configuration changes and drives the biometric flow.
// The biometric gate yields an authenticated Cipher; the VK is wrapped/unwrapped
// with the KEK (KeystoreMasterKey) and then handed to the Vault, which holds it
// in memory and seals/opens vault.dat. Mirrors the unlock/bootstrap semantics of
// iOS's Vault.swift, split out so the Vault itself stays free of Android UI types.
//
// 4.0.0 adds an app-owned password/PIN unlock (PasswordVault) that coexists with
// biometric, and the duress/decoy wipe that rides on it.
//
class VaultViewModel(app: Application) : AndroidViewModel(app) {

    // One Vault per process: the share-sheet activity and the main one must never hold two
    // copies of the vault in memory, or a save from one could overwrite the other's changes.
    val vault = SharedVault.get(app)

    var provisioned by mutableStateOf(vault.isProvisioned())
        private set

    var isBusy by mutableStateOf(false)
        private set

    var error by mutableStateOf<String?>(null)
        private set

    /** Observable mirror of the vault's lock mode (prefs aren't Compose-observable). */
    var lockMode by mutableStateOf(vault.lockMode)
        private set

    /** Observable mirror of the vault's biometric preference (prefs aren't Compose-observable). */
    var biometricEnabled by mutableStateOf(vault.biometricEnabled)
        private set

    /** Observable mirror of whether an app-owned password/PIN unlock is set. */
    var passwordEnrolled by mutableStateOf(vault.passwordKeyBlobExists())
        private set

    /** Observable mirror of whether a duress secret is set. */
    var duressEnrolled by mutableStateOf(vault.duressBlobExists())
        private set

    /** "password" or "pin" — drives the unlock keyboard only. */
    var unlockSecretKind by mutableStateOf(vault.unlockSecretKind ?: "password")
        private set

    /** Create a brand-new vault: generate KEK, wrap a fresh VK, write the blob, seed empty vault. */
    fun bootstrap(activity: FragmentActivity) {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                if (!BiometricGate.canAuthenticate(activity)) {
                    error = "Set up a screen lock or biometric to secure your AgePony vault."
                    return@launch
                }
                KeystoreMasterKey.generate()
                val cipher = KeystoreMasterKey.wrapCipher()
                val authed = BiometricGate.authenticate(
                    activity,
                    title = "Create AgePony vault",
                    subtitle = "Confirm it's you to secure your keys",
                    cryptoObject = BiometricPrompt.CryptoObject(cipher)
                )
                withContext(Dispatchers.IO) {
                    val vk = VaultCrypto.randomKey()
                    val wrapped = authed.doFinal(vk)
                    val iv = authed.iv
                    vault.writeKeyBlob(iv + wrapped)
                    vault.bootstrap(vk)
                }
                provisioned = true
            } catch (e: BiometricGateException) {
                error = if (e.code == BiometricPrompt.ERROR_USER_CANCELED ||
                    e.code == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                ) null else (e.message ?: "Authentication failed")
            } catch (e: Exception) {
                error = e.message ?: "Could not create the vault"
            } finally {
                isBusy = false
            }
        }
    }

    /**
     * Create a brand-new vault protected by an app-owned password/PIN, with no biometric.
     * For devices with no screen lock or fingerprint enrolled (where [bootstrap] can't run),
     * and for anyone who simply prefers a password. A biometric can be added later from
     * Settings. [kind] is "password" or "pin"; [secret] is zeroed before returning.
     */
    fun bootstrapWithPassword(secret: CharArray, kind: String) {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                withContext(Dispatchers.IO) {
                    val vk = VaultCrypto.randomKey()
                    // No Keystore KEK and no biometric blob: the password blob is the only
                    // wrapping of the VK. biometricEnabled=false, and with no plain blob the
                    // gate will require the password at every unlock (never auto-unlocks).
                    vault.writePasswordKeyBlob(PasswordVault.wrapVaultKey(secret, vk))
                    vault.unlockSecretKind = kind
                    vault.lockMode = LockMode.OFF
                    vault.bootstrap(vk)
                    vk.fill(0)
                }
                provisioned = true
            } catch (e: Exception) {
                error = e.message ?: "Could not create the vault"
            } finally {
                secret.fill(' ')
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /**
     * Create a brand-new vault gated by the device credential, for pre-30 devices with
     * a secure lock screen but no biometric (where [bootstrap] can't run, because the
     * Cipher-bound device-credential form isn't available below API 30). The VK is
     * wrapped under the non-auth KEK; the KeyguardManager confirm at unlock is the gate.
     */
    fun bootstrapWithDeviceCredential() {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                withContext(Dispatchers.IO) {
                    val vk = VaultCrypto.randomKey()
                    KeystoreMasterKey.generatePlain()
                    val cipher = KeystoreMasterKey.wrapCipherPlain()
                    vault.writePlainKeyBlob(cipher.iv + cipher.doFinal(vk))
                    vault.lockMode = LockMode.DEVICE_CREDENTIAL
                    vault.bootstrap(vk)
                    vk.fill(0)
                }
                provisioned = true
            } catch (e: Exception) {
                error = e.message ?: "Could not create the vault"
            } finally {
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /**
     * Unlock an existing vault. Routes on the lock mode:
     *   - OFF: unwrap with the non-auth KEK, no prompt (only when a plain blob exists;
     *     a password-only vault unlocks via [unlockWithPassword] instead).
     *   - DEVICE_CREDENTIAL on API 30+: device-credential prompt on the auth KEK.
     *   - DEVICE_CREDENTIAL pre-30: driven from the UI via a KeyguardManager confirm
     *     that calls [unlockAfterDeviceCredential] on success; nothing to do here.
     *   - BIOMETRIC: biometric (with device-credential fallback) on the auth KEK.
     */
    fun unlock(activity: FragmentActivity) {
        if (isBusy) return
        when (vault.lockMode) {
            LockMode.OFF -> if (vault.plainKeyBlobExists()) unlockPlain()
            LockMode.DEVICE_CREDENTIAL ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    unlockWithPrompt(activity, deviceCredentialOnly = true)
                }
            LockMode.BIOMETRIC -> unlockWithPrompt(activity, deviceCredentialOnly = false)
        }
    }

    /**
     * The BiometricPrompt-gated unlock on the auth KEK, shared by BIOMETRIC and (on
     * API 30+) DEVICE_CREDENTIAL. [deviceCredentialOnly] drops biometric from the
     * allowed authenticators so only the device credential is offered.
     */
    private fun unlockWithPrompt(activity: FragmentActivity, deviceCredentialOnly: Boolean) {
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                val blob = withContext(Dispatchers.IO) { vault.readKeyBlob() }
                val iv = blob.copyOfRange(0, KeystoreMasterKey.IV_LEN)
                val wrapped = blob.copyOfRange(KeystoreMasterKey.IV_LEN, blob.size)
                val cipher = KeystoreMasterKey.unwrapCipher(iv)
                val authed = BiometricGate.authenticate(
                    activity,
                    title = "Unlock AgePony",
                    subtitle = "Confirm it's you",
                    cryptoObject = BiometricPrompt.CryptoObject(cipher),
                    deviceCredentialOnly = deviceCredentialOnly,
                )
                withContext(Dispatchers.IO) {
                    val vk = authed.doFinal(wrapped)
                    vault.unlock(vk)
                }
            } catch (e: BiometricGateException) {
                error = if (e.code == BiometricPrompt.ERROR_USER_CANCELED ||
                    e.code == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                ) null else (e.message ?: "Authentication failed")
            } catch (e: KekUnavailableException) {
                recoverOrphanedVault()
            } catch (e: Exception) {
                // A KEK invalidated by new biometric enrollment lands here.
                error = e.message ?: "Could not unlock the vault"
            } finally {
                isBusy = false
            }
        }
    }

    /**
     * Pre-30 DEVICE_CREDENTIAL: the UI has already confirmed the device credential via
     * KeyguardManager, so open with the non-auth KEK sitting behind that gate.
     */
    fun unlockAfterDeviceCredential() = unlockPlain()

    /** Unlock without any prompt, using the non-auth KEK (biometric disabled). */
    private fun unlockPlain() {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                withContext(Dispatchers.IO) {
                    val blob = vault.readPlainKeyBlob()
                    val iv = blob.copyOfRange(0, KeystoreMasterKey.IV_LEN)
                    val wrapped = blob.copyOfRange(KeystoreMasterKey.IV_LEN, blob.size)
                    val vk = KeystoreMasterKey.unwrapCipherPlain(iv).doFinal(wrapped)
                    vault.unlock(vk)
                }
            } catch (e: KekUnavailableException) {
                recoverOrphanedVault()
            } catch (e: Exception) {
                error = e.message ?: "Could not unlock the vault"
            } finally {
                isBusy = false
            }
        }
    }

    /**
     * Recover from an orphaned vault: the wrapped vault key is on disk but the
     * Keystore KEK that sealed it is gone (reinstall or device-to-device restore).
     * Android backup can carry the vault blobs, but a hardware Keystore key never
     * leaves the device, so the VK can never be unwrapped again. Clear the dead
     * blobs and drop back to first-run instead of crashing on the impossible
     * unwrap. New installs are kept out of this state by excluding the vault dir
     * from backup (see res/xml/backup_rules.xml); this rescues anyone already in it.
     */
    private suspend fun recoverOrphanedVault() {
        withContext(Dispatchers.IO) {
            KeystoreMasterKey.delete()
            KeystoreMasterKey.deletePlain()
            vault.reset()
        }
        syncSecretFlags()
        error = "AgePony was reinstalled or restored from a backup, and the device " +
            "key that sealed your old vault is gone, so it can't be reopened. Set up " +
            "a new vault to continue."
    }

    // MARK: - App-owned password / PIN unlock (4.0.0)

    /**
     * Unlock with the app-owned secret. Three outcomes, from [PasswordVault.tryUnlock]:
     *   - Real: open the vault with the recovered VK.
     *   - Duress: the decoy — wipe everything and re-bootstrap an empty vault whose
     *     real password becomes this decoy (see [performDuressWipe]). The screen that
     *     follows is an ordinary unlocked, empty vault: indistinguishable from someone
     *     who simply has nothing saved.
     *   - Wrong: a plain wrong-password error, the same whether or not a duress secret
     *     is set.
     *
     * [secret] is zeroed before returning.
     */
    fun unlockWithPassword(secret: CharArray) {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                val outcome = withContext(Dispatchers.IO) {
                    val real = if (vault.passwordKeyBlobExists()) vault.readPasswordKeyBlob() else null
                    val duress = if (vault.duressBlobExists()) vault.readDuressBlob() else null
                    PasswordVault.tryUnlock(secret, real, duress)
                }
                when (outcome) {
                    is PasswordVault.Outcome.Real ->
                        withContext(Dispatchers.IO) { vault.unlock(outcome.vaultKey) }
                    PasswordVault.Outcome.Duress ->
                        withContext(Dispatchers.IO) { performDuressWipe(secret) }
                    PasswordVault.Outcome.Wrong ->
                        error = "Wrong ${secretNoun()}."
                }
            } catch (e: Exception) {
                error = e.message ?: "Could not unlock the vault"
            } finally {
                secret.fill(' ')
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /**
     * Enroll (or replace) the app-owned password/PIN. The vault must be unlocked, since
     * the current VK is what gets wrapped under the new secret. [kind] is "password" or
     * "pin" and only affects the unlock keyboard.
     */
    fun enrollPassword(secret: CharArray, kind: String) {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                val vk = vault.snapshotVaultKey()
                    ?: throw IllegalStateException("Unlock the vault first.")
                withContext(Dispatchers.IO) {
                    val blob = PasswordVault.wrapVaultKey(secret, vk)
                    vault.writePasswordKeyBlob(blob)
                    vault.unlockSecretKind = kind
                    vk.fill(0)
                }
            } catch (e: Exception) {
                error = e.message ?: "Couldn't set the password"
            } finally {
                secret.fill(' ')
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /**
     * Set (or replace) the duress secret. Requires a real password already enrolled, and
     * refuses a decoy that equals the real secret — checked by running the candidate
     * against the real blob, so the two can never collide and make the real password
     * trigger a wipe.
     */
    fun setDuressSecret(secret: CharArray) {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                if (!vault.passwordKeyBlobExists()) {
                    throw IllegalStateException("Set a password before a duress password.")
                }
                withContext(Dispatchers.IO) {
                    val real = vault.readPasswordKeyBlob()
                    val matchesReal = PasswordVault.tryUnlock(secret, real, null) is
                        PasswordVault.Outcome.Real
                    if (matchesReal) {
                        throw IllegalStateException("The duress password must differ from your real one.")
                    }
                    vault.writeDuressBlob(PasswordVault.duressBlob(secret))
                }
            } catch (e: Exception) {
                error = e.message ?: "Couldn't set the duress password"
            } finally {
                secret.fill(' ')
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /** Remove the app-owned password and any duress secret. Biometric stays as it was. */
    fun removePassword() {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                withContext(Dispatchers.IO) {
                    vault.deletePasswordKeyBlob()
                    vault.deleteDuressBlob()
                    vault.unlockSecretKind = null
                }
            } catch (e: Exception) {
                error = e.message ?: "Couldn't remove the password"
            } finally {
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /** Remove only the duress secret, leaving the real password in place. */
    fun removeDuress() {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                withContext(Dispatchers.IO) { vault.deleteDuressBlob() }
            } catch (e: Exception) {
                error = e.message ?: "Couldn't remove the duress password"
            } finally {
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /**
     * Verify [secret] against the real password blob without unlocking or wiping, for
     * in-app re-auth (revealing a private key) on a vault with no biometric/credential.
     * The duress blob is deliberately not consulted, so entering the duress password
     * here just fails rather than triggering a wipe. [secret] is zeroed before returning.
     */
    fun confirmPassword(secret: CharArray, onVerified: () -> Unit) {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                val ok = withContext(Dispatchers.IO) {
                    val real = if (vault.passwordKeyBlobExists()) vault.readPasswordKeyBlob() else null
                    real != null &&
                        PasswordVault.tryUnlock(secret, real, null) is PasswordVault.Outcome.Real
                }
                if (ok) onVerified() else error = "Wrong ${secretNoun()}."
            } catch (e: Exception) {
                error = e.message ?: "Couldn't verify the ${secretNoun()}"
            } finally {
                secret.fill(' ')
                isBusy = false
            }
        }
    }

    /** Surface a one-off error to the UI (e.g. a missing device credential). */
    fun noteError(message: String) { error = message }

    /**
     * The decoy path. Runs on an IO dispatcher (caller already switched). Everything the
     * old vault held is destroyed, then a fresh empty vault is created whose sole unlock
     * is [decoy] — the very secret just entered, so a coerced retry keeps working and any
     * other secret fails normally.
     *
     * Deliberately quiet: no toast, no dialog, no distinct screen. Control returns and
     * the app shows an ordinary unlocked, empty vault. Biometric is torn down (the old
     * KEK wrapped the destroyed VK, and re-keying it needs a prompt we must not raise
     * here), so the rebuilt vault is password-only — which is also what "fresh install
     * with a password" would look like.
     */
    private fun performDuressWipe(decoy: CharArray) {
        // 1. Destroy every trace of the old vault and its keys.
        vault.reset()
        KeystoreMasterKey.delete()
        KeystoreMasterKey.deletePlain()
        vault.deletePasswordKeyBlob()
        vault.deleteDuressBlob()

        // 2. Fresh empty vault under a new VK, held in memory and shown unlocked.
        val vk = VaultCrypto.randomKey()
        vault.bootstrap(vk)

        // 3. The decoy becomes the real (and only) password of the new vault.
        vault.writePasswordKeyBlob(PasswordVault.wrapVaultKey(decoy, vk))
        vault.lockMode = LockMode.OFF
        vk.fill(0)
    }

    private fun secretNoun(): String = if (vault.unlockSecretKind == "pin") "PIN" else "password"

    private fun syncSecretFlags() {
        provisioned = vault.isProvisioned()
        lockMode = vault.lockMode
        biometricEnabled = vault.biometricEnabled
        passwordEnrolled = vault.passwordKeyBlobExists()
        duressEnrolled = vault.duressBlobExists()
        unlockSecretKind = vault.unlockSecretKind ?: "password"
    }

    /**
     * Switch the Keystore/OS gate to [target]. The vault must be unlocked (its VK is
     * what each mode wraps). The VK is never re-keyed, so switching only changes which
     * KEK/blob a later unlock reads.
     *
     *   - OFF: (re)create the non-auth plain KEK and wrap the VK under it.
     *   - DEVICE_CREDENTIAL, API 30+: use the auth KEK (device-credential prompt at
     *     unlock). Enroll one first if the vault has none, then drop the plain blob.
     *   - DEVICE_CREDENTIAL, pre-30: gate the non-auth plain KEK behind a KeyguardManager
     *     confirm at unlock; requires a secure lock screen.
     *   - BIOMETRIC: use the auth KEK, enrolling one first if the vault has none.
     */
    fun applyLockMode(activity: FragmentActivity, target: LockMode) {
        if (isBusy || target == vault.lockMode) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                when (target) {
                    LockMode.OFF -> writePlainBlobFromCurrentVk()
                    LockMode.DEVICE_CREDENTIAL -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            if (!vault.keyBlobExists()) {
                                enrollAuthKek(activity, deviceCredentialOnly = true)
                            }
                            withContext(Dispatchers.IO) {
                                vault.deletePlainKeyBlob()
                                KeystoreMasterKey.deletePlain()
                            }
                        } else {
                            if (!BiometricGate.isDeviceSecure(activity)) {
                                throw IllegalStateException(
                                    "Set a device PIN, pattern, or password in Android settings first."
                                )
                            }
                            writePlainBlobFromCurrentVk()
                        }
                    }
                    LockMode.BIOMETRIC -> {
                        if (!vault.keyBlobExists()) {
                            enrollAuthKek(activity, deviceCredentialOnly = false)
                        }
                        withContext(Dispatchers.IO) {
                            vault.deletePlainKeyBlob()
                            KeystoreMasterKey.deletePlain()
                        }
                    }
                }
                vault.lockMode = target
                lockMode = target
                biometricEnabled = vault.biometricEnabled
            } catch (e: BiometricGateException) {
                error = if (e.code == BiometricPrompt.ERROR_USER_CANCELED ||
                    e.code == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                ) null else (e.message ?: "Authentication failed")
            } catch (e: Exception) {
                error = e.message ?: "Couldn't change the lock setting"
            } finally {
                isBusy = false
            }
        }
    }

    /** Wrap the current in-memory VK under a fresh non-auth plain KEK. */
    private suspend fun writePlainBlobFromCurrentVk() {
        val vk = vault.snapshotVaultKey()
            ?: throw IllegalStateException("Unlock the vault first.")
        withContext(Dispatchers.IO) {
            KeystoreMasterKey.generatePlain()
            val cipher = KeystoreMasterKey.wrapCipherPlain()
            val wrapped = cipher.doFinal(vk)
            vault.writePlainKeyBlob(cipher.iv + wrapped)
            vk.fill(0)
        }
    }

    /**
     * Create the auth KEK and wrap the current VK under it, prompting once. Adds a
     * hardware-bound gate to a vault created without one (e.g. a password-only vault).
     * [deviceCredentialOnly] restricts the prompt to the device credential.
     */
    private suspend fun enrollAuthKek(activity: FragmentActivity, deviceCredentialOnly: Boolean) {
        val vk = vault.snapshotVaultKey()
            ?: throw IllegalStateException("Unlock the vault first.")
        KeystoreMasterKey.generate()
        val cipher = KeystoreMasterKey.wrapCipher()
        val authed = BiometricGate.authenticate(
            activity,
            title = "Confirm it's you",
            subtitle = "Add this lock to your AgePony vault",
            cryptoObject = BiometricPrompt.CryptoObject(cipher),
            deviceCredentialOnly = deviceCredentialOnly,
        )
        withContext(Dispatchers.IO) {
            val wrapped = authed.doFinal(vk)
            vault.writeKeyBlob(authed.iv + wrapped)
            vk.fill(0)
        }
    }

    /** Lock the vault (drop the VK + decrypted state) now. */
    fun lock() {
        pendingLockJob?.cancel()
        pendingLockJob = null
        vault.lock()
    }

    // Background auto-lock grace period. Locking the instant the app is backgrounded
    // tore down the whole app shell on every app switch, which lost in-progress
    // navigation and half-entered forms (issue #4) and, for no-lock vaults, flashed
    // the unlock screen on every return (issue #5). Instead the vault stays unlocked
    // for a short window after backgrounding and locks only if the app stays away
    // past it, so a quick switch (copy a recipient, paste it elsewhere) keeps state.
    private var pendingLockJob: Job? = null

    /**
     * App went to the background. Schedule a lock after the grace period, unless an
     * in-app SAF round trip is in flight (that exemption already existed so the file
     * picker doesn't lock the vault out from under an active flow).
     */
    fun onEnterBackground() {
        if (vault.autoLockSuppressed) return
        pendingLockJob?.cancel()
        val graceMillis = vault.autoLockGraceSeconds.toLong() * 1000L
        pendingLockJob = viewModelScope.launch {
            delay(graceMillis)
            vault.lock()
            pendingLockJob = null
        }
    }

    /** App returned to the foreground. Cancel any pending lock and clear the SAF exemption. */
    fun onEnterForeground() {
        vault.autoLockSuppressed = false
        pendingLockJob?.cancel()
        pendingLockJob = null
    }

    /** Destroy the vault and the KEK entirely. */
    fun reset() {
        vault.reset()
        KeystoreMasterKey.delete()
        KeystoreMasterKey.deletePlain()
        provisioned = false
        syncSecretFlags()
        error = null
    }
}
