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
import com.agepony.app.security.AutoLock
import com.agepony.app.security.BiometricGate
import com.agepony.app.security.BiometricGateException
import com.agepony.app.security.PasswordCheck
import com.agepony.app.security.PasswordVault
import com.agepony.app.security.UnlockAttempts
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.CharBuffer

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
// 5.0.1 (security audit): a duress secret makes the vault PIN-only (H-1); No lock plus a
// password is password-only (H-4); failed password attempts are counted with a backoff and
// an optional erase (M-1); the background auto-lock moved to the process-level AutoLock
// (H-3), so there is no lock timer here any more.
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

    /** Observable mirror of whether a duress secret is set. While true the vault is PIN-only. */
    var duressEnrolled by mutableStateOf(vault.duressBlobExists())
        private set

    /** "password" or "pin": drives the unlock keyboard only. */
    var unlockSecretKind by mutableStateOf(vault.unlockSecretKind ?: "password")
        private set

    /**
     * True once the app password was entered in this process and turned out shorter than
     * what 5.0.1 requires of a new one (audit M-1). It still works; Settings suggests a
     * change. Memory only: the length of the secret is never written anywhere.
     */
    var secretBelowMinimum by mutableStateOf(false)
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
                    // Set explicitly: a lock mode left over from an earlier vault would
                    // otherwise decide how this one unlocks (audit L-17).
                    vault.lockMode = LockMode.BIOMETRIC
                    vault.bootstrap(vk)
                    vk.fill(0)
                }
                provisioned = true
            } catch (e: BiometricGateException) {
                error = if (e.code == BiometricPrompt.ERROR_USER_CANCELED ||
                    e.code == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                ) null else (e.message ?: "Authentication failed")
            } catch (e: Exception) {
                error = e.message ?: "Could not create the vault"
            } finally {
                syncSecretFlags()
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
                PasswordVault.secretPolicyError(CharBuffer.wrap(secret), kind)?.let {
                    throw IllegalStateException(it)
                }
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
                secretBelowMinimum = false
            } catch (e: Exception) {
                error = e.message ?: "Could not create the vault"
            } finally {
                secret.fill('\u0000')
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
     *   - OFF: unwrap with the non-auth KEK, no prompt (only when a plain blob exists and
     *     no password is set; a password-enrolled vault unlocks via [unlockWithPassword]
     *     only, audit H-4).
     *   - DEVICE_CREDENTIAL on API 30+: device-credential prompt on the auth KEK.
     *   - DEVICE_CREDENTIAL pre-30: driven from the UI via a KeyguardManager confirm
     *     that calls [unlockAfterDeviceCredential] on success; nothing to do here.
     *   - BIOMETRIC: biometric (with device-credential fallback) on the auth KEK.
     *
     * With a duress secret set nothing here runs: the vault is PIN-only (audit H-1), so a
     * coerced unlock always goes through the PIN field, where the duress secret can fire.
     */
    fun unlock(activity: FragmentActivity) {
        if (isBusy || vault.duressBlobExists()) return
        when (vault.lockMode) {
            LockMode.OFF ->
                if (vault.plainKeyBlobExists() && !vault.passwordKeyBlobExists()) unlockPlain()
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
                    vk.fill(0)
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
    /**
     * True for a vault left by 5.0.0 in No lock mode with a password and its old no-prompt
     * key (the plain blob) still on disk, and no duress secret. 5.0.0 opened such a vault
     * without asking for the password (audit H-4), so its owner may not remember it. The
     * first password unlock deletes the plain blob, after which this is false for good.
     */
    val legacyNoLockFallbackAvailable: Boolean
        get() = vault.lockMode == LockMode.OFF && vault.passwordKeyBlobExists() &&
            !vault.duressBlobExists() && vault.plainKeyBlobExists()

    /**
     * Open a [legacyNoLockFallbackAvailable] vault the way 5.0.0 did, with the plain blob, and
     * remove the password so the vault is honestly No lock afterwards. No weaker than the
     * 5.0.0 behavior it replaces, and only possible while that old blob exists.
     */
    fun openLegacyNoLockAndRemovePassword() {
        if (isBusy || !legacyNoLockFallbackAvailable) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                withContext(Dispatchers.IO) {
                    val blob = vault.readPlainKeyBlob()
                    val iv = blob.copyOfRange(0, KeystoreMasterKey.IV_LEN)
                    val wrapped = blob.copyOfRange(KeystoreMasterKey.IV_LEN, blob.size)
                    val vk = KeystoreMasterKey.unwrapCipherPlain(iv).doFinal(wrapped)
                    try {
                        vault.unlock(vk)
                    } finally {
                        vk.fill(0)
                    }
                    // Only once the vault is open with the plain blob, so the password blob
                    // is never deleted while it might still be the only way in.
                    vault.deletePasswordKeyBlob()
                    vault.unlockSecretKind = null
                    vault.unlockAttempts.reset()
                }
            } catch (e: KekUnavailableException) {
                recoverOrphanedVault()
            } catch (e: Exception) {
                error = e.message ?: "Could not unlock the vault"
            } finally {
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    private fun unlockPlain() {
        // PIN-only while a duress secret is set (audit H-1).
        if (isBusy || vault.duressBlobExists()) return
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
                    vk.fill(0)
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

    /** Milliseconds until the lock screen accepts another password attempt (audit M-1). */
    fun lockoutRemainingMillis(): Long = vault.unlockAttempts.remainingLockoutMillis()

    /**
     * Unlock with the app-owned secret. Three outcomes, from [PasswordVault.tryUnlock]:
     *   - Real: open the vault with the recovered VK.
     *   - Duress: the decoy. Wipe everything and re-bootstrap an empty vault whose real
     *     password becomes this decoy (see [performDuressWipe]). The screen that follows
     *     is an ordinary unlocked, empty vault: indistinguishable from someone who simply
     *     has nothing saved.
     *   - Wrong: a plain wrong-password error, the same whether or not a duress secret
     *     is set.
     *
     * Every attempt goes through the persisted counter first (audit M-1): refused outright
     * while a backoff wait is running, counted before it is checked, and cleared by Real
     * and Duress alike, so the counter can't tell the decoy from the real secret. With
     * "erase after failed attempts" on, the attempt that reaches the limit wipes the vault.
     *
     * [secret] is zeroed before returning.
     */
    fun unlockWithPassword(secret: CharArray) {
        if (isBusy) {
            secret.fill('\u0000')
            return
        }
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                val wait = vault.unlockAttempts.remainingLockoutMillis()
                if (wait > 0L) {
                    error = UnlockAttempts.lockoutMessage(wait)
                    return@launch
                }
                val belowMinimum =
                    PasswordVault.secretPolicyError(CharBuffer.wrap(secret), vault.unlockSecretKind ?: "password") != null
                var attemptCount = 0
                val outcome = withContext(Dispatchers.IO) {
                    // Counted before the check, so killing the app mid-attempt can't make a guess free.
                    attemptCount = vault.unlockAttempts.recordAttempt()
                    val real = if (vault.passwordKeyBlobExists()) vault.readPasswordKeyBlob() else null
                    val duress = if (vault.duressBlobExists()) vault.readDuressBlob() else null
                    PasswordVault.tryUnlock(secret, real, duress)
                }
                when (outcome) {
                    is PasswordVault.Outcome.Real -> {
                        try {
                            withContext(Dispatchers.IO) {
                                vault.unlock(outcome.vaultKey)
                                vault.unlockAttempts.reset()
                                afterPasswordUnlock(secret, outcome)
                            }
                        } finally {
                            outcome.wipe()
                        }
                        secretBelowMinimum = belowMinimum
                    }
                    is PasswordVault.Outcome.Duress -> {
                        try {
                            withContext(Dispatchers.IO) { performDuressWipe(outcome) }
                        } finally {
                            outcome.wipe()
                        }
                        // Same as a real unlock with this secret would show.
                        secretBelowMinimum = belowMinimum
                    }
                    PasswordVault.Outcome.Wrong -> {
                        if (vault.eraseAfterFailedAttempts && attemptCount >= UnlockAttempts.ERASE_AFTER) {
                            val erasedNoun = noun
                            withContext(Dispatchers.IO) { performFailedAttemptsWipe() }
                            error = "The $erasedNoun was entered wrong ${UnlockAttempts.ERASE_AFTER} times, so the " +
                                "vault was erased as set in Settings."
                        } else {
                            error = wrongSecretMessage(attemptCount)
                        }
                    }
                }
            } catch (e: Exception) {
                error = e.message ?: "Could not unlock the vault"
            } finally {
                secret.fill('\u0000')
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /**
     * Housekeeping after a real password unlock, on IO. The password has just been shown to
     * open its blob, so this is the one safe moment to drop the other wraps it makes
     * redundant, and to upgrade the blob itself:
     *   - re-wrap a v1 (or low work factor) blob as v2 while the secret is in hand (audit M-2);
     *   - a duress secret means PIN-only: delete the hardware and plain wraps (audit H-1),
     *     which also migrates a 5.0.0 vault that had duress next to biometric;
     *   - No lock plus a password means password-only: delete a plain blob a 5.0.0 vault
     *     may still have (audit H-4).
     * Failures here never undo the unlock.
     */
    private fun afterPasswordUnlock(secret: CharArray, outcome: PasswordVault.Outcome.Real) {
        if (outcome.needsRewrap) {
            // The new blob is opened once before it replaces the old one, and the other wraps
            // are only dropped if it did. Otherwise a v2 blob that somehow didn't open (a
            // Keystore quirk on the device key) could end up as the only wrap of the VK.
            val rewrapped = runCatching {
                val blob = PasswordVault.wrapVaultKey(secret, outcome.vaultKey)
                val check = PasswordVault.tryUnlock(secret, blob, null)
                val opens = check is PasswordVault.Outcome.Real &&
                    check.vaultKey.contentEquals(outcome.vaultKey)
                check.wipe()
                if (opens) vault.writePasswordKeyBlob(blob)
                opens
            }.getOrDefault(false)
            if (!rewrapped) return
        }
        runCatching { dropWrapsMadeRedundantByPassword() }
    }

    /**
     * Delete wraps of the VK that the current password state says must not exist: all of
     * them but the password blob when a duress secret is set, and the plain blob in No lock
     * mode with a password. Only call once the password blob is known to open.
     */
    private fun dropWrapsMadeRedundantByPassword() {
        if (!vault.passwordKeyBlobExists()) return
        if (vault.duressBlobExists()) {
            vault.deleteKeyBlob()
            runCatching { KeystoreMasterKey.delete() }
            vault.deletePlainKeyBlob()
            runCatching { KeystoreMasterKey.deletePlain() }
            if (vault.lockMode != LockMode.OFF) vault.lockMode = LockMode.OFF
        } else if (vault.lockMode == LockMode.OFF) {
            vault.deletePlainKeyBlob()
            runCatching { KeystoreMasterKey.deletePlain() }
            vault.deleteKeyBlob()
            runCatching { KeystoreMasterKey.delete() }
        }
    }

    /** The lock screen's wrong-secret message. The lock screen shows any backoff wait itself. */
    private fun wrongSecretMessage(attemptCount: Int): String {
        val base = "Wrong $noun."
        if (vault.eraseAfterFailedAttempts) {
            val left = UnlockAttempts.ERASE_AFTER - attemptCount
            if (left in 1..3) {
                return base + (if (left == 1) " One more wrong try" else " $left more wrong tries") +
                    " will erase the vault."
            }
        }
        return base
    }

    /**
     * Enroll (or replace) the app-owned password/PIN. The vault must be unlocked, since
     * the current VK is what gets wrapped under the new secret. [kind] is "password" or
     * "pin" and only affects the unlock keyboard.
     *
     * 5.0.1: a new secret must meet the minimum length (audit M-1) and must differ from the
     * duress secret (checked against the duress blob), and in No lock mode the password
     * becomes the only way in: the plain blob and its KEK are deleted (audit H-4).
     */
    fun enrollPassword(secret: CharArray, kind: String) {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                PasswordVault.secretPolicyError(CharBuffer.wrap(secret), kind)?.let {
                    throw IllegalStateException(it)
                }
                // The duress secret is typed on the same keyboard; a PIN pad can't enter a
                // password-style decoy, so the kind can't change under it.
                if (vault.duressBlobExists() && kind != (vault.unlockSecretKind ?: "password")) {
                    throw IllegalStateException(
                        "Remove the duress $noun first to switch between a password and a PIN."
                    )
                }
                val vk = vault.snapshotVaultKey()
                    ?: throw IllegalStateException("Unlock the vault first.")
                try {
                    withContext(Dispatchers.IO) {
                        if (vault.duressBlobExists()) {
                            val check = PasswordVault.tryUnlock(secret, null, vault.readDuressBlob())
                            val clash = check is PasswordVault.Outcome.Duress
                            check.wipe()
                            if (clash) {
                                throw IllegalStateException("It must differ from your duress $noun.")
                            }
                        }
                        val blob = PasswordVault.wrapVaultKey(secret, vk)
                        // Open it once before it replaces the current blob: in No lock mode it
                        // becomes the only wrap of the VK right below.
                        val check = PasswordVault.tryUnlock(secret, blob, null)
                        val opens = check is PasswordVault.Outcome.Real && check.vaultKey.contentEquals(vk)
                        check.wipe()
                        if (!opens) throw IllegalStateException("Couldn't set the $noun on this device.")
                        vault.writePasswordKeyBlob(blob)
                        if (!vault.readPasswordKeyBlob().contentEquals(blob)) {
                            throw IllegalStateException("Couldn't save the $noun.")
                        }
                        vault.unlockSecretKind = kind
                        if (vault.lockMode == LockMode.OFF) dropWrapsMadeRedundantByPassword()
                    }
                } finally {
                    vk.fill(0)
                }
                secretBelowMinimum = false
            } catch (e: Exception) {
                error = e.message ?: "Couldn't set the password"
            } finally {
                secret.fill('\u0000')
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /**
     * Set (or replace) the duress secret. Requires a real password already enrolled, and
     * refuses a decoy that equals the real secret, checked by running the candidate
     * against the real blob, so the two can never collide and make the real password
     * trigger a wipe.
     *
     * 5.0.1 (audit H-1): setting a duress secret makes the vault PIN-only. Biometric and
     * device unlock are turned off and their blobs and KEKs deleted, because a coercer who
     * has the phone's passcode could otherwise open the real vault without ever reaching
     * the PIN field. Since that leaves the password blob as the only wrap of the vault key,
     * [current] (the real password) is required while any other unlock exists, and must
     * open the real blob to this vault's key before anything is deleted. It also counts
     * toward the failed-attempt limit. Both arrays are zeroed before returning.
     */
    fun setDuressSecret(secret: CharArray, current: CharArray? = null) {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                if (!vault.passwordKeyBlobExists()) {
                    throw IllegalStateException("Set a $noun before a duress $noun.")
                }
                PasswordVault.secretPolicyError(CharBuffer.wrap(secret), vault.unlockSecretKind ?: "password")?.let {
                    throw IllegalStateException(it)
                }
                val vk = vault.snapshotVaultKey()
                    ?: throw IllegalStateException("Unlock the vault first.")
                try {
                    withContext(Dispatchers.IO) {
                        if (current != null) {
                            verifyCurrentSecret(current, vk)
                        } else if (!vault.passwordIsOnlyUnlock()) {
                            throw IllegalStateException("Enter your current $noun first.")
                        }
                        val real = vault.readPasswordKeyBlob()
                        val check = PasswordVault.tryUnlock(secret, real, null)
                        val matchesReal = check is PasswordVault.Outcome.Real
                        check.wipe()
                        if (matchesReal) {
                            throw IllegalStateException("The duress $noun must differ from your real one.")
                        }
                        vault.writeDuressBlob(PasswordVault.duressBlob(secret))
                        dropWrapsMadeRedundantByPassword()
                    }
                } finally {
                    vk.fill(0)
                }
            } catch (e: Exception) {
                error = e.message ?: "Couldn't set the duress password"
            } finally {
                secret.fill('\u0000')
                current?.fill('\u0000')
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /**
     * On IO: prove [current] is the real password AND that its blob opens to this vault's
     * key [vk], through the failed-attempt counter. Throws with a user-facing message
     * otherwise. Also upgrades a v1 blob while the secret is in hand.
     */
    private fun verifyCurrentSecret(current: CharArray, vk: ByteArray) {
        val wait = vault.unlockAttempts.remainingLockoutMillis()
        if (wait > 0L) throw IllegalStateException(UnlockAttempts.lockoutMessage(wait))
        vault.unlockAttempts.recordAttempt()
        val outcome = PasswordVault.tryUnlock(current, vault.readPasswordKeyBlob(), null)
        try {
            val ok = outcome is PasswordVault.Outcome.Real && outcome.vaultKey.contentEquals(vk)
            if (!ok) throw IllegalStateException("Wrong $noun.")
            vault.unlockAttempts.reset()
            if ((outcome as PasswordVault.Outcome.Real).needsRewrap) {
                runCatching {
                    // Opened once before it replaces the old blob (see afterPasswordUnlock).
                    val blob = PasswordVault.wrapVaultKey(current, vk)
                    val check = PasswordVault.tryUnlock(current, blob, null)
                    val opens = check is PasswordVault.Outcome.Real && check.vaultKey.contentEquals(vk)
                    check.wipe()
                    if (opens) vault.writePasswordKeyBlob(blob)
                }
            }
        } finally {
            outcome.wipe()
        }
    }

    /**
     * Remove the app-owned password and any duress secret. Biometric stays as it was.
     *
     * Refused when the password is the only way into the vault (audit L-16): the vault
     * would be unopenable at the next lock. The user picks another lock mode first (and
     * removes the duress secret first, since that makes the vault PIN-only).
     */
    fun removePassword() {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                if (vault.passwordIsOnlyUnlock()) throw IllegalStateException(passwordOnlyMessage())
                withContext(Dispatchers.IO) {
                    vault.deletePasswordKeyBlob()
                    vault.deleteDuressBlob()
                    vault.unlockSecretKind = null
                    vault.unlockAttempts.reset()
                }
                secretBelowMinimum = false
            } catch (e: Exception) {
                error = e.message ?: "Couldn't remove the password"
            } finally {
                syncSecretFlags()
                isBusy = false
            }
        }
    }

    /** Why the password can't be removed right now (audit L-16). */
    fun passwordOnlyMessage(): String =
        if (vault.duressBlobExists()) {
            "Your $noun is the only way into the vault. Remove the duress $noun, then pick " +
                "Biometric or Device PIN above before removing it."
        } else {
            "Your $noun is the only way into the vault. Pick Biometric or Device PIN above " +
                "before removing it."
        }

    /**
     * Remove only the duress secret, leaving the real password in place. The vault stays
     * PIN-only until the user picks a hardware lock mode again in Settings.
     */
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
     * here just fails rather than triggering a wipe. Goes through the failed-attempt
     * counter (audit M-1). [secret] is zeroed before returning.
     */
    fun confirmPassword(secret: CharArray, onVerified: () -> Unit) {
        if (isBusy) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                when (val check = withContext(Dispatchers.IO) { vault.verifyAppPassword(secret) }) {
                    PasswordCheck.Ok -> onVerified()
                    PasswordCheck.Wrong -> error = "Wrong $noun."
                    is PasswordCheck.LockedOut -> error = UnlockAttempts.lockoutMessage(check.remainingMillis)
                }
            } catch (e: Exception) {
                error = e.message ?: "Couldn't verify the $noun"
            } finally {
                secret.fill('\u0000')
                isBusy = false
            }
        }
    }

    /** Surface a one-off error to the UI (e.g. a missing device credential). */
    fun noteError(message: String) { error = message }

    /**
     * The decoy path. Runs on an IO dispatcher (caller already switched). Everything the
     * old vault held is destroyed, then a fresh empty vault is created whose sole unlock
     * is the decoy, the very secret just entered, so a coerced retry keeps working and any
     * other secret fails normally.
     *
     * Deliberately quiet: no toast, no dialog, no distinct screen. Control returns and
     * the app shows an ordinary unlocked, empty vault. Since 5.0.1 a vault with a duress
     * secret is already PIN-only (lock mode OFF), so the lock mode doesn't change here.
     *
     * Kept close to a wrong attempt in time (audit M-8): the new password blob reuses the
     * scrypt work [PasswordVault.tryUnlock] already did for the decoy, so the extra work is
     * file deletes and Keystore calls. Settings go back to a new user's defaults except the
     * onboarding flag and the secret kind (the decoy was typed on that keyboard), proxy
     * credentials and counters included, and cached staging files are swept (Vault.reset).
     */
    private fun performDuressWipe(duress: PasswordVault.Outcome.Duress) {
        val kind = vault.unlockSecretKind

        // 1. Destroy every trace of the old vault and its keys. A Keystore hiccup must not
        // stop the wipe halfway and leave a visibly broken app.
        vault.reset(silentWipe = true)
        runCatching { KeystoreMasterKey.delete() }
        runCatching { KeystoreMasterKey.deletePlain() }

        // 2. A fresh empty vault under a new VK, held in memory and shown unlocked. The screen
        // changes here (vm.provisioned stays true until syncSecretFlags runs after this).
        val vk = VaultCrypto.randomKey()
        try {
            vault.unlockSecretKind = kind
            vault.lockMode = LockMode.OFF
            vault.bootstrap(vk)
            // 3. The decoy becomes the real (and only) password of the new vault. Done after
            // the vault is on screen because it includes generating a new Keystore key, the
            // slowest step left on this path.
            vault.writePasswordKeyBlob(duress.wrapNewVaultKey(vk))
        } finally {
            vk.fill(0)
        }
    }

    /**
     * "Erase the vault after 10 wrong attempts" (audit M-1): the same destruction as the
     * duress wipe, but no decoy vault follows. The app is left with no vault, and keeps
     * its onboarding flag, so it offers to create a new one. Runs on IO.
     */
    private fun performFailedAttemptsWipe() {
        vault.reset(silentWipe = true)
        runCatching { KeystoreMasterKey.delete() }
        runCatching { KeystoreMasterKey.deletePlain() }
    }

    /** "PIN" or "password", for messages. */
    private val noun: String get() = if (vault.unlockSecretKind == "pin") "PIN" else "password"

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
     *   - OFF without a password: (re)create the non-auth plain KEK and wrap the VK under it.
     *   - OFF with a password: password-only (audit H-4). No plain blob is written, and the
     *     plain and auth blobs and KEKs are deleted, so only the password opens the vault.
     *   - DEVICE_CREDENTIAL, API 30+: use the auth KEK (device-credential prompt at
     *     unlock). Enroll one first if the vault has none, then drop the plain blob.
     *   - DEVICE_CREDENTIAL, pre-30: gate the non-auth plain KEK behind a KeyguardManager
     *     confirm at unlock; requires a secure lock screen.
     *   - BIOMETRIC: use the auth KEK, enrolling one first if the vault has none.
     *
     * Refused while a duress secret is set: the vault is PIN-only then (audit H-1).
     */
    fun applyLockMode(activity: FragmentActivity, target: LockMode) {
        if (isBusy || target == vault.lockMode) return
        if (vault.duressBlobExists()) {
            error = "Turn off the duress $noun to use fingerprint or device unlock."
            return
        }
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                when (target) {
                    LockMode.OFF ->
                        if (vault.passwordKeyBlobExists()) {
                            if (!vault.isUnlocked) throw IllegalStateException("Unlock the vault first.")
                            withContext(Dispatchers.IO) {
                                vault.lockMode = LockMode.OFF
                                dropWrapsMadeRedundantByPassword()
                            }
                        } else {
                            writePlainBlobFromCurrentVk()
                        }
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
                syncSecretFlags()
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

    /**
     * Lock the vault (drop the VK + decrypted state) now. Goes through AutoLock so any
     * pending background timer is dropped with it (there is only the one, audit H-3).
     */
    fun lock() {
        AutoLock.lockNow(getApplication<Application>())
    }

    /**
     * The activity that owned this ViewModel is gone. The background lock is AutoLock's
     * process-level timer, not anything in viewModelScope, so it isn't cancelled here;
     * this only makes sure one is pending if nothing else is on screen (audit H-3).
     */
    override fun onCleared() {
        AutoLock.onViewModelCleared()
        super.onCleared()
    }

    /** Destroy the vault and the KEK entirely. */
    fun reset() {
        vault.reset()
        KeystoreMasterKey.delete()
        KeystoreMasterKey.deletePlain()
        provisioned = false
        secretBelowMinimum = false
        syncSecretFlags()
        error = null
    }
}
