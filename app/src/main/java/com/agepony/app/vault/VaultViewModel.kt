package com.agepony.app.vault

import android.app.Application
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

    val vault = Vault(app)

    var provisioned by mutableStateOf(vault.isProvisioned())
        private set

    var isBusy by mutableStateOf(false)
        private set

    var error by mutableStateOf<String?>(null)
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
                    vault.biometricEnabled = false
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

    /** Unlock an existing vault: unwrap the VK via biometric, then open vault.dat. */
    fun unlock(activity: FragmentActivity) {
        if (isBusy) return
        // Biometric disabled: unwrap with the non-auth KEK, no prompt.
        if (!vault.biometricEnabled && vault.plainKeyBlobExists()) {
            unlockPlain()
            return
        }
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
                    cryptoObject = BiometricPrompt.CryptoObject(cipher)
                )
                withContext(Dispatchers.IO) {
                    val vk = authed.doFinal(wrapped)
                    vault.unlock(vk)
                }
            } catch (e: BiometricGateException) {
                error = if (e.code == BiometricPrompt.ERROR_USER_CANCELED ||
                    e.code == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                ) null else (e.message ?: "Authentication failed")
            } catch (e: Exception) {
                // A KEK invalidated by new biometric enrollment lands here.
                error = e.message ?: "Could not unlock the vault"
            } finally {
                isBusy = false
            }
        }
    }

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
            } catch (e: Exception) {
                error = e.message ?: "Could not unlock the vault"
            } finally {
                isBusy = false
            }
        }
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
        vault.biometricEnabled = false
        vk.fill(0)
    }

    private fun secretNoun(): String = if (vault.unlockSecretKind == "pin") "PIN" else "password"

    private fun syncSecretFlags() {
        provisioned = vault.isProvisioned()
        biometricEnabled = vault.biometricEnabled
        passwordEnrolled = vault.passwordKeyBlobExists()
        duressEnrolled = vault.duressBlobExists()
        unlockSecretKind = vault.unlockSecretKind ?: "password"
    }

    /**
     * Turn biometric unlock on or off. The vault must be unlocked (the VK is
     * needed to create the non-auth blob when disabling). Enabling just flips
     * back to the existing biometric blob and drops the plain one; no prompt
     * either way, since the VK never changes.
     */
    fun applyBiometric(enabled: Boolean) {
        if (isBusy || enabled == vault.biometricEnabled) return
        viewModelScope.launch {
            isBusy = true
            error = null
            try {
                if (enabled) {
                    if (!vault.keyBlobExists()) {
                        throw IllegalStateException("No biometric key on this device.")
                    }
                    withContext(Dispatchers.IO) {
                        vault.deletePlainKeyBlob()
                        KeystoreMasterKey.deletePlain()
                    }
                    vault.biometricEnabled = true
                } else {
                    val vk = vault.snapshotVaultKey()
                        ?: throw IllegalStateException("Unlock the vault first.")
                    withContext(Dispatchers.IO) {
                        KeystoreMasterKey.generatePlain()
                        val cipher = KeystoreMasterKey.wrapCipherPlain()
                        val wrapped = cipher.doFinal(vk)
                        vault.writePlainKeyBlob(cipher.iv + wrapped)
                        vk.fill(0)
                    }
                    vault.biometricEnabled = false
                }
                biometricEnabled = vault.biometricEnabled
            } catch (e: Exception) {
                error = e.message ?: "Couldn't change the biometric setting"
            } finally {
                isBusy = false
            }
        }
    }

    /** Lock the vault (drop the VK + decrypted state). Called when the app backgrounds. */
    fun lock() {
        vault.lock()
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
