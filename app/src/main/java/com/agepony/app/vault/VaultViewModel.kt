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
        biometricEnabled = vault.biometricEnabled
        error = null
    }
}
