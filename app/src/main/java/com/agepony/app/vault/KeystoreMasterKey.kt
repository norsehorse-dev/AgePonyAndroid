package com.agepony.app.vault

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

//
// The Android counterpart of iOS's KeychainStore.swift. iOS keeps a 32-byte
// AES-256 master key in the Keychain behind a biometric ACL. Android Keystore
// keys are non-exportable, so we can't pull raw key bytes out the way iOS does.
// Instead this is the Key-Encryption-Key (KEK): a hardware-backed, biometric-
// gated AES-256-GCM key that lives in the AndroidKeyStore and is used ONLY to
// wrap/unwrap the vault key (VK). The VK (random 32 bytes) is what actually
// seals vault.dat (see VaultCrypto) and is held in memory after unlock — this
// reproduces iOS's "unlock once via biometric, then persist freely until the
// app backgrounds" behavior.
//
// Re-enrolling a biometric invalidates the KEK (setInvalidatedByBiometric-
// Enrollment), which is a deliberate security property surfaced in the UI.
//
object KeystoreMasterKey {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEK_ALIAS = "com.agepony.app.vault.master"
    // Non-auth-bound KEK used only when the user has turned biometric OFF. It
    // wraps the SAME vault key as the biometric KEK, so toggling biometric never
    // re-keys the vault — it only changes which blob unlock reads.
    private const val KEK_ALIAS_PLAIN = "com.agepony.app.vault.master.plain"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val TAG_BITS = 128

    /** GCM IV length the KEK uses; the wrap step records the actual IV alongside the blob. */
    const val IV_LEN = 12

    fun exists(): Boolean {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.containsAlias(KEK_ALIAS)
    }

    fun delete() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(KEK_ALIAS)) ks.deleteEntry(KEK_ALIAS)
    }

    /**
     * Generate a fresh KEK, replacing any existing one. Hardware-backed, with
     * StrongBox when the device supports it (falls back to the TEE otherwise).
     * Requires a secure lock screen; throws if none is configured.
     */
    fun generate() {
        delete()
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                kg.init(buildSpec(strongBox = true))
                kg.generateKey()
                return
            } catch (_: Exception) {
                // StrongBox unavailable on this device — regenerate in the TEE.
            }
        }
        kg.init(buildSpec(strongBox = false))
        kg.generateKey()
    }

    private fun buildSpec(strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(
            KEK_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Per-use auth, biometric or device credential (API 30+).
            b.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            b.setIsStrongBoxBacked(true)
        }
        return b.build()
    }

    private fun loadKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(KEK_ALIAS, null) as KeyStore.SecretKeyEntry
        return entry.secretKey
    }

    /**
     * Cipher for WRAPPING (encrypting) the VK. Must be presented to a
     * BiometricPrompt via a CryptoObject; after authentication the caller runs
     * doFinal(vk) and records cipher.iv with the wrapped bytes.
     */
    fun wrapCipher(): Cipher {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, loadKey())
        return c
    }

    /**
     * Cipher for UNWRAPPING (decrypting) the VK, using the [iv] captured when
     * the VK was wrapped. Present to a BiometricPrompt via a CryptoObject; after
     * authentication the caller runs doFinal(wrappedVk) to recover the VK.
     */
    fun unwrapCipher(iv: ByteArray): Cipher {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, loadKey(), GCMParameterSpec(TAG_BITS, iv))
        return c
    }

    // ---- Non-auth (plain) KEK: used only when biometric is disabled ----

    fun existsPlain(): Boolean {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.containsAlias(KEK_ALIAS_PLAIN)
    }

    fun deletePlain() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(KEK_ALIAS_PLAIN)) ks.deleteEntry(KEK_ALIAS_PLAIN)
    }

    /**
     * Generate a fresh non-auth KEK (no biometric/credential gate), hardware-
     * backed when possible. Usable immediately without a prompt — this is what
     * makes "biometric off" instant. Does not require a secure lock screen.
     */
    fun generatePlain() {
        deletePlain()
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                kg.init(buildSpecPlain(strongBox = true))
                kg.generateKey()
                return
            } catch (_: Exception) {
                // StrongBox unavailable — fall back to the TEE.
            }
        }
        kg.init(buildSpecPlain(strongBox = false))
        kg.generateKey()
    }

    private fun buildSpecPlain(strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(
            KEK_ALIAS_PLAIN,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        // No setUserAuthenticationRequired -> defaults to false (no prompt).
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            b.setIsStrongBoxBacked(true)
        }
        return b.build()
    }

    private fun loadKeyPlain(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(KEK_ALIAS_PLAIN, null) as KeyStore.SecretKeyEntry
        return entry.secretKey
    }

    /** Wrap cipher for the plain KEK. No CryptoObject/prompt — call doFinal directly. */
    fun wrapCipherPlain(): Cipher {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, loadKeyPlain())
        return c
    }

    /** Unwrap cipher for the plain KEK, using the [iv] captured at wrap time. */
    fun unwrapCipherPlain(iv: ByteArray): Cipher {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, loadKeyPlain(), GCMParameterSpec(TAG_BITS, iv))
        return c
    }
}
