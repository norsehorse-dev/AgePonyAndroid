package com.agepony.app.vault

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
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
/**
 * Thrown when a Keystore KEK alias is absent: the wrapped vault key exists on disk
 * but the hardware key that sealed it does not. This is the reinstall / restore
 * case. Android backup can carry the vault blobs, but an AndroidKeyStore key never
 * leaves the device and cannot be restored, so the vault is unrecoverable. Callers
 * reset to first-run rather than crash on the impossible unwrap.
 */
class KekUnavailableException(alias: String) :
    IllegalStateException("Keystore key \"$alias\" is unavailable (missing after reinstall or restore).")

object KeystoreMasterKey {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEK_ALIAS = "com.agepony.app.vault.master"
    // Non-auth-bound KEK used only when the user has turned biometric OFF. It
    // wraps the SAME vault key as the biometric KEK, so toggling biometric never
    // re-keys the vault — it only changes which blob unlock reads.
    private const val KEK_ALIAS_PLAIN = "com.agepony.app.vault.master.plain"
    // Biometrics-only KEK (5.1.0, iOS E6): BIOMETRIC_STRONG only, never the device credential.
    private const val KEK_ALIAS_BIOMETRIC_ONLY = "com.agepony.app.vault.master.biometriconly"
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
        val entry = ks.getEntry(KEK_ALIAS, null) as? KeyStore.SecretKeyEntry
            ?: throw KekUnavailableException(KEK_ALIAS)
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

    // ---- Biometrics-only KEK (5.1.0, iOS E6) ----
    //
    // Its own alias, so the BIOMETRIC mode's KEK (which accepts the device credential on API
    // 30+) is never reused for this mode. BIOMETRIC_STRONG only, per use, and invalidated by
    // any biometric enrolment change. Below API 30 a per-use auth key only accepts a biometric,
    // so the same spec gives the same guarantee there.

    /** What a Biometrics-only KEK check found. */
    enum class BiometricOnlyKeyState {
        /** Present and usable once a strong biometric confirms. */
        VALID,
        /** Invalidated by Keystore: a biometric was added or removed since it was made. */
        INVALIDATED,
        /** No such key on this device. */
        MISSING,
    }

    fun existsBiometricOnly(): Boolean {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.containsAlias(KEK_ALIAS_BIOMETRIC_ONLY)
    }

    fun deleteBiometricOnly() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(KEK_ALIAS_BIOMETRIC_ONLY)) ks.deleteEntry(KEK_ALIAS_BIOMETRIC_ONLY)
    }

    /**
     * Generate a fresh Biometrics-only KEK, replacing any existing one. Throws if the device
     * can't make such a key (no secure lock screen, no strong biometric enrolled). StrongBox
     * when available, as for the other KEKs.
     */
    fun generateBiometricOnly() {
        deleteBiometricOnly()
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                kg.init(buildSpecBiometricOnly(strongBox = true))
                kg.generateKey()
                return
            } catch (_: Exception) {
                // StrongBox unavailable: generate in the TEE instead.
            }
        }
        kg.init(buildSpecBiometricOnly(strongBox = false))
        kg.generateKey()
    }

    private fun buildSpecBiometricOnly(strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(
            KEK_ALIAS_BIOMETRIC_ONLY,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Per use, strong biometric only: no device credential (5.1.0, E6).
            b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            b.setIsStrongBoxBacked(true)
        }
        return b.build()
    }

    private fun loadKeyBiometricOnly(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(KEK_ALIAS_BIOMETRIC_ONLY, null) as? KeyStore.SecretKeyEntry
            ?: throw KekUnavailableException(KEK_ALIAS_BIOMETRIC_ONLY)
        return entry.secretKey
    }

    /**
     * Wrap cipher for the Biometrics-only KEK. Present it to a BIOMETRIC_STRONG-only prompt via a
     * CryptoObject. Throws [KeyPermanentlyInvalidatedException] after an enrolment change.
     */
    fun wrapCipherBiometricOnly(): Cipher {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, loadKeyBiometricOnly())
        return c
    }

    /** Unwrap cipher for the Biometrics-only KEK, using the [iv] captured at wrap time. */
    fun unwrapCipherBiometricOnly(iv: ByteArray): Cipher {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, loadKeyBiometricOnly(), GCMParameterSpec(TAG_BITS, iv))
        return c
    }

    /**
     * Whether the Biometrics-only KEK is still usable. A per-use auth key initializes without a
     * prompt, and Keystore refuses the init with [KeyPermanentlyInvalidatedException] once a
     * biometric was added or removed, which is how an in-app prompt tells that the enrolment
     * changed since the vault was locked to it (5.1.0, iOS M-3).
     */
    fun biometricOnlyKeyState(): BiometricOnlyKeyState =
        try {
            wrapCipherBiometricOnly()
            BiometricOnlyKeyState.VALID
        } catch (_: KekUnavailableException) {
            BiometricOnlyKeyState.MISSING
        } catch (_: KeyPermanentlyInvalidatedException) {
            BiometricOnlyKeyState.INVALIDATED
        } catch (_: Exception) {
            // Anything else from Keystore: not usable, so not a pass either.
            BiometricOnlyKeyState.INVALIDATED
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
        val entry = ks.getEntry(KEK_ALIAS_PLAIN, null) as? KeyStore.SecretKeyEntry
            ?: throw KekUnavailableException(KEK_ALIAS_PLAIN)
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
