package com.agepony.app.vault

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

//
// Software AEAD used to seal the vault file (vault.dat) with the in-memory
// vault key (VK). AES-256-GCM via javax.crypto, available on all supported
// API levels (min SDK 26). This is the Android counterpart of iOS's
// ChaCha20-Poly1305 vault seal: the AEAD differs, but the security role and
// on-disk shape are identical — iv ‖ ciphertext ‖ tag. (JCE ChaCha20-Poly1305
// is API 28+, so AES-GCM is the portable choice; the age payload AEAD inside
// agepony-core is unaffected and remains ChaCha20-Poly1305.)
//
object VaultCrypto {

    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val IV_LEN = 12
    private const val TAG_BITS = 128

    private val rng = SecureRandom()

    /** Generate a fresh 32-byte vault key. */
    fun randomKey(): ByteArray = ByteArray(32).also { rng.nextBytes(it) }

    /** Seal [plaintext] under [key]. Output layout: iv(12) ‖ ciphertext ‖ tag(16). */
    fun seal(key: ByteArray, plaintext: ByteArray): ByteArray {
        val iv = ByteArray(IV_LEN).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        val ctWithTag = cipher.doFinal(plaintext)
        return iv + ctWithTag
    }

    /** Open a payload produced by [seal]. Throws on tamper / wrong key. */
    fun open(key: ByteArray, sealed: ByteArray): ByteArray {
        require(sealed.size > IV_LEN) { "sealed payload too short" }
        val iv = sealed.copyOfRange(0, IV_LEN)
        val ctWithTag = sealed.copyOfRange(IV_LEN, sealed.size)
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(ctWithTag)
    }
}
