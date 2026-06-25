package com.agepony.core.crypto

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

/**
 * ChaCha20-Poly1305 AEAD wrapper.
 *
 * age uses ChaCha20-Poly1305 for:
 *   - Stanza body encryption (key from wrap-key HKDF, nonce = 0 for stanzas)
 *   - Payload chunk encryption (key from payload HKDF, nonce = 11B counter || 1B last-flag)
 */
object ChaChaPoly {
    class AeadException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /**
     * Encrypt and authenticate. Output is `ciphertext || 16B-tag`.
     */
    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(key.size == 32) { "key must be 32 bytes, got ${key.size}" }
        require(nonce.size == 12) { "nonce must be 12 bytes, got ${nonce.size}" }
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val output = ByteArray(cipher.getOutputSize(plaintext.size))
        val len = cipher.processBytes(plaintext, 0, plaintext.size, output, 0)
        val finalLen = try {
            cipher.doFinal(output, len)
        } catch (e: Exception) {
            throw AeadException("ChaCha20-Poly1305 encrypt failed", e)
        }
        return output.copyOf(len + finalLen)
    }

    /**
     * Decrypt and verify. Input is `ciphertext || 16B-tag`. Throws if authentication fails.
     */
    fun decrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(key.size == 32) { "key must be 32 bytes, got ${key.size}" }
        require(nonce.size == 12) { "nonce must be 12 bytes, got ${nonce.size}" }
        require(ciphertext.size >= 16) { "ciphertext too short for tag" }
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val output = ByteArray(cipher.getOutputSize(ciphertext.size))
        val len = cipher.processBytes(ciphertext, 0, ciphertext.size, output, 0)
        val finalLen = try {
            cipher.doFinal(output, len)
        } catch (e: Exception) {
            throw AeadException("ChaCha20-Poly1305 decrypt/auth failed", e)
        }
        return output.copyOf(len + finalLen)
    }
}
