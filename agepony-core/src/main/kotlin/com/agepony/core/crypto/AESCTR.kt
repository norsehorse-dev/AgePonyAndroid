package com.agepony.core.crypto

import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * AES-CTR (also called AES-SIC). Used to decrypt OpenSSH passphrase-protected private
 * key sections.
 *
 * AES-CTR is a stream cipher mode — output size equals input size, no padding involved.
 * IV bytes ARE the initial counter value; the counter increments per block in big-endian.
 */
object AESCTR {
    class AESCTRException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** Decrypt with AES-256-CTR. */
    fun decrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray =
        process(key, iv, ciphertext, forEncryption = false, label = "decrypt")

    /**
     * Encrypt with AES-256-CTR. Internally identical to decrypt — CTR mode is symmetric,
     * but the named function exists for caller clarity.
     */
    fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray =
        process(key, iv, plaintext, forEncryption = true, label = "encrypt")

    private fun process(
        key: ByteArray,
        iv: ByteArray,
        input: ByteArray,
        forEncryption: Boolean,
        label: String,
    ): ByteArray {
        require(key.size == 32) { "AES-256 key must be 32 bytes, got ${key.size}" }
        require(iv.size == 16) { "AES-CTR IV must be 16 bytes, got ${iv.size}" }
        val cipher = BufferedBlockCipher(SICBlockCipher.newInstance(AESEngine.newInstance()))
        cipher.init(forEncryption, ParametersWithIV(KeyParameter(key), iv))
        val out = ByteArray(cipher.getOutputSize(input.size))
        val processed = cipher.processBytes(input, 0, input.size, out, 0)
        val finalLen = try {
            cipher.doFinal(out, processed)
        } catch (e: Exception) {
            throw AESCTRException("AES-CTR $label failed", e)
        }
        return out.copyOf(processed + finalLen)
    }
}
