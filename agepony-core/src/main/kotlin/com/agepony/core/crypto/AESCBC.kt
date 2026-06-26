package com.agepony.core.crypto

import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * AES-256-CBC with no padding and an explicit IV. The FIDO PIN/UV auth protocol (v1)
 * uses this with an all-zero IV to wrap the PIN hash and unwrap the PIN token; the input
 * is always a whole number of 16-byte blocks, so no padding is involved.
 */
object AESCBC {
    class AESCBCException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** The all-zero IV used by PIN protocol v1. */
    val ZERO_IV = ByteArray(16)

    fun encrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray =
        process(key, iv, plaintext, forEncryption = true, label = "encrypt")

    fun decrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray =
        process(key, iv, ciphertext, forEncryption = false, label = "decrypt")

    private fun process(
        key: ByteArray,
        iv: ByteArray,
        input: ByteArray,
        forEncryption: Boolean,
        label: String,
    ): ByteArray {
        require(key.size == 32) { "AES-256 key must be 32 bytes, got ${key.size}" }
        require(iv.size == 16) { "AES-CBC IV must be 16 bytes, got ${iv.size}" }
        require(input.size % 16 == 0) {
            "AES-CBC NoPadding input must be a multiple of 16 bytes, got ${input.size}"
        }
        val cipher = BufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()))
        cipher.init(forEncryption, ParametersWithIV(KeyParameter(key), iv))
        val out = ByteArray(cipher.getOutputSize(input.size))
        val processed = cipher.processBytes(input, 0, input.size, out, 0)
        val finalLen = try {
            cipher.doFinal(out, processed)
        } catch (e: Exception) {
            throw AESCBCException("AES-CBC $label failed", e)
        }
        return out.copyOf(processed + finalLen)
    }
}
