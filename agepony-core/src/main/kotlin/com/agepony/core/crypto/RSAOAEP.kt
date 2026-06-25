package com.agepony.core.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.encodings.OAEPEncoding
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import java.math.BigInteger

/**
 * RSA-OAEP with SHA-256 hash and MGF1-SHA-256, with a custom label.
 *
 * age uses this for the ssh-rsa recipient stanza body, with
 * `label = "age-encryption.org/v1/ssh-rsa".toByteArray()`.
 *
 * Ciphertext size always equals the RSA modulus byte length (256 for RSA-2048,
 * 384 for RSA-3072, 512 for RSA-4096).
 */
object RSAOAEP {
    class RSAOAEPException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** Encrypt with the RSA public key (modulus, exponent) and the given label. */
    fun encrypt(
        modulus: BigInteger,
        exponent: BigInteger,
        label: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val oaep = OAEPEncoding(RSAEngine(), SHA256Digest(), SHA256Digest(), label)
        oaep.init(true, RSAKeyParameters(false, modulus, exponent))
        return try {
            oaep.processBlock(plaintext, 0, plaintext.size)
        } catch (e: Exception) {
            throw RSAOAEPException("RSA-OAEP encrypt failed", e)
        }
    }

    /**
     * Decrypt with the RSA private key in CRT form. `dp` and `dq` are computed from
     * `d, p, q`; `iqmp` (= q^-1 mod p) is read from the SSH PEM directly.
     */
    fun decrypt(
        modulus: BigInteger,
        publicExponent: BigInteger,
        privateExponent: BigInteger,
        p: BigInteger,
        q: BigInteger,
        iqmp: BigInteger,
        label: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val pMinusOne = p.subtract(BigInteger.ONE)
        val qMinusOne = q.subtract(BigInteger.ONE)
        val dp = privateExponent.mod(pMinusOne)
        val dq = privateExponent.mod(qMinusOne)
        val oaep = OAEPEncoding(RSAEngine(), SHA256Digest(), SHA256Digest(), label)
        oaep.init(
            false,
            RSAPrivateCrtKeyParameters(
                modulus, publicExponent, privateExponent, p, q, dp, dq, iqmp
            )
        )
        return try {
            oaep.processBlock(ciphertext, 0, ciphertext.size)
        } catch (e: Exception) {
            throw RSAOAEPException("RSA-OAEP decrypt/auth failed", e)
        }
    }
}
