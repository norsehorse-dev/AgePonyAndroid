package com.agepony.core.ssh

import org.bouncycastle.crypto.digests.SHA512Digest
import java.math.BigInteger

/**
 * Convert Ed25519 keys to X25519 keys. Ed25519 (twisted Edwards) and X25519 (Montgomery)
 * are isomorphic curves over the same prime field; the conversions are:
 *
 *   - Public key (encoded y-coordinate with sign-of-x in top bit):
 *       1. Decode 32 bytes as little-endian integer; clear the top bit.
 *       2. y = the resulting field element.
 *       3. u = (1 + y) * (1 - y)^-1  mod  p   where p = 2^255 - 19.
 *       4. Encode u as 32 bytes little-endian.
 *
 *   - Private key (32-byte seed → 32-byte X25519 scalar):
 *       1. Compute SHA-512(seed); take the first 32 bytes.
 *       2. Apply X25519 clamping: clear bottom 3 bits of byte 0;
 *          clear top bit and set second-to-top bit of byte 31.
 *       3. The clamped value is the X25519 scalar (identical to the scalar
 *          Ed25519 derives internally for signing).
 *
 * BouncyCastle does not expose these conversions, so they're implemented here.
 */
object Ed25519Conversion {
    private val P: BigInteger = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19))
    private val ONE: BigInteger = BigInteger.ONE

    /** Convert a 32-byte Ed25519 public key to a 32-byte X25519 public key. */
    fun publicKeyToX25519(edPublicKey: ByteArray): ByteArray {
        require(edPublicKey.size == 32) { "Ed25519 public key must be 32 bytes" }
        // Decode as little-endian with sign bit cleared
        val yBytes = edPublicKey.copyOf()
        yBytes[31] = (yBytes[31].toInt() and 0x7f).toByte()
        val y = leBytesToBigInt(yBytes)

        // u = (1 + y) * (1 - y)^-1  mod p
        val numerator = ONE.add(y).mod(P)
        val denominator = ONE.subtract(y).mod(P)
        val u = numerator.multiply(denominator.modInverse(P)).mod(P)

        return bigIntToLeBytes(u, 32)
    }

    /** Convert a 32-byte Ed25519 seed to a 32-byte X25519 private scalar. */
    fun privateKeyToX25519(edSeed: ByteArray): ByteArray {
        require(edSeed.size == 32) { "Ed25519 seed must be 32 bytes" }
        val digest = SHA512Digest()
        digest.update(edSeed, 0, edSeed.size)
        val full = ByteArray(64)
        digest.doFinal(full, 0)
        val scalar = full.copyOfRange(0, 32)
        // Clamp per X25519 (RFC 7748 §5)
        scalar[0] = (scalar[0].toInt() and 0xf8).toByte()
        scalar[31] = (scalar[31].toInt() and 0x7f).toByte()
        scalar[31] = (scalar[31].toInt() or 0x40).toByte()
        return scalar
    }

    // --- Internals ---

    private fun leBytesToBigInt(bytes: ByteArray): BigInteger {
        // BigInteger expects big-endian; reverse, then mark as positive.
        return BigInteger(1, bytes.reversedArray())
    }

    private fun bigIntToLeBytes(value: BigInteger, len: Int): ByteArray {
        val be = value.toByteArray()
        // Strip leading sign byte if BigInteger added one
        val unsigned = if (be.isNotEmpty() && be[0] == 0.toByte() && be.size > 1) {
            be.copyOfRange(1, be.size)
        } else be
        // Right-align into a len-byte BE buffer, then reverse to LE
        val beBuf = ByteArray(len)
        val offset = len - unsigned.size
        if (offset < 0) throw IllegalArgumentException("value too large for $len bytes")
        for (i in unsigned.indices) {
            beBuf[offset + i] = unsigned[i]
        }
        return beBuf.reversedArray()
    }
}
