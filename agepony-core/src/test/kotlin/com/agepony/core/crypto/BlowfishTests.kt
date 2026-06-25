package com.agepony.core.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Standard Blowfish KAT vectors from Eric Young's published test set (also reproduced
 * in Schneier's "Applied Cryptography" Blowfish appendix). These exercise the full key
 * schedule (expand0state) and one round of encryption, so any typo in the π-derived
 * P-array or S-box constants will produce a wrong ciphertext.
 */
class BlowfishTests {
    private fun fromHex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun toHex(v: IntArray): String =
        v.joinToString("") { "%08x".format(it) }

    private fun encryptOnce(keyHex: String, plaintextHex: String): String {
        val key = fromHex(keyHex)
        val pt = fromHex(plaintextHex)
        val state = Blowfish()
        state.expand0state(key)
        // Read plaintext as two BE uint32s
        val L = ((pt[0].toInt() and 0xff) shl 24) or
                ((pt[1].toInt() and 0xff) shl 16) or
                ((pt[2].toInt() and 0xff) shl 8) or
                (pt[3].toInt() and 0xff)
        val R = ((pt[4].toInt() and 0xff) shl 24) or
                ((pt[5].toInt() and 0xff) shl 16) or
                ((pt[6].toInt() and 0xff) shl 8) or
                (pt[7].toInt() and 0xff)
        return toHex(state.encipher(L, R))
    }

    @Test
    fun kat_allZeros() {
        // key=0x0000000000000000, pt=0x0000000000000000 → ct=0x4EF997456198DD78
        assertEquals("4ef997456198dd78", encryptOnce("0000000000000000", "0000000000000000"))
    }

    @Test
    fun kat_allOnes() {
        // key=0xFFFFFFFFFFFFFFFF, pt=0xFFFFFFFFFFFFFFFF → ct=0x51866FD5B85ECB8A
        assertEquals("51866fd5b85ecb8a", encryptOnce("ffffffffffffffff", "ffffffffffffffff"))
    }

    @Test
    fun kat_mixed() {
        // key=0x3000000000000000, pt=0x1000000000000001 → ct=0x7D856F9A613063F2
        assertEquals("7d856f9a613063f2", encryptOnce("3000000000000000", "1000000000000001"))
    }

    @Test
    fun kat_partialKey() {
        // key=0x1111111111111111, pt=0x1111111111111111 → ct=0x2466DD878B963C9D
        assertEquals("2466dd878b963c9d", encryptOnce("1111111111111111", "1111111111111111"))
    }

    @Test
    fun kat_asymmetric() {
        // key=0x0123456789ABCDEF, pt=0x1111111111111111 → ct=0x61F9C3802281B096
        assertEquals("61f9c3802281b096", encryptOnce("0123456789abcdef", "1111111111111111"))
    }
}
