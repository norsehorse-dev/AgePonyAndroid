package com.agepony.core.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test

/**
 * AES-256-CBC tests. The known-answer pair is the NIST SP 800-38A Appendix F.2 CBC-AES256
 * first block; the zero-IV path is what FIDO PIN protocol v1 uses.
 */
class AESCBCTests {
    private fun fromHex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private val key = fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    private val iv = fromHex("000102030405060708090a0b0c0d0e0f")
    private val plaintext = fromHex("6bc1bee22e409f96e93d7e117393172a")
    private val ciphertext = "f58c4c04d6e5f1ba779eabfb5f7bfbd6"

    @Test
    fun nistCbcKat() {
        assertEquals(ciphertext, toHex(AESCBC.encrypt(key, iv, plaintext)))
        assertArrayEquals(plaintext, AESCBC.decrypt(key, iv, fromHex(ciphertext)))
    }

    @Test
    fun zeroIvRoundTrips() {
        val k = ByteArray(32) { it.toByte() }
        val data = ByteArray(48) { (it * 7).toByte() }
        val ct = AESCBC.encrypt(k, AESCBC.ZERO_IV, data)
        assertArrayEquals(data, AESCBC.decrypt(k, AESCBC.ZERO_IV, ct))
    }

    @Test
    fun rejectsNonBlockSizedInput() {
        assertThrows<IllegalArgumentException> {
            AESCBC.encrypt(ByteArray(32), AESCBC.ZERO_IV, ByteArray(15))
        }
    }

    @Test
    fun rejectsWrongKeySize() {
        assertThrows<IllegalArgumentException> {
            AESCBC.encrypt(ByteArray(16), AESCBC.ZERO_IV, ByteArray(16))
        }
    }
}
