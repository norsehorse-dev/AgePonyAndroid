package com.agepony.core.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * AES-256-CTR tests, including NIST SP 800-38A Appendix F.5.5 (CTR-AES256) test vectors.
 *
 * NIST counts the IV bytes as the initial 128-bit counter block and increments per block
 * in big-endian. BC's SICBlockCipher uses the same convention, so we expect the first
 * encrypted block to match NIST's expected output exactly.
 */
class AESCTRTests {
    private fun fromHex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun toHex(b: ByteArray): String =
        b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    /** NIST SP 800-38A F.5.5 — first 16-byte block (counter = initial IV). */
    @Test
    fun nist_F55_block1() {
        val key = fromHex("603deb1015ca71be2b73aef0857d7781" +
                          "1f352c073b6108d72d9810a30914dff4")
        val iv  = fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        val pt  = fromHex("6bc1bee22e409f96e93d7e117393172a")
        val expected = "601ec313775789a5b7a7f504bbf3d228"
        assertEquals(expected, toHex(AESCTR.encrypt(key, iv, pt)))
    }

    /** NIST SP 800-38A F.5.5 — all 4 blocks (64 bytes), tests counter increment. */
    @Test
    fun nist_F55_allFourBlocks() {
        val key = fromHex("603deb1015ca71be2b73aef0857d7781" +
                          "1f352c073b6108d72d9810a30914dff4")
        val iv  = fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        val pt  = fromHex("6bc1bee22e409f96e93d7e117393172a" +
                          "ae2d8a571e03ac9c9eb76fac45af8e51" +
                          "30c81c46a35ce411e5fbc1191a0a52ef" +
                          "f69f2445df4f9b17ad2b417be66c3710")
        val expected = "601ec313775789a5b7a7f504bbf3d228" +
                       "f443e3ca4d62b59aca84e990cacaf5c5" +
                       "2b0930daa23de94ce87017ba2d84988d" +
                       "dfc9c58db67aada613c2dd08457941a6"
        assertEquals(expected, toHex(AESCTR.encrypt(key, iv, pt)))
    }

    @Test
    fun decrypt_isInverseOfEncrypt() {
        val key = ByteArray(32) { (it * 7).toByte() }
        val iv  = ByteArray(16) { (it * 13).toByte() }
        val pt  = "hello agepony — encrypted with CTR mode".toByteArray(Charsets.UTF_8)
        val ct = AESCTR.encrypt(key, iv, pt)
        val pt2 = AESCTR.decrypt(key, iv, ct)
        assertArrayEquals(pt, pt2)
    }

    @Test
    fun encrypt_outputSizeEqualsInputSize() {
        // CTR is a stream cipher — no padding, output length matches input.
        val key = ByteArray(32)
        val iv = ByteArray(16)
        for (size in intArrayOf(0, 1, 15, 16, 17, 32, 100, 1024)) {
            val pt = ByteArray(size)
            val ct = AESCTR.encrypt(key, iv, pt)
            assertEquals(size, ct.size, "size $size produced wrong ciphertext length")
        }
    }

    @Test
    fun encrypt_partialBlockEncryptsCorrectly() {
        // Single-byte plaintext — only first byte of counter keystream used.
        val key = ByteArray(32) { 0x42.toByte() }
        val iv = ByteArray(16) { 0x11.toByte() }
        val pt = byteArrayOf(0x55)
        val ct = AESCTR.encrypt(key, iv, pt)
        assertEquals(1, ct.size)
        // Decrypt should give back the same byte.
        assertArrayEquals(pt, AESCTR.decrypt(key, iv, ct))
    }

    @Test
    fun roundTrip_randomInputs() {
        val random = SecureRandom()
        for (trial in 0 until 5) {
            val key = ByteArray(32).also { random.nextBytes(it) }
            val iv = ByteArray(16).also { random.nextBytes(it) }
            val sz = random.nextInt(1024)
            val pt = ByteArray(sz).also { random.nextBytes(it) }
            val ct = AESCTR.encrypt(key, iv, pt)
            assertArrayEquals(pt, AESCTR.decrypt(key, iv, ct))
        }
    }

    @Test
    fun rejects_wrongKeyLength() {
        val iv = ByteArray(16)
        val pt = ByteArray(16)
        assertThrows(IllegalArgumentException::class.java) {
            AESCTR.encrypt(ByteArray(16), iv, pt)  // AES-128 key — we only do AES-256
        }
        assertThrows(IllegalArgumentException::class.java) {
            AESCTR.encrypt(ByteArray(24), iv, pt)  // AES-192 — also rejected
        }
    }

    @Test
    fun rejects_wrongIVLength() {
        val key = ByteArray(32)
        val pt = ByteArray(16)
        assertThrows(IllegalArgumentException::class.java) {
            AESCTR.encrypt(key, ByteArray(12), pt)  // 12-byte IV not supported
        }
        assertThrows(IllegalArgumentException::class.java) {
            AESCTR.encrypt(key, ByteArray(8), pt)
        }
    }
}
