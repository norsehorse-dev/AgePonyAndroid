package com.agepony.core.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class ChaChaPolyTests {
    private fun fromHex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** RFC 7539 §2.8.2: AEAD_CHACHA20_POLY1305 test vector. */
    @Test
    fun rfc7539_testVector() {
        val key = fromHex(
            "808182838485868788898a8b8c8d8e8f" +
            "909192939495969798999a9b9c9d9e9f"
        )
        val nonce = fromHex("070000004041424344454647")
        val aad = fromHex("50515253c0c1c2c3c4c5c6c7")
        val plaintext = ("Ladies and Gentlemen of the class of '99: " +
                        "If I could offer you only one tip for the future, " +
                        "sunscreen would be it.").toByteArray()
        // Expected: 114 bytes of ciphertext + 16-byte tag
        val expected = fromHex(
            "d31a8d34648e60db7b86afbc53ef7ec2" +
            "a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b" +
            "1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58" +
            "fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b" +
            "6116" +
            "1ae10b594f09e26a7e902ecbd0600691"  // tag
        )
        val ct = ChaChaPoly.encrypt(key, nonce, plaintext, aad)
        assertArrayEquals(expected, ct)
    }

    @Test
    fun roundTrip_emptyPlaintext() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(12) { (0xff - it).toByte() }
        val ct = ChaChaPoly.encrypt(key, nonce, ByteArray(0))
        assertEquals(16, ct.size)  // just the tag
        val pt = ChaChaPoly.decrypt(key, nonce, ct)
        assertEquals(0, pt.size)
    }

    @Test
    fun roundTrip_randomPayload() {
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val plaintext = ByteArray(1000).also { SecureRandom().nextBytes(it) }
        val ct = ChaChaPoly.encrypt(key, nonce, plaintext)
        val pt = ChaChaPoly.decrypt(key, nonce, ct)
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun bitFlip_failsAuthentication() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(12) { (0xff - it).toByte() }
        val ct = ChaChaPoly.encrypt(key, nonce, "secret".toByteArray()).copyOf()
        ct[0] = (ct[0].toInt() xor 0x01).toByte()
        assertThrows(ChaChaPoly.AeadException::class.java) {
            ChaChaPoly.decrypt(key, nonce, ct)
        }
    }
}
