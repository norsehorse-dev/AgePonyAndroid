package com.agepony.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class AgePayloadTests {
    private fun randomFileKey() = ByteArray(16).also { SecureRandom().nextBytes(it) }

    @Test
    fun roundTrip_emptyPlaintext() {
        val key = randomFileKey()
        val ct = AgePayload.encrypt(key, ByteArray(0))
        // 16-byte nonce + (0 plaintext + 16 tag) chunk = 32 bytes minimum
        assertTrue(ct.size == 32)
        val pt = AgePayload.decrypt(key, ct)
        assertArrayEquals(ByteArray(0), pt)
    }

    @Test
    fun roundTrip_tinyPlaintext() {
        val key = randomFileKey()
        val plaintext = "hi".toByteArray()
        val ct = AgePayload.encrypt(key, plaintext)
        assertArrayEquals(plaintext, AgePayload.decrypt(key, ct))
    }

    @Test
    fun roundTrip_singleFullChunk_64KB() {
        val key = randomFileKey()
        val plaintext = ByteArray(64 * 1024).also { SecureRandom().nextBytes(it) }
        val ct = AgePayload.encrypt(key, plaintext)
        assertArrayEquals(plaintext, AgePayload.decrypt(key, ct))
    }

    @Test
    fun roundTrip_justOverOneChunk_64KBplus1() {
        val key = randomFileKey()
        val plaintext = ByteArray(64 * 1024 + 1).also { SecureRandom().nextBytes(it) }
        val ct = AgePayload.encrypt(key, plaintext)
        assertArrayEquals(plaintext, AgePayload.decrypt(key, ct))
    }

    @Test
    fun roundTrip_exactlyTwoChunks_128KB() {
        val key = randomFileKey()
        val plaintext = ByteArray(128 * 1024).also { SecureRandom().nextBytes(it) }
        val ct = AgePayload.encrypt(key, plaintext)
        assertArrayEquals(plaintext, AgePayload.decrypt(key, ct))
    }

    @Test
    fun roundTrip_arbitrary500KB() {
        val key = randomFileKey()
        val plaintext = ByteArray(500_000).also { SecureRandom().nextBytes(it) }
        val ct = AgePayload.encrypt(key, plaintext)
        assertArrayEquals(plaintext, AgePayload.decrypt(key, ct))
    }

    @Test
    fun decrypt_rejectsShortPayload() {
        val key = randomFileKey()
        assertThrows(AgePayload.PayloadException::class.java) {
            AgePayload.decrypt(key, ByteArray(20))   // 20 < 16 nonce + 16 tag minimum
        }
    }

    @Test
    fun decrypt_failsOnBitFlipInPayload() {
        val key = randomFileKey()
        val plaintext = "secret data".toByteArray()
        val ct = AgePayload.encrypt(key, plaintext).copyOf()
        // Flip a byte in the encrypted chunk (after the 16-byte nonce)
        ct[20] = (ct[20].toInt() xor 0x01).toByte()
        assertThrows(AgePayload.PayloadException::class.java) {
            AgePayload.decrypt(key, ct)
        }
    }
}
