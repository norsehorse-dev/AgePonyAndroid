package com.agepony.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.SecureRandom

/**
 * Streaming payload tests. The core guarantee: [AgePayload.encryptStream] /
 * [AgePayload.decryptStream] produce byte-identical results to the whole-buffer
 * [AgePayload.encrypt] / [AgePayload.decrypt] for the same fileKey and nonce, while holding
 * only a couple of chunks in memory.
 */
class AgePayloadStreamTests {
    private val rng = SecureRandom()
    private fun randomFileKey() = ByteArray(16).also { rng.nextBytes(it) }
    private fun fixedNonce() = ByteArray(16) { it.toByte() }

    // Sizes chosen to exercise every boundary: empty, sub-chunk, exact chunk multiples,
    // one-over, and multi-chunk arbitrary lengths.
    private val sizes = listOf(
        0, 1, 2, 100,
        AgePayload.CHUNK_SIZE - 1,
        AgePayload.CHUNK_SIZE,
        AgePayload.CHUNK_SIZE + 1,
        2 * AgePayload.CHUNK_SIZE - 1,
        2 * AgePayload.CHUNK_SIZE,
        2 * AgePayload.CHUNK_SIZE + 1,
        200_000,
        500_000,
    )

    @Test
    fun streamingEncrypt_isByteIdenticalToWholeBuffer() {
        for (size in sizes) {
            val key = randomFileKey()
            val nonce = fixedNonce()
            val plaintext = ByteArray(size).also { rng.nextBytes(it) }

            val whole = AgePayload.encrypt(key, plaintext, nonce)

            val streamed = ByteArrayOutputStream()
            AgePayload.encryptStream(key, ByteArrayInputStream(plaintext), streamed, nonce)

            assertArrayEquals(whole, streamed.toByteArray(), "encrypt mismatch at size=$size")
        }
    }

    @Test
    fun streamingDecrypt_recoversWholeBufferCiphertext() {
        for (size in sizes) {
            val key = randomFileKey()
            val plaintext = ByteArray(size).also { rng.nextBytes(it) }
            val ct = AgePayload.encrypt(key, plaintext)

            val out = ByteArrayOutputStream()
            AgePayload.decryptStream(key, ByteArrayInputStream(ct), out)

            assertArrayEquals(plaintext, out.toByteArray(), "decrypt mismatch at size=$size")
        }
    }

    @Test
    fun streamRoundTrip_acrossAllSizes() {
        for (size in sizes) {
            val key = randomFileKey()
            val plaintext = ByteArray(size).also { rng.nextBytes(it) }

            val ct = ByteArrayOutputStream()
            AgePayload.encryptStream(key, ByteArrayInputStream(plaintext), ct)

            val pt = ByteArrayOutputStream()
            AgePayload.decryptStream(key, ByteArrayInputStream(ct.toByteArray()), pt)

            assertArrayEquals(plaintext, pt.toByteArray(), "round-trip mismatch at size=$size")
        }
    }

    @Test
    fun streamRoundTrip_largeFileViaDisk_boundedMemory() {
        // 12 MiB exercises ~192 chunks; routed through temp files so the test itself
        // never holds the whole payload in memory, demonstrating bounded-memory streaming.
        val key = randomFileKey()
        val size = 12 * 1024 * 1024
        val src = File.createTempFile("agepony_pt_", ".bin")
        val enc = File.createTempFile("agepony_ct_", ".age")
        val dec = File.createTempFile("agepony_rt_", ".bin")
        try {
            src.outputStream().use { o ->
                val block = ByteArray(64 * 1024)
                var written = 0
                while (written < size) {
                    rng.nextBytes(block)
                    val n = minOf(block.size, size - written)
                    o.write(block, 0, n)
                    written += n
                }
            }
            src.inputStream().use { i -> enc.outputStream().use { o -> AgePayload.encryptStream(key, i, o) } }
            enc.inputStream().use { i -> dec.outputStream().use { o -> AgePayload.decryptStream(key, i, o) } }

            assertEquals(src.length(), dec.length(), "length mismatch after large round-trip")
            assertArrayEquals(sha256(src), sha256(dec), "content hash mismatch after large round-trip")
        } finally {
            src.delete(); enc.delete(); dec.delete()
        }
    }

    @Test
    fun streamDecrypt_failsLoudlyOnBitFlip() {
        val key = randomFileKey()
        val ct = AgePayload.encrypt(key, "secret data".toByteArray()).copyOf()
        ct[20] = (ct[20].toInt() xor 0x01).toByte()   // flip a byte inside the first chunk
        assertThrows(AgePayload.PayloadException::class.java) {
            AgePayload.decryptStream(key, ByteArrayInputStream(ct), ByteArrayOutputStream())
        }
    }

    @Test
    fun streamDecrypt_rejectsTruncatedNonce() {
        val key = randomFileKey()
        assertThrows(AgePayload.PayloadException::class.java) {
            AgePayload.decryptStream(key, ByteArrayInputStream(ByteArray(8)), ByteArrayOutputStream())
        }
    }

    private fun sha256(f: File): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        f.inputStream().use { i ->
            val b = ByteArray(64 * 1024)
            while (true) {
                val n = i.read(b)
                if (n < 0) break
                md.update(b, 0, n)
            }
        }
        return md.digest()
    }
}
