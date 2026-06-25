package com.agepony.core

import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.HKDF
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom

/**
 * Chunked ChaCha20-Poly1305 payload encryption/decryption.
 *
 * Layout: `<16B random nonce N> || <chunk1_ct> || <chunk2_ct> || ... || <last_chunk_ct>`
 *
 * - payloadKey = HKDF-SHA256(ikm=fileKey, salt=N, info="payload", L=32)
 * - Each chunk: 64 KiB of plaintext → 64 KiB + 16 B of ciphertext (Poly1305 tag).
 *   The LAST chunk has 0 ≤ plaintext_size ≤ 64 KiB; it may be a full 64 KiB.
 * - Per-chunk nonce = 11-byte BE counter (starting at 0) || 1-byte flag (0 non-last, 1 last).
 * - Empty plaintext encodes as ONE chunk of 0 bytes plaintext + 16-byte tag.
 *
 * Two API styles are provided, producing byte-identical output for the same fileKey + nonce:
 *   - Whole-buffer: [encrypt] / [decrypt] operate on ByteArrays (convenient for small data).
 *   - Streaming:   [encryptStream] / [decryptStream] operate on InputStream/OutputStream in
 *                  bounded memory (one 64 KiB chunk at a time), for large files.
 */
object AgePayload {
    const val CHUNK_SIZE = 64 * 1024              // 65536 plaintext bytes per chunk
    const val CT_CHUNK_SIZE = CHUNK_SIZE + 16     // 65552 ciphertext bytes per full chunk
    private const val PAYLOAD_INFO = "payload"

    class PayloadException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /**
     * Encrypt `plaintext` using the given `fileKey`. Returns `nonce || encrypted_chunks`.
     */
    fun encrypt(fileKey: ByteArray, plaintext: ByteArray, nonce: ByteArray = randomNonce16()): ByteArray {
        require(nonce.size == 16) { "payload nonce must be 16 bytes" }
        val payloadKey = HKDF.derive(fileKey, nonce, PAYLOAD_INFO.toByteArray(), 32)
        val out = ByteArrayOutputStream()
        out.write(nonce)

        val totalChunks = if (plaintext.isEmpty()) 1
                          else (plaintext.size + CHUNK_SIZE - 1) / CHUNK_SIZE
        var counter = 0L
        for (i in 0 until totalChunks) {
            val isLast = (i == totalChunks - 1)
            val start = i * CHUNK_SIZE
            val end = minOf(start + CHUNK_SIZE, plaintext.size)
            val chunk = if (plaintext.isEmpty()) ByteArray(0) else plaintext.copyOfRange(start, end)
            val chunkNonce = makeNonce(counter, isLast)
            val ct = ChaChaPoly.encrypt(payloadKey, chunkNonce, chunk)
            out.write(ct)
            counter++
        }
        return out.toByteArray()
    }

    /**
     * Decrypt `nonce || encrypted_chunks` using the given `fileKey`.
     * `payloadBytes` is the bytes immediately after the header (starts with the 16-byte nonce).
     */
    fun decrypt(fileKey: ByteArray, payloadBytes: ByteArray): ByteArray {
        if (payloadBytes.size < 16 + 16) {
            throw PayloadException("payload too short (need at least 16B nonce + 16B tag)")
        }
        val nonce = payloadBytes.copyOfRange(0, 16)
        val payloadKey = HKDF.derive(fileKey, nonce, PAYLOAD_INFO.toByteArray(), 32)
        val out = ByteArrayOutputStream()
        var pos = 16
        var counter = 0L
        while (pos < payloadBytes.size) {
            val remaining = payloadBytes.size - pos
            val isLast = remaining <= CT_CHUNK_SIZE
            val take = if (isLast) remaining else CT_CHUNK_SIZE
            val chunkNonce = makeNonce(counter, isLast)
            val pt = try {
                ChaChaPoly.decrypt(
                    payloadKey,
                    chunkNonce,
                    payloadBytes.copyOfRange(pos, pos + take)
                )
            } catch (e: Exception) {
                throw PayloadException("chunk $counter authentication failed (isLast=$isLast)", e)
            }
            out.write(pt)
            pos += take
            counter++
        }
        return out.toByteArray()
    }

    /**
     * Streaming encrypt: read plaintext from `plaintext`, write `nonce || encrypted_chunks` to
     * `out`, holding at most ~2 chunks in memory at once. Byte-identical to [encrypt] for the
     * same `fileKey` and `nonce`.
     *
     * Uses one-chunk lookahead so the final chunk (full or partial) is correctly flagged as last
     * without emitting a spurious trailing empty chunk. Does not close either stream.
     */
    fun encryptStream(
        fileKey: ByteArray,
        plaintext: InputStream,
        out: OutputStream,
        nonce: ByteArray = randomNonce16(),
    ) {
        require(nonce.size == 16) { "payload nonce must be 16 bytes" }
        val payloadKey = HKDF.derive(fileKey, nonce, PAYLOAD_INFO.toByteArray(), 32)
        out.write(nonce)

        var counter = 0L
        var buf = readFully(plaintext, CHUNK_SIZE)
        while (true) {
            val next = readFully(plaintext, CHUNK_SIZE)
            val isLast = next.isEmpty()
            val chunkNonce = makeNonce(counter, isLast)
            out.write(ChaChaPoly.encrypt(payloadKey, chunkNonce, buf))
            counter++
            if (isLast) break
            buf = next
        }
    }

    /**
     * Streaming decrypt: read `nonce || encrypted_chunks` from `payload`, write plaintext to
     * `out`, holding at most ~2 ciphertext chunks in memory at once. Byte-identical result to
     * [decrypt].
     *
     * Uses one-byte lookahead to disambiguate a full final chunk from a full non-final chunk
     * (both are CT_CHUNK_SIZE on the wire). Does not close either stream.
     */
    fun decryptStream(
        fileKey: ByteArray,
        payload: InputStream,
        out: OutputStream,
    ) {
        val nonce = readFully(payload, 16)
        if (nonce.size < 16) {
            throw PayloadException("payload too short (need at least 16B nonce)")
        }
        val payloadKey = HKDF.derive(fileKey, nonce, PAYLOAD_INFO.toByteArray(), 32)

        var counter = 0L
        var ct = readFully(payload, CT_CHUNK_SIZE)
        while (true) {
            if (ct.size < CT_CHUNK_SIZE) {
                // A short chunk can only be the final chunk.
                decryptChunk(payloadKey, counter, isLast = true, ctChunk = ct, out = out)
                break
            }
            // Full chunk: ambiguous. Peek one byte to learn whether more chunks follow.
            val peek = payload.read()
            if (peek < 0) {
                decryptChunk(payloadKey, counter, isLast = true, ctChunk = ct, out = out)
                break
            }
            // More data follows, so this chunk is NOT the last one.
            decryptChunk(payloadKey, counter, isLast = false, ctChunk = ct, out = out)
            counter++
            val rest = readFully(payload, CT_CHUNK_SIZE - 1)
            ct = ByteArray(1 + rest.size)
            ct[0] = peek.toByte()
            System.arraycopy(rest, 0, ct, 1, rest.size)
        }
    }

    // --- Internals ---

    private fun randomNonce16(): ByteArray {
        val n = ByteArray(16)
        SecureRandom().nextBytes(n)
        return n
    }

    /**
     * Read up to `n` bytes from `input`, blocking through short reads until `n` bytes are read
     * or EOF is reached. Returns an array of the actual number of bytes read (0..n).
     */
    private fun readFully(input: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(buf, off, n - off)
            if (r < 0) break
            off += r
        }
        return if (off == n) buf else buf.copyOf(off)
    }

    /**
     * Decrypt and authenticate a single ciphertext chunk, writing the recovered plaintext to `out`.
     */
    private fun decryptChunk(
        payloadKey: ByteArray,
        counter: Long,
        isLast: Boolean,
        ctChunk: ByteArray,
        out: OutputStream,
    ) {
        if (ctChunk.size < 16) {
            throw PayloadException("chunk $counter too short for 16B tag (got ${ctChunk.size})")
        }
        val chunkNonce = makeNonce(counter, isLast)
        val pt = try {
            ChaChaPoly.decrypt(payloadKey, chunkNonce, ctChunk)
        } catch (e: Exception) {
            throw PayloadException("chunk $counter authentication failed (isLast=$isLast)", e)
        }
        out.write(pt)
    }

    /**
     * Build the 12-byte per-chunk nonce: 11-byte BE counter || 1-byte last-flag.
     */
    private fun makeNonce(counter: Long, isLast: Boolean): ByteArray {
        val nonce = ByteArray(12)
        // 11-byte BE counter at offsets [0..10], so the LSB goes at offset 10.
        var c = counter
        for (i in 10 downTo 0) {
            nonce[i] = (c and 0xff).toByte()
            c = c ushr 8
        }
        if (c != 0L) throw PayloadException("chunk counter overflowed 11 bytes")
        nonce[11] = if (isLast) 1 else 0
        return nonce
    }
}
