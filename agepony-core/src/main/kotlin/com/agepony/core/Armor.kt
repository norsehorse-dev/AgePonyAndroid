package com.agepony.core

import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.util.Base64

/**
 * age ASCII armor format:
 * ```
 * -----BEGIN AGE ENCRYPTED FILE-----
 * <standard padded base64, wrapped at 64 columns>
 * -----END AGE ENCRYPTED FILE-----
 * ```
 *
 * Encode/decode is symmetric. Decode is lenient about trailing whitespace and CRLF.
 *
 * [encode] / [decode] hold the whole input and the whole result in memory, which is fine for
 * notes and pasted text. [encodeStream] / [decodeStream] are the bounded-memory equivalents
 * for files: they hold one 48 KiB working buffer regardless of input size, and produce
 * byte-identical output to the whole-buffer pair for the same input.
 */
object Armor {
    const val BEGIN_MARKER = "-----BEGIN AGE ENCRYPTED FILE-----"
    const val END_MARKER = "-----END AGE ENCRYPTED FILE-----"
    private const val LINE_WIDTH = 64

    /**
     * 48 binary bytes encode to exactly [LINE_WIDTH] base64 characters with no padding, so the
     * input can be chunked on 48-byte boundaries and still yield identical lines. Padding can
     * only appear in the final group, which is the only group allowed to be short.
     */
    private const val GROUP = LINE_WIDTH / 4 * 3   // 48
    private const val READ_CHUNK = GROUP * 1024    // 48 KiB per read
    private const val FLUSH_AT = 64 * 1024         // decode pending base64 in 64 KiB batches

    /** Bytes to sniff from the head of a file to recognize armor. */
    const val SNIFF_LEN = 64

    class ArmorException(message: String) : Exception(message)

    fun encode(binary: ByteArray): String {
        val b64 = Base64.getEncoder().encodeToString(binary)
        val sb = StringBuilder()
        sb.append(BEGIN_MARKER).append('\n')
        var i = 0
        while (i < b64.length) {
            val end = minOf(i + LINE_WIDTH, b64.length)
            sb.append(b64, i, end).append('\n')
            i = end
        }
        sb.append(END_MARKER).append('\n')
        return sb.toString()
    }

    fun decode(armored: String): ByteArray {
        val normalized = armored.replace("\r\n", "\n").trim()
        val lines = normalized.split('\n').map { it.trimEnd() }
        if (lines.size < 2) throw ArmorException("armor too short")
        if (lines.first() != BEGIN_MARKER) throw ArmorException("missing BEGIN marker")
        if (lines.last() != END_MARKER) throw ArmorException("missing END marker")
        val body = if (lines.size > 2) lines.subList(1, lines.size - 1).joinToString("") else ""
        if (body.isEmpty()) return ByteArray(0)
        return try {
            Base64.getDecoder().decode(body)
        } catch (e: IllegalArgumentException) {
            throw ArmorException("invalid base64 in armor body: ${e.message}")
        }
    }

    /**
     * True if [prefix] (the first bytes of a file, [SNIFF_LEN] of them where available) begins
     * with the armor BEGIN marker, ignoring leading whitespace. Lets a streaming reader decide
     * whether to armor-decode without buffering the whole file.
     */
    fun looksArmored(prefix: ByteArray): Boolean {
        val text = String(prefix, Charsets.US_ASCII)
        val trimmed = text.trimStart()
        return if (trimmed.length >= BEGIN_MARKER.length) {
            trimmed.startsWith(BEGIN_MARKER)
        } else {
            // Truncated prefix: still conclusive when what we have already diverges.
            trimmed.isNotEmpty() && BEGIN_MARKER.startsWith(trimmed)
        }
    }

    /**
     * Streaming encode: read binary from [binary], write armored text to [out] in bounded
     * memory. Output is byte for byte what [encode] would produce for the same input.
     * Does not close either stream.
     */
    fun encodeStream(binary: InputStream, out: OutputStream) {
        val encoder = Base64.getEncoder()
        val nl = '\n'.code
        out.write(BEGIN_MARKER.toByteArray(Charsets.US_ASCII))
        out.write(nl)

        val buf = ByteArray(READ_CHUNK)
        while (true) {
            val n = readFully(binary, buf)
            if (n == 0) break
            val aligned = n - (n % GROUP)
            if (aligned > 0) {
                // A multiple of 48 bytes encodes to a multiple of 64 unpadded base64 chars.
                val enc = encoder.encode(if (aligned == buf.size) buf else buf.copyOfRange(0, aligned))
                var i = 0
                while (i < enc.size) {
                    out.write(enc, i, LINE_WIDTH)
                    out.write(nl)
                    i += LINE_WIDTH
                }
            }
            if (aligned < n) {
                // Short group: only possible at end of input, and the only place padding appears.
                out.write(encoder.encode(buf.copyOfRange(aligned, n)))
                out.write(nl)
                break
            }
            if (n < buf.size) break // clean EOF on a group boundary
        }

        out.write(END_MARKER.toByteArray(Charsets.US_ASCII))
        out.write(nl)
    }

    /**
     * Streaming decode: read armored text from [armored], write decoded binary to [out] in
     * bounded memory. Accepts what [decode] accepts, including CRLF line endings, trailing
     * whitespace and blank lines around the markers. Does not close either stream.
     */
    fun decodeStream(armored: InputStream, out: OutputStream) {
        val reader = BufferedReader(InputStreamReader(armored, Charsets.US_ASCII))
        val decoder = Base64.getDecoder()
        val pending = StringBuilder(FLUSH_AT + LINE_WIDTH)
        var sawBegin = false
        var sawEnd = false
        var sawPadding = false

        fun flush(all: Boolean) {
            val take = if (all) pending.length else pending.length - (pending.length % 4)
            if (take == 0) return
            val chunk = pending.substring(0, take)
            pending.delete(0, take)
            if (chunk.indexOf('=') >= 0) sawPadding = true
            val bytes = try {
                decoder.decode(chunk)
            } catch (e: IllegalArgumentException) {
                throw ArmorException("invalid base64 in armor body: ${e.message}")
            }
            out.write(bytes)
        }

        while (true) {
            val raw = reader.readLine() ?: break
            val line = raw.trim()
            if (!sawBegin) {
                if (line.isEmpty()) continue
                if (line != BEGIN_MARKER) throw ArmorException("missing BEGIN marker")
                sawBegin = true
                continue
            }
            if (!sawEnd) {
                if (line == END_MARKER) { sawEnd = true; continue }
                if (line == BEGIN_MARKER) throw ArmorException("unexpected second BEGIN marker")
                if (line.isEmpty()) continue
                if (sawPadding) throw ArmorException("base64 padding before the end of the body")
                pending.append(line)
                if (pending.length >= FLUSH_AT) flush(all = false)
                continue
            }
            // After END, only blank lines are tolerated (decode() requires END to be the last line).
            if (line.isNotEmpty()) throw ArmorException("unexpected content after END marker")
        }

        if (!sawBegin) throw ArmorException("missing BEGIN marker")
        if (!sawEnd) throw ArmorException("missing END marker")
        flush(all = true)
    }

    // --- Internals ---

    /**
     * Read up to `buf.size` bytes, blocking through short reads until the buffer is full or the
     * stream ends. Returns the number of bytes read (0 at EOF).
     */
    private fun readFully(input: InputStream, buf: ByteArray): Int {
        var off = 0
        while (off < buf.size) {
            val r = input.read(buf, off, buf.size - off)
            if (r < 0) break
            off += r
        }
        return off
    }
}
