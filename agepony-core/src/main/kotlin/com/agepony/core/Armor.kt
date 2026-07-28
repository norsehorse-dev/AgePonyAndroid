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
     * An [OutputStream] that armors whatever is written to it. The BEGIN marker goes out when the
     * sink is created; [finish] emits the trailing short group and the END marker. Bytes produced
     * are identical to [encode] for the same input.
     *
     * [close] finishes the armor but deliberately leaves the wrapped stream open, so a caller can
     * keep owning a SAF output stream.
     */
    class EncodingSink(private val out: OutputStream) : OutputStream() {
        private val encoder = Base64.getEncoder()
        private val group = ByteArray(GROUP)
        private var held = 0
        private var finished = false

        init {
            out.write(BEGIN_MARKER.toByteArray(Charsets.US_ASCII))
            out.write(NEWLINE)
        }

        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            check(!finished) { "armor sink is already finished" }
            var pos = off
            var left = len

            if (held > 0) {
                val take = minOf(GROUP - held, left)
                System.arraycopy(b, pos, group, held, take)
                held += take
                pos += take
                left -= take
                if (held == GROUP) {
                    emitLines(group, 0, GROUP)
                    held = 0
                }
            }

            val aligned = left - (left % GROUP)
            if (aligned > 0) {
                emitLines(b, pos, aligned)
                pos += aligned
                left -= aligned
            }
            if (left > 0) {
                System.arraycopy(b, pos, group, 0, left)
                held = left
            }
        }

        /** Emit the final partial group and the END marker. Idempotent. */
        fun finish() {
            if (finished) return
            finished = true
            if (held > 0) {
                // The only short group, and the only place base64 padding can appear.
                out.write(encoder.encode(group.copyOfRange(0, held)))
                out.write(NEWLINE)
                held = 0
            }
            out.write(END_MARKER.toByteArray(Charsets.US_ASCII))
            out.write(NEWLINE)
        }

        override fun flush() = out.flush()

        override fun close() = finish()

        /** [len] is a multiple of 48, so its base64 is a whole number of unpadded 64-char lines. */
        private fun emitLines(src: ByteArray, off: Int, len: Int) {
            var pos = off
            var left = len
            while (left > 0) {
                val take = minOf(left, READ_CHUNK)
                val enc = encoder.encode(src.copyOfRange(pos, pos + take))
                var i = 0
                while (i < enc.size) {
                    out.write(enc, i, LINE_WIDTH)
                    out.write(NEWLINE)
                    i += LINE_WIDTH
                }
                pos += take
                left -= take
            }
        }
    }

    /**
     * An [InputStream] that reads armored text and yields the decoded binary, so an armored file
     * can be fed straight to a binary reader without being decoded whole first. Accepts what
     * [decode] accepts, including CRLF, trailing whitespace and blank lines around the markers.
     * [close] leaves the wrapped stream open.
     */
    class DecodingSource(input: InputStream) : InputStream() {
        private val reader = BufferedReader(InputStreamReader(input, Charsets.US_ASCII))
        private val decoder = Base64.getDecoder()
        private val pending = StringBuilder(FLUSH_AT + LINE_WIDTH)
        private var buf = ByteArray(0)
        private var pos = 0
        private var sawBegin = false
        private var sawEnd = false
        private var sawPadding = false
        private var done = false

        override fun read(): Int {
            if (!fill()) return -1
            return buf[pos++].toInt() and 0xff
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (!fill()) return -1
            val take = minOf(len, buf.size - pos)
            System.arraycopy(buf, pos, b, off, take)
            pos += take
            return take
        }

        override fun available(): Int = buf.size - pos

        override fun close() { /* the wrapped stream stays the caller's */ }

        /** Refill [buf] when it runs out. False once the armored body is exhausted. */
        private fun fill(): Boolean {
            while (pos >= buf.size) {
                if (done) return false
                buf = nextChunk()
                pos = 0
            }
            return true
        }

        private fun nextChunk(): ByteArray {
            while (true) {
                val raw = reader.readLine()
                if (raw == null) {
                    if (!sawBegin) throw ArmorException("missing BEGIN marker")
                    if (!sawEnd) throw ArmorException("missing END marker")
                    done = true
                    return decodePending(all = true)
                }
                val line = raw.trim()

                if (!sawBegin) {
                    if (line.isEmpty()) continue
                    if (line != BEGIN_MARKER) throw ArmorException("missing BEGIN marker")
                    sawBegin = true
                    continue
                }

                if (!sawEnd) {
                    // Reading continues past END so trailing junk is still rejected, the way
                    // decode() rejects it by requiring END to be the last line.
                    if (line == END_MARKER) { sawEnd = true; continue }
                    if (line == BEGIN_MARKER) throw ArmorException("unexpected second BEGIN marker")
                    if (line.isEmpty()) continue
                    if (sawPadding) throw ArmorException("base64 padding before the end of the body")
                    pending.append(line)
                    if (pending.length >= FLUSH_AT) {
                        val chunk = decodePending(all = false)
                        if (chunk.isNotEmpty()) return chunk
                    }
                    continue
                }

                if (line.isNotEmpty()) throw ArmorException("unexpected content after END marker")
            }
        }

        private fun decodePending(all: Boolean): ByteArray {
            val take = if (all) pending.length else pending.length - (pending.length % 4)
            if (take == 0) return ByteArray(0)
            val chunk = pending.substring(0, take)
            pending.delete(0, take)
            if (chunk.indexOf('=') >= 0) sawPadding = true
            return try {
                decoder.decode(chunk)
            } catch (e: IllegalArgumentException) {
                throw ArmorException("invalid base64 in armor body: ${e.message}")
            }
        }
    }

    /** Wrap [out] so everything written to it comes out armored. Finish with [EncodingSink.finish]. */
    fun encodingSink(out: OutputStream): EncodingSink = EncodingSink(out)

    /** Wrap armored [armored] so it reads as the decoded binary. */
    fun decodingSource(armored: InputStream): DecodingSource = DecodingSource(armored)

    /**
     * Streaming encode: read binary from [binary], write armored text to [out] in bounded memory.
     * Output is byte for byte what [encode] would produce. Does not close either stream.
     */
    fun encodeStream(binary: InputStream, out: OutputStream) {
        val sink = EncodingSink(out)
        copy(binary, sink)
        sink.finish()
    }

    /**
     * Streaming decode: read armored text from [armored], write decoded binary to [out] in
     * bounded memory. Does not close either stream.
     */
    fun decodeStream(armored: InputStream, out: OutputStream) {
        copy(DecodingSource(armored), out)
    }

    // --- Internals ---

    private const val NEWLINE = '\n'.code

    private fun copy(input: InputStream, out: OutputStream) {
        val buf = ByteArray(READ_CHUNK)
        while (true) {
            val r = input.read(buf)
            if (r < 0) break
            out.write(buf, 0, r)
        }
    }
}
