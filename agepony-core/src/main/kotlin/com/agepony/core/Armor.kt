package com.agepony.core

import java.io.ByteArrayOutputStream
import java.io.InputStream
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
 * Encode/decode is symmetric. Decode follows Go age's armor reader (audit L-1): every body line
 * but the last is exactly 64 columns, the last is shorter (or a full line directly followed by
 * the END marker), each line is strict padded base64 with zero trailing bits, CRLF is accepted,
 * and only whitespace may come before BEGIN or after END. On top of Go it still tolerates
 * whitespace around each line, which pasted text often picks up and which cannot change the
 * decoded bytes. Lines are length-capped while reading, so input with no newlines cannot
 * exhaust memory.
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
    private const val FLUSH_AT = 64 * 1024         // hand decoded bytes back in ~64 KiB batches

    /**
     * Longest raw line the streaming reader buffers before giving up. Go age rejects any body
     * line over 64 columns and more than 1 KiB of leading or trailing whitespace, so no input it
     * accepts has a line anywhere near this long.
     */
    private const val MAX_RAW_LINE = 4096

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
        val out = ByteArrayOutputStream()
        val parser = LineParser()
        for (line in armored.split('\n')) parser.line(line, out)
        parser.end()
        return out.toByteArray()
    }

    /**
     * The armor grammar, one line at a time, shared by [decode] and [DecodingSource] so both
     * accept exactly the same inputs. Mirrors filippo.io/age/armor's reader.
     */
    private class LineParser {
        private enum class State { BEFORE_BEGIN, BODY, NEED_END, AFTER_END }
        private var state = State.BEFORE_BEGIN

        /** Feed one line (without its '\n'); decoded bytes are appended to [out]. */
        fun line(raw: String, out: ByteArrayOutputStream) {
            val line = raw.trim()   // also drops the '\r' of a CRLF line ending
            when (state) {
                State.BEFORE_BEGIN -> {
                    if (line.isEmpty()) return
                    if (line != BEGIN_MARKER) throw ArmorException("missing BEGIN marker")
                    state = State.BODY
                }
                State.BODY -> {
                    if (line == END_MARKER) { state = State.AFTER_END; return }
                    if (line == BEGIN_MARKER) throw ArmorException("unexpected second BEGIN marker")
                    val bytes = decodeLine(line)
                    out.write(bytes)
                    // A short line ends the body; only the END marker may follow it.
                    if (bytes.size < GROUP) state = State.NEED_END
                }
                State.NEED_END -> {
                    if (line != END_MARKER) {
                        throw ArmorException("armor body continues after a short line (lines must be $LINE_WIDTH columns)")
                    }
                    state = State.AFTER_END
                }
                State.AFTER_END -> {
                    if (line.isNotEmpty()) throw ArmorException("unexpected content after END marker")
                }
            }
        }

        /** End of input. */
        fun end() {
            when (state) {
                State.BEFORE_BEGIN -> throw ArmorException("missing BEGIN marker")
                State.BODY, State.NEED_END -> throw ArmorException("missing END marker")
                State.AFTER_END -> Unit
            }
        }

        /**
         * Strict padded base64 for one line, like Go's `base64.StdEncoding.Strict()`: at most
         * 64 columns, padding required on a short final group, and zero trailing bits. A full
         * 48-byte line has no padding or spare bits, so only a short line needs the
         * re-encode comparison that catches non-canonical input.
         */
        private fun decodeLine(line: String): ByteArray {
            if (line.length > LINE_WIDTH) throw ArmorException("armor line exceeds $LINE_WIDTH columns")
            if (line.isEmpty()) return ByteArray(0)
            val bytes = try {
                Base64.getDecoder().decode(line)
            } catch (e: IllegalArgumentException) {
                throw ArmorException("invalid base64 in armor body: ${e.message}")
            }
            if (bytes.size < GROUP && Base64.getEncoder().encodeToString(bytes) != line) {
                throw ArmorException("non-canonical base64 in armor body")
            }
            return bytes
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
     * can be fed straight to a binary reader without being decoded whole first. Accepts exactly
     * what [decode] accepts, including CRLF, whitespace around lines and blank lines around the
     * markers. Each raw line is capped at [MAX_RAW_LINE] bytes while it is read (no unbounded
     * readLine), so a newline-free multi-gigabyte input fails fast instead of filling memory.
     * [close] leaves the wrapped stream open.
     */
    class DecodingSource(private val input: InputStream) : InputStream() {
        private val parser = LineParser()
        private val inBuf = ByteArray(8192)
        private var inPos = 0
        private var inLim = 0
        private var inEof = false
        private val lineBuf = ByteArray(MAX_RAW_LINE)
        private val decoded = ByteArrayOutputStream(FLUSH_AT + GROUP)
        private var buf = ByteArray(0)
        private var pos = 0
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
            decoded.reset()
            while (true) {
                val raw = readRawLine()
                if (raw == null) {
                    // Reading continues past END so trailing junk is still rejected.
                    parser.end()
                    done = true
                    return decoded.toByteArray()
                }
                parser.line(raw, decoded)
                if (decoded.size() >= FLUSH_AT) return decoded.toByteArray()
            }
        }

        /**
         * The next line without its '\n', or null at end of input. Bytes map one to one onto
         * chars (ISO-8859-1), so a non-ASCII byte survives to be rejected by the grammar.
         */
        private fun readRawLine(): String? {
            var n = 0
            var any = false
            while (true) {
                if (inPos >= inLim) {
                    if (inEof) break
                    val r = input.read(inBuf, 0, inBuf.size)
                    if (r < 0) { inEof = true; break }
                    inPos = 0
                    inLim = r
                    continue
                }
                val b = inBuf[inPos++]
                any = true
                if (b == NEWLINE.toByte()) return String(lineBuf, 0, n, Charsets.ISO_8859_1)
                if (n == lineBuf.size) throw ArmorException("armor line longer than $MAX_RAW_LINE bytes")
                lineBuf[n++] = b
            }
            return if (any) String(lineBuf, 0, n, Charsets.ISO_8859_1) else null
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
