package com.agepony.core

import java.util.Base64

/**
 * An age recipient stanza. Wire format:
 * ```
 * -> type arg1 arg2 ...
 * <base64-body-line-1>
 * <base64-body-line-2>
 * ```
 * Body is unpadded standard base64 wrapped at 64 columns. The last body line is always
 * shorter than 64 columns: when the encoded body length is exactly a multiple of 64 (body
 * byte length is a multiple of 48, including an empty body), an additional empty line is
 * appended as terminator. This matches filippo.io/age `Stanza.Marshal`.
 */
class Stanza(
    val type: String,
    val args: List<String>,
    val body: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Stanza) return false
        return type == other.type && args == other.args && body.contentEquals(other.body)
    }

    override fun hashCode(): Int {
        var h = type.hashCode()
        h = 31 * h + args.hashCode()
        h = 31 * h + body.contentHashCode()
        return h
    }

    override fun toString(): String = "Stanza(type=$type, args=$args, body[${body.size}B])"

    /**
     * Serialize this stanza to its text form, ending with a newline.
     * Concatenating multiple stanzas' `serialize()` outputs yields a valid stanza sequence.
     */
    fun serialize(): String {
        val sb = StringBuilder()
        sb.append("-> ").append(type)
        for (a in args) sb.append(' ').append(a)
        sb.append('\n')
        // An empty body is one empty line, exactly as Go age writes it (the loop below adds
        // nothing and the terminator check appends the empty line).
        val b64 = base64NoPad(body)
        var i = 0
        while (i < b64.length) {
            val end = minOf(i + 64, b64.length)
            sb.append(b64, i, end).append('\n')
            i = end
        }
        // If the last body line was exactly 64 chars (or the body is empty), append the empty
        // terminator line, so the body always ends with a short line.
        if (b64.length % 64 == 0) sb.append('\n')
        return sb.toString()
    }

    companion object {
        class StanzaException(message: String) : Exception(message)

        /**
         * Standard unpadded base64 encoding.
         */
        fun base64NoPad(bytes: ByteArray): String =
            Base64.getEncoder().withoutPadding().encodeToString(bytes)

        /** Decoded bytes per full 64-column body line. */
        const val BYTES_PER_LINE = 48
        const val COLUMNS_PER_LINE = 64

        /**
         * Strict, canonical unpadded standard base64, as Go age's
         * `base64.RawStdEncoding.Strict()`: no `=` padding, no whitespace or newlines, and the
         * unused trailing bits must be zero. The JDK decoder accepts padding and ignores
         * non-zero trailing bits, so the result is re-encoded and compared; anything that does
         * not round-trip is rejected (audit L-1). Throws [IllegalArgumentException].
         */
        fun base64Decode(s: String): ByteArray {
            if (s.isEmpty()) return ByteArray(0)
            if (s.indexOf('=') >= 0) throw IllegalArgumentException("base64 padding is not allowed")
            val decoded = Base64.getDecoder().decode(s)
            if (base64NoPad(decoded) != s) throw IllegalArgumentException("non-canonical base64")
            return decoded
        }

        /** True if [s] is a valid stanza argument: non-empty, every char VCHAR (33..126). */
        fun isValidArg(s: String): Boolean = s.isNotEmpty() && s.all { it.code in 33..126 }

        /**
         * Parse a single stanza starting at `lines[fromIndex]`. Returns the stanza
         * and the index of the next unconsumed line.
         *
         * Matches filippo.io/age `ReadStanza` exactly (audit L-1): the opening line is `->`
         * followed by one or more single-space-separated arguments, each VCHAR only; then
         * body lines, each strict base64. A line that decodes to 48 bytes (64 columns) is a
         * full line and the body continues; the first shorter line (0..63 columns, possibly
         * empty) ends it. The terminating short line is consumed, so an empty terminator
         * never reaches the caller. A body that runs into `-> `, `---` or the end of input
         * without a short line is rejected, as is any line longer than 64 columns.
         */
        fun parseOne(lines: List<String>, fromIndex: Int): Pair<Stanza, Int> {
            if (fromIndex !in lines.indices) throw StanzaException("no line at index $fromIndex")
            val header = lines[fromIndex]
            if (!header.startsWith("-> ")) {
                throw StanzaException("stanza must start with '-> ', got: '$header'")
            }
            // Split on every single space, like Go's strings.Split: a doubled or trailing
            // space yields an empty argument, which isValidArg rejects.
            val parts = header.substring(3).split(' ')
            if (parts.isEmpty() || parts[0].isEmpty()) throw StanzaException("stanza needs a type")
            for (p in parts) {
                if (!isValidArg(p)) throw StanzaException("malformed stanza line: '$header'")
            }
            val type = parts[0]
            val args = parts.drop(1)

            val body = java.io.ByteArrayOutputStream()
            var i = fromIndex + 1
            while (true) {
                if (i >= lines.size) throw StanzaException("stanza '$type' ended without a short body line")
                val line = lines[i]
                if (line.length > COLUMNS_PER_LINE) {
                    throw StanzaException("stanza '$type' body line too long (${line.length} columns)")
                }
                val decoded = try {
                    base64Decode(line)
                } catch (e: IllegalArgumentException) {
                    if (line.startsWith("->") || line.startsWith("---")) {
                        throw StanzaException("stanza '$type' ended without a short body line")
                    }
                    throw StanzaException("stanza '$type' has a malformed body line: ${e.message}")
                }
                body.write(decoded)
                i++
                if (decoded.size < BYTES_PER_LINE) break
            }
            return Stanza(type, args, body.toByteArray()) to i
        }
    }
}
