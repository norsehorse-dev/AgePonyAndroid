package com.agepony.core

import java.util.Base64

/**
 * An age recipient stanza. Wire format:
 * ```
 * -> type arg1 arg2 ...
 * <base64-body-line-1>
 * <base64-body-line-2>
 * ```
 * Body is unpadded standard base64 wrapped at 64 columns. When the encoded body
 * length is exactly a multiple of 64 (body byte length is a multiple of 48), an
 * additional empty line is appended as terminator.
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
        if (body.isEmpty()) return sb.toString()
        val b64 = base64NoPad(body)
        var i = 0
        while (i < b64.length) {
            val end = minOf(i + 64, b64.length)
            sb.append(b64, i, end).append('\n')
            i = end
        }
        // If the last body line was exactly 64 chars, append empty terminator line.
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

        /**
         * Standard base64 decoding (accepts both padded and unpadded input, since
         * the JDK decoder ignores missing padding when input length permits).
         */
        fun base64Decode(s: String): ByteArray = Base64.getDecoder().decode(s)

        /**
         * Parse a single stanza starting at `lines[fromIndex]`. Returns the stanza
         * and the index of the next unconsumed line.
         *
         * A stanza body ends when the next line starts with `-> ` (next stanza),
         * `--- ` (header MAC), or `---` alone, or we hit the end of input.
         */
        fun parseOne(lines: List<String>, fromIndex: Int): Pair<Stanza, Int> {
            if (fromIndex !in lines.indices) throw StanzaException("no line at index $fromIndex")
            val header = lines[fromIndex]
            if (!header.startsWith("-> ")) {
                throw StanzaException("stanza must start with '-> ', got: '$header'")
            }
            val parts = header.substring(3).split(' ').filter { it.isNotEmpty() }
            if (parts.isEmpty()) throw StanzaException("stanza needs a type")
            val type = parts[0]
            val args = parts.drop(1)

            // Collect body lines until next stanza or MAC marker.
            val bodyLines = mutableListOf<String>()
            var i = fromIndex + 1
            while (i < lines.size) {
                val line = lines[i]
                if (line.startsWith("-> ") || line.startsWith("--- ") || line == "---") break
                bodyLines.add(line)
                i++
            }

            // Validate body line lengths: all but the last must be exactly 64 chars,
            // OR an empty line as terminator (only valid for 64-aligned bodies).
            val nonEmpty = bodyLines.filter { it.isNotEmpty() }
            val b64 = nonEmpty.joinToString("")
            val body = if (b64.isEmpty()) ByteArray(0) else base64Decode(b64)
            return Stanza(type, args, body) to i
        }
    }
}
