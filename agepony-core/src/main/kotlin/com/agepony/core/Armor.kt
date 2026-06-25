package com.agepony.core

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
 */
object Armor {
    const val BEGIN_MARKER = "-----BEGIN AGE ENCRYPTED FILE-----"
    const val END_MARKER = "-----END AGE ENCRYPTED FILE-----"
    private const val LINE_WIDTH = 64

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
}
