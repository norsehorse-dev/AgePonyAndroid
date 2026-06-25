package com.agepony.core

import com.agepony.core.crypto.HKDF
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * age header serialization, parsing, and MAC computation.
 *
 * Wire format:
 * ```
 * age-encryption.org/v1
 * -> stanza1 ...
 * body1
 * -> stanza2 ...
 * body2
 * --- <base64-of-MAC>
 * <16-byte payload nonce, then ciphertext chunks>
 * ```
 *
 * MAC = HMAC-SHA256(macKey, headerBytes) where
 *   macKey = HKDF-SHA256(ikm=fileKey, salt=empty, info="header", L=32)
 *   headerBytes = all bytes from the version line through and including the literal `---`
 *                 (NOT including the space after, or the MAC itself).
 */
object AgeHeader {
    const val VERSION_LINE = "age-encryption.org/v1"
    private const val HEADER_INFO = "header"

    class HeaderException(message: String) : Exception(message)

    data class ParsedHeader(
        val stanzas: List<Stanza>,
        val macInputBytes: ByteArray,
        val mac: ByteArray,
        val payloadStart: Int,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ParsedHeader) return false
            return stanzas == other.stanzas
                && macInputBytes.contentEquals(other.macInputBytes)
                && mac.contentEquals(other.mac)
                && payloadStart == other.payloadStart
        }
        override fun hashCode(): Int {
            var h = stanzas.hashCode()
            h = 31 * h + macInputBytes.contentHashCode()
            h = 31 * h + mac.contentHashCode()
            h = 31 * h + payloadStart
            return h
        }
    }

    /**
     * Serialize header (version line + stanzas + MAC) and return the full byte sequence
     * including the trailing newline after the MAC. Append payload bytes after this.
     */
    fun serialize(stanzas: List<Stanza>, fileKey: ByteArray): ByteArray {
        val sb = StringBuilder()
        sb.append(VERSION_LINE).append('\n')
        for (s in stanzas) sb.append(s.serialize())
        sb.append("---")
        val macInputBytes = sb.toString().toByteArray(Charsets.UTF_8)
        val macKey = HKDF.derive(fileKey, ByteArray(0), HEADER_INFO.toByteArray(), 32)
        val mac = hmacSHA256(macKey, macInputBytes)
        sb.append(' ').append(Stanza.base64NoPad(mac)).append('\n')
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Parse the header from the start of `data`. Returns stanzas, the MAC input bytes
     * (for verification), the parsed MAC, and the index in `data` where the payload begins.
     */
    fun parse(data: ByteArray): ParsedHeader {
        // Find the "---<space>" marker, prefixed by a newline.
        val needle = "\n--- ".toByteArray()
        var idx = -1
        var i = 0
        outer@ while (i <= data.size - needle.size) {
            for (j in needle.indices) {
                if (data[i + j] != needle[j]) { i++; continue@outer }
            }
            idx = i
            break
        }
        if (idx < 0) throw HeaderException("missing '--- ' line in header")

        // MAC input = bytes from start through and including the 3 dashes.
        // data[idx]    = '\n'
        // data[idx+1..idx+3] = '---'
        // data[idx+4]  = ' '
        val macInputBytes = data.copyOfRange(0, idx + 4)

        // Find newline after the MAC value.
        var nlPos = idx + 5
        while (nlPos < data.size && data[nlPos] != '\n'.code.toByte()) nlPos++
        if (nlPos >= data.size) throw HeaderException("missing newline after MAC")

        val macB64 = String(data, idx + 5, nlPos - (idx + 5), Charsets.US_ASCII)
        val mac = Stanza.base64Decode(macB64)
        val payloadStart = nlPos + 1

        // Split macInputBytes into lines (no terminating newline after '---').
        val headerText = String(macInputBytes, Charsets.UTF_8)
        val lines = headerText.split('\n')
        if (lines.isEmpty() || lines[0] != VERSION_LINE) {
            throw HeaderException("missing or wrong version line: got '${lines.getOrNull(0)}'")
        }

        val stanzas = mutableListOf<Stanza>()
        var li = 1
        while (li < lines.size && lines[li] != "---") {
            if (lines[li].startsWith("-> ")) {
                val (stanza, nextIdx) = Stanza.parseOne(lines, li)
                stanzas.add(stanza)
                li = nextIdx
            } else if (lines[li].isEmpty()) {
                li++   // empty line — terminator after a 64-aligned stanza body
            } else {
                throw HeaderException("unexpected header line: '${lines[li]}'")
            }
        }
        return ParsedHeader(stanzas, macInputBytes, mac, payloadStart)
    }

    /**
     * Verify a MAC produced by this header against the provided fileKey. Throws if mismatch.
     * Uses constant-time comparison.
     */
    fun verifyMAC(macInputBytes: ByteArray, mac: ByteArray, fileKey: ByteArray) {
        val macKey = HKDF.derive(fileKey, ByteArray(0), HEADER_INFO.toByteArray(), 32)
        val computed = hmacSHA256(macKey, macInputBytes)
        if (!constantTimeEquals(computed, mac)) throw HeaderException("MAC verification failed")
    }

    // --- Internals ---

    private fun hmacSHA256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}
