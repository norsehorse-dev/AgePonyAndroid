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

    /**
     * Largest header accepted, MAC line included: 1 MiB, the same cap as iOS (audit L-3). A
     * real header is a few hundred bytes per recipient; without a cap a file with no `---`
     * line would be buffered until the process runs out of memory.
     */
    const val MAX_HEADER_SIZE = 1024 * 1024

    /** The MAC is 32 bytes, so its unpadded base64 is always exactly 43 characters. */
    private const val MAC_B64_LEN = 43

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
     *
     * Strict, matching filippo.io/age `format.Parse` (audit L-1): the header is US-ASCII, the
     * version line is exact, stanzas follow each other with no stray lines in between (see
     * [Stanza.parseOne] for the body rules), and the closing line is exactly `--- ` plus 43
     * characters of canonical unpadded base64. Anything else is a [HeaderException], so a
     * header has exactly one accepted encoding and cannot be altered without the file key.
     */
    fun parse(data: ByteArray): ParsedHeader {
        // Find the "---<space>" marker, prefixed by a newline. A stanza line starts with "->"
        // and a body line holds only base64, so the first such marker is the MAC line.
        val needle = "\n--- ".toByteArray()
        val searchEnd = minOf(data.size, MAX_HEADER_SIZE) - needle.size
        var idx = -1
        var i = 0
        outer@ while (i <= searchEnd) {
            for (j in needle.indices) {
                if (data[i + j] != needle[j]) { i++; continue@outer }
            }
            idx = i
            break
        }
        if (idx < 0) {
            if (data.size >= MAX_HEADER_SIZE) throw HeaderException("header exceeds $MAX_HEADER_SIZE bytes")
            throw HeaderException("missing '--- ' line in header")
        }

        // MAC input = bytes from start through and including the 3 dashes.
        // data[idx]    = '\n'
        // data[idx+1..idx+3] = '---'
        // data[idx+4]  = ' '
        val macInputBytes = data.copyOfRange(0, idx + 4)

        // The MAC line is exactly 43 base64 characters, then '\n'.
        val macStart = idx + 5
        val nlPos = macStart + MAC_B64_LEN
        if (nlPos > MAX_HEADER_SIZE - 1) throw HeaderException("header exceeds $MAX_HEADER_SIZE bytes")
        if (nlPos >= data.size) throw HeaderException("truncated MAC line")
        if (data[nlPos] != '\n'.code.toByte()) throw HeaderException("malformed MAC line")
        for (k in macStart until nlPos) {
            if (data[k].toInt() and 0x80 != 0) throw HeaderException("malformed MAC line")
        }
        val macB64 = String(data, macStart, MAC_B64_LEN, Charsets.US_ASCII)
        val mac = try {
            Stanza.base64Decode(macB64)
        } catch (e: IllegalArgumentException) {
            throw HeaderException("malformed MAC line: ${e.message}")
        }
        if (mac.size != 32) throw HeaderException("malformed MAC line: MAC must be 32 bytes")
        val payloadStart = nlPos + 1

        // The header is US-ASCII only; any high byte is malformed rather than something to
        // reinterpret through a charset.
        for (b in macInputBytes) {
            if (b.toInt() and 0x80 != 0) throw HeaderException("header is not US-ASCII")
        }

        // Split macInputBytes into lines (no terminating newline after '---').
        val headerText = String(macInputBytes, Charsets.US_ASCII)
        val lines = headerText.split('\n')
        if (lines.isEmpty() || lines[0] != VERSION_LINE) {
            throw HeaderException("missing or wrong version line: got '${lines.getOrNull(0)}'")
        }

        val stanzas = mutableListOf<Stanza>()
        val last = lines.size - 1   // lines[last] is the "---" that precedes the MAC
        var li = 1
        while (li < last) {
            if (!lines[li].startsWith("-> ")) {
                // Go age accepts no blank or stray lines between stanzas.
                throw HeaderException("unexpected header line: '${lines[li]}'")
            }
            val (stanza, nextIdx) = try {
                Stanza.parseOne(lines, li)
            } catch (e: Stanza.Companion.StanzaException) {
                throw HeaderException("malformed stanza: ${e.message}")
            }
            if (nextIdx > last) throw HeaderException("stanza ran into the MAC line")
            stanzas.add(stanza)
            li = nextIdx
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
