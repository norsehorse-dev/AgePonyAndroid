package com.agepony.core

import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.AgeRecipient
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom

/**
 * Top-level age encryption and decryption.
 *
 * `encrypt` produces binary age-encryption.org/v1 output. Use `Armor.encode` separately
 * if you want ASCII armor.
 *
 * `encryptStream` / `decryptStream` are the bounded-memory equivalents for large files: the
 * (small) header is buffered, while the payload is streamed one 64 KiB chunk at a time. Output
 * is byte-identical to the whole-buffer methods for the same inputs.
 */
object Age {
    private const val FILE_KEY_SIZE = 16

    // Marker that begins the header MAC line: newline, three dashes, space.
    private val MAC_MARKER = "\n--- ".toByteArray(Charsets.US_ASCII)

    class NoMatchingIdentityException : Exception(
        "no identity could decrypt any stanza in the header"
    )

    /**
     * Encrypt `plaintext` to one or more recipients. Returns binary ciphertext.
     *
     * Note: per the age spec, a scrypt recipient must be the only recipient in the file.
     * This method enforces that constraint by checking the stanza types after wrapping.
     */
    fun encrypt(plaintext: ByteArray, to: List<AgeRecipient>): ByteArray {
        require(to.isNotEmpty()) { "must have at least one recipient" }
        val fileKey = ByteArray(FILE_KEY_SIZE).also { SecureRandom().nextBytes(it) }
        val stanzas = to.map { it.wrap(fileKey) }

        val scryptCount = stanzas.count { it.type == "scrypt" }
        if (scryptCount > 0 && stanzas.size > 1) {
            throw IllegalArgumentException(
                "scrypt recipient must be the only recipient (age spec)"
            )
        }

        val header = AgeHeader.serialize(stanzas, fileKey)
        val payload = AgePayload.encrypt(fileKey, plaintext)
        return header + payload
    }

    /**
     * Decrypt `ciphertext` with one or more identities. Tries each identity against each
     * stanza in turn; the first successful unwrap unlocks the file. Throws
     * `NoMatchingIdentityException` if no identity matched any stanza.
     */
    fun decrypt(ciphertext: ByteArray, identities: List<AgeIdentity>): ByteArray {
        require(identities.isNotEmpty()) { "must have at least one identity" }
        val parsed = AgeHeader.parse(ciphertext)

        var fileKey: ByteArray? = null
        outer@ for (stanza in parsed.stanzas) {
            for (id in identities) {
                val k = id.unwrap(stanza)
                if (k != null) { fileKey = k; break@outer }
            }
        }
        if (fileKey == null) throw NoMatchingIdentityException()

        AgeHeader.verifyMAC(parsed.macInputBytes, parsed.mac, fileKey)
        val payloadBytes = ciphertext.copyOfRange(parsed.payloadStart, ciphertext.size)
        return AgePayload.decrypt(fileKey, payloadBytes)
    }

    /**
     * Streaming encrypt: read plaintext from `plaintext`, write binary age ciphertext to `out`
     * in bounded memory. Equivalent to [encrypt] but for large inputs. Does not close streams.
     */
    fun encryptStream(plaintext: InputStream, to: List<AgeRecipient>, out: OutputStream) {
        require(to.isNotEmpty()) { "must have at least one recipient" }
        val fileKey = ByteArray(FILE_KEY_SIZE).also { SecureRandom().nextBytes(it) }
        val stanzas = to.map { it.wrap(fileKey) }

        val scryptCount = stanzas.count { it.type == "scrypt" }
        if (scryptCount > 0 && stanzas.size > 1) {
            throw IllegalArgumentException(
                "scrypt recipient must be the only recipient (age spec)"
            )
        }

        val header = AgeHeader.serialize(stanzas, fileKey)
        out.write(header)
        AgePayload.encryptStream(fileKey, plaintext, out)
    }

    /**
     * Streaming decrypt: read binary age ciphertext from `ciphertext`, write plaintext to `out`
     * in bounded memory. The (small) header is buffered and parsed; the payload is then streamed
     * chunk by chunk. Throws `NoMatchingIdentityException` if no identity matched any stanza, or a
     * header/payload exception on malformed or tampered input. Does not close streams.
     */
    fun decryptStream(ciphertext: InputStream, identities: List<AgeIdentity>, out: OutputStream) {
        require(identities.isNotEmpty()) { "must have at least one identity" }

        val headerBytes = readHeaderBytes(ciphertext)
        val parsed = AgeHeader.parse(headerBytes)

        var fileKey: ByteArray? = null
        outer@ for (stanza in parsed.stanzas) {
            for (id in identities) {
                val k = id.unwrap(stanza)
                if (k != null) { fileKey = k; break@outer }
            }
        }
        if (fileKey == null) throw NoMatchingIdentityException()

        AgeHeader.verifyMAC(parsed.macInputBytes, parsed.mac, fileKey)
        // `ciphertext` is now positioned exactly at the first payload byte.
        AgePayload.decryptStream(fileKey, ciphertext, out)
    }

    // --- Internals ---

    /**
     * Read exactly the header bytes from `input`: everything up to and including the newline that
     * terminates the MAC line, leaving the stream positioned at the first payload byte. The header
     * is small and bounded, so buffering it fully is fine; only the payload must stream.
     *
     * The MAC line is the first line beginning with the marker "\n--- "; it ends at the next
     * newline. Base64 stanza bodies contain no dashes, so the marker is unambiguous.
     */
    private fun readHeaderBytes(input: InputStream): ByteArray {
        val buf = ByteArrayOutputStream()
        val window = ByteArray(MAC_MARKER.size)
        var windowLen = 0
        var sawMacMarker = false

        while (true) {
            val b = input.read()
            if (b < 0) throw AgeHeader.HeaderException("unexpected EOF while reading header")
            buf.write(b)

            if (sawMacMarker) {
                if (b == '\n'.code) return buf.toByteArray()
                continue
            }

            // Maintain a sliding window of the last MAC_MARKER.size bytes.
            if (windowLen < window.size) {
                window[windowLen++] = b.toByte()
            } else {
                for (i in 0 until window.size - 1) window[i] = window[i + 1]
                window[window.size - 1] = b.toByte()
            }
            if (windowLen == window.size && window.contentEquals(MAC_MARKER)) {
                sawMacMarker = true
            }
        }
    }
}
