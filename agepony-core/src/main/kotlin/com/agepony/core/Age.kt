package com.agepony.core

import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.LabeledAgeRecipient
import com.agepony.core.recipients.HardwareIdentity
import com.agepony.core.recipients.ScryptIdentity
import com.agepony.core.signing.SignatureStanza
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
    fun encrypt(
        plaintext: ByteArray,
        to: List<AgeRecipient>,
        extraStanzas: (fileKey: ByteArray) -> List<Stanza> = { emptyList() },
    ): ByteArray {
        require(to.isNotEmpty()) { "must have at least one recipient" }
        enforceRecipientLabels(to)
        val fileKey = ByteArray(FILE_KEY_SIZE).also { SecureRandom().nextBytes(it) }
        val stanzas = to.map { it.wrap(fileKey) } + extraStanzas(fileKey)

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
    /**
     * Plaintext plus the armored SSHSIG recovered from an `agepony.com/sig` stanza, when the file
     * carried one and it opened under the file key. [signatureArmored] is null for a file with no
     * signature stanza.
     */
    class DecryptedWithSignature(
        val plaintext: ByteArray,
        val signatureArmored: String?,
        /** The sig stanza as a three-way result with its version (audit L-8, L-9). */
        val signature: SignatureStanza.Opening = SignatureStanza.Opening.Absent,
    )

    fun decrypt(ciphertext: ByteArray, identities: List<AgeIdentity>): ByteArray =
        decryptAndRecoverSignature(ciphertext, identities).plaintext

    /**
     * Like [decrypt], but also recovers the AgePony signature stanza if one is present. An
     * unrecognized stanza is otherwise ignored, exactly as plain age ignores it, so this returns
     * the same bare plaintext either way.
     */
    fun decryptAndRecoverSignature(
        ciphertext: ByteArray,
        identities: List<AgeIdentity>,
    ): DecryptedWithSignature {
        require(identities.isNotEmpty()) { "must have at least one identity" }
        val parsed = AgeHeader.parse(ciphertext)
        requireScryptAlone(parsed.stanzas, identities)

        val fileKey = unwrapFileKey(parsed.stanzas, identities)

        AgeHeader.verifyMAC(parsed.macInputBytes, parsed.mac, fileKey)
        val payloadBytes = ciphertext.copyOfRange(parsed.payloadStart, ciphertext.size)
        val plaintext = AgePayload.decrypt(fileKey, payloadBytes)
        val opening = SignatureStanza.openHeader(fileKey, parsed.stanzas)
        val signature = (opening as? SignatureStanza.Opening.Opened)?.signatureArmored
        return DecryptedWithSignature(plaintext, signature, opening)
    }

    /**
     * Streaming encrypt: read plaintext from `plaintext`, write binary age ciphertext to `out`
     * in bounded memory. Equivalent to [encrypt] but for large inputs. Does not close streams.
     */
    fun encryptStream(plaintext: InputStream, to: List<AgeRecipient>, out: OutputStream) {
        require(to.isNotEmpty()) { "must have at least one recipient" }
        enforceRecipientLabels(to)
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
        requireScryptAlone(parsed.stanzas, identities)

        val fileKey = unwrapFileKey(parsed.stanzas, identities)

        AgeHeader.verifyMAC(parsed.macInputBytes, parsed.mac, fileKey)
        // `ciphertext` is now positioned exactly at the first payload byte.
        AgePayload.decryptStream(fileKey, ciphertext, out)
    }

    /**
     * Parse just the header of [ciphertext] and hand back its stanzas, leaving the stream
     * positioned at the first payload byte. Lets a reader show what a file is encrypted to
     * without decrypting it, and without holding more than the (bounded) header.
     */
    fun parseHeaderStream(ciphertext: InputStream): AgeHeader.ParsedHeader =
        AgeHeader.parse(readHeaderBytes(ciphertext))

    /**
     * True if any of [identities] can unwrap this file's header. Reads the header and stops
     * there, leaving `ciphertext` positioned at the first payload byte, so a caller can find out
     * which key a file needs without decrypting it. Throws the usual header exceptions for input
     * that is not age at all, including a header that mixes scrypt with other stanzas when a
     * passphrase identity is offered, which no decrypt would accept (audit L-2).
     */
    fun canDecryptStream(ciphertext: InputStream, identities: List<AgeIdentity>): Boolean {
        if (identities.isEmpty()) return false
        val parsed = AgeHeader.parse(readHeaderBytes(ciphertext))
        requireScryptAlone(parsed.stanzas, identities)
        for (stanza in parsed.stanzas) {
            for (id in identities) {
                // A hardware identity answers from its key tag, so probing a file never makes a
                // hardware key (or its user prompt) do an ECDH just to find out.
                val opens = if (id is HardwareIdentity) id.matches(stanza) else id.unwrap(stanza) != null
                if (opens) return true
            }
        }
        return false
    }

    // --- Internals ---

    /**
     * Go age: "an scrypt recipient must be the only one". Checked before any identity runs, so a
     * header that pairs a cheap stanza with a second scrypt stanza at a huge work factor never
     * reaches the KDF (audit L-2). The app's memory guard only reads the first scrypt stanza,
     * which is safe once this holds.
     *
     * Exactly as in Go, where the check lives in `ScryptIdentity.Unwrap`, it applies when a
     * passphrase identity is being tried: only that identity would run scrypt. Decrypting a
     * mixed file with, say, an X25519 key does no KDF work and Go age opens it, so this does too.
     */
    private fun requireScryptAlone(stanzas: List<Stanza>, identities: List<AgeIdentity>) {
        if (stanzas.size > 1 && stanzas.any { it.type == "scrypt" } && identities.any { it is ScryptIdentity }) {
            throw AgeHeader.HeaderException("an scrypt recipient must be the only one in the file")
        }
    }

    /**
     * A recovered file key must be exactly 16 bytes. The per-type body length checks catch this
     * earlier for the built-in recipients; this backstop covers ssh-rsa (whose OAEP body is the
     * modulus size) and any hardware or plugin identity (audit L-5).
     */
    private fun checkFileKey(key: ByteArray): ByteArray {
        if (key.size != FILE_KEY_SIZE) {
            throw AgeHeader.HeaderException("unwrapped file key is ${key.size} bytes, expected $FILE_KEY_SIZE")
        }
        return key
    }

    /**
     * Find the file key. Software identities go first across every stanza, so a file that also
     * has a software recipient never waits on (or fails because of) a hardware key. Tag
     * identities go last, and an error from one (a cancelled prompt, a key the OS invalidated) is
     * held back while the rest are tried; it only surfaces if nothing else opened the file.
     */
    private fun unwrapFileKey(stanzas: List<Stanza>, identities: List<AgeIdentity>): ByteArray {
        val (hardware, software) = identities.partition { it is HardwareIdentity }
        for (stanza in stanzas) {
            for (id in software) id.unwrap(stanza)?.let { return checkFileKey(it) }
        }
        var firstError: Exception? = null
        for (stanza in stanzas) {
            for (id in hardware) {
                val key = try {
                    id.unwrap(stanza)
                } catch (e: Exception) {
                    if (firstError == null) firstError = e
                    null
                }
                if (key != null) return checkFileKey(key)
            }
        }
        throw firstError ?: NoMatchingIdentityException()
    }

    /**
     * Enforce age's recipient-labels rule: every recipient must agree on the exact same set
     * of labels. Recipients that don't implement [LabeledAgeRecipient] have an empty label set.
     * This blocks mixing a post-quantum recipient (label "postquantum") with a classical one
     * that would defeat its quantum resistance.
     */
    private fun enforceRecipientLabels(to: List<AgeRecipient>) {
        val first = labelsOf(to.first())
        for (r in to) {
            if (labelsOf(r) != first) {
                throw IllegalArgumentException(
                    "recipients disagree on labels: all recipients must share the same labels " +
                        "(e.g. a post-quantum recipient cannot be combined with a non-post-quantum one)"
                )
            }
        }
    }

    private fun labelsOf(r: AgeRecipient): Set<String> =
        (r as? LabeledAgeRecipient)?.labels() ?: emptySet()

    /**
     * Read exactly the header bytes from `input`: everything up to and including the newline that
     * terminates the MAC line, leaving the stream positioned at the first payload byte. The header
     * is small and bounded, so buffering it fully is fine; only the payload must stream.
     *
     * The MAC line is the first line beginning with the marker "\n--- "; it ends at the next
     * newline. Base64 stanza bodies contain no dashes, so the marker is unambiguous.
     *
     * At most [AgeHeader.MAX_HEADER_SIZE] bytes are read (audit L-3): a stream with no MAC line
     * throws [AgeHeader.HeaderException] instead of being buffered without limit. Never reading
     * past the cap also keeps a caller's `mark(1 MiB)` valid.
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

            if (sawMacMarker && b == '\n'.code) return buf.toByteArray()
            if (buf.size() >= AgeHeader.MAX_HEADER_SIZE) {
                throw AgeHeader.HeaderException("header exceeds ${AgeHeader.MAX_HEADER_SIZE} bytes")
            }
            if (sawMacMarker) continue

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
