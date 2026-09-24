package com.agepony.core.signing

import com.agepony.core.Stanza
import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.HKDF
import com.agepony.core.ssh.SSHWire
import org.bouncycastle.crypto.digests.SHA512Digest
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * AgePony's signature stanza, "agepony.com/sig" (v1, and v2 from 5.0.1).
 *
 * A signed-and-encrypted file carries its SSHSIG in an extra age header stanza rather than in a
 * wrapper around the payload (the older approach is [com.agepony.core.archive.SignedBundle]). The
 * signature is encrypted under a key derived from the file key, so:
 *
 *   - plain age ignores the unrecognized stanza and hands back the bare payload (no wrapper
 *     surprise, which is what confused a YubiKey tester on issue #10),
 *   - only a recipient who can unwrap the file key can read or verify the signature, so the
 *     signer's identity stays out of the cleartext header,
 *   - the age header MAC already covers every stanza, so the signature cannot be swapped for
 *     another without AgePony's decrypt noticing.
 *
 * The age spec requires an scrypt stanza to be the only stanza in a header, so this is used only
 * for public-key recipients. Passphrase (scrypt) files keep the [com.agepony.core.archive.SignedBundle]
 * wrapper.
 *
 * Body layout (both versions): a 12-byte random nonce, then ChaCha20-Poly1305(key, nonce) over the
 * armored SSHSIG, no associated data. key = HKDF-SHA256(ikm = fileKey, salt = empty,
 * info = "agepony.com/sig-v1" or "agepony.com/sig-v2", L = 32). The info labels are distinct from
 * age's own "header" and "payload" labels and from each other, so this key never collides with
 * the header-MAC key, the payload-stream key, or the other version's key. Each file key seals
 * exactly one stanza, so a random nonce is safe.
 *
 * What the SSHSIG covers:
 *
 *  - v1 (`-> agepony.com/sig v1`): SSHSIG over the plaintext itself, namespace "agepony". It does
 *    not cover the recipients, so a recipient could re-wrap the file key (or re-encrypt the
 *    plaintext) to someone else and the signature would still check (audit L-8). Still read and
 *    verified exactly as in 5.0.0.
 *
 *  - v2 (`-> agepony.com/sig v2`, exactly one argument): SSHSIG over the message [v2Message] under
 *    namespace [NAMESPACE_V2]. All integers are big-endian, and `string` is SSH wire framing
 *    (uint32 length, then the bytes):
 *
 *    ```
 *    M = string  "agepony.com/sig v2"           (MESSAGE_DOMAIN_V2, ASCII, 18 bytes)
 *        string  SHA-512(plaintext)              (64 bytes)
 *        string  SHA-512(R)                      (64 bytes, see below)
 *        string  original file name, UTF-8       (always empty for this stanza: an age file has no name)
 *
 *    R = uint32  n                                (number of stanzas that follow)
 *        n times, in header order, every stanza whose type is not "agepony.com/sig":
 *          string  type                           (ASCII)
 *          uint32  argc
 *          argc times: string arg                 (ASCII)
 *          string  body                           (the raw decoded body bytes, not base64)
 *    ```
 *
 *    The SSHSIG is the ordinary PROTOCOL.sshsig construction over M (so its signed-data holds
 *    H(M) with the envelope's hash algorithm, sha512 by default). Because R holds each
 *    recipient's wrapped file key, a recipient who re-wraps the file key to new recipients, or
 *    re-encrypts the plaintext under a new file key, changes R and the signature fails. The
 *    distinct namespace stops a v2 signature being passed off as a v1 one (or as a detached
 *    "agepony" signature) and the reverse.
 *
 * Mirrored by the iOS app; docs/SIGNATURE_FORMATS_v2.md carries the same layout.
 */
object SignatureStanza {
    const val TYPE = "agepony.com/sig"

    /** The v1 version argument. Kept under its original name for existing callers. */
    const val VERSION = "v1"
    const val VERSION_V2 = "v2"

    /** SSHSIG namespace of a v2 signature stanza. Detached signatures keep "agepony". */
    const val NAMESPACE_V2 = "agepony-sig-v2"

    /** First field of the v2 signed message. */
    const val MESSAGE_DOMAIN_V2 = "agepony.com/sig v2"

    private const val KEY_INFO = "agepony.com/sig-v1"
    private const val KEY_INFO_V2 = "agepony.com/sig-v2"
    private const val KEY_LEN = 32
    private const val NONCE_LEN = 12
    private const val TAG_LEN = 16
    private val EMPTY_SALT = ByteArray(0)

    /**
     * Build a v1 stanza carrying [signatureArmored] (an armored SSHSIG over the plaintext, namespace
     * "agepony"), sealed under [fileKey]. New files should use [buildV2] through [SignedEncryption].
     */
    fun build(fileKey: ByteArray, signatureArmored: String): Stanza =
        seal(fileKey, KEY_INFO, VERSION, signatureArmored)

    /**
     * Build a v2 stanza carrying [signatureArmored], an armored SSHSIG over [v2Message] under
     * [NAMESPACE_V2]. [SignedEncryption] is the usual way in, since the message needs the
     * recipient stanzas that only exist once the file key is wrapped.
     */
    fun buildV2(fileKey: ByteArray, signatureArmored: String): Stanza =
        seal(fileKey, KEY_INFO_V2, VERSION_V2, signatureArmored)

    /** The signature stanza among [stanzas], or null if there is none. */
    fun find(stanzas: List<Stanza>): Stanza? = stanzas.firstOrNull { it.type == TYPE }

    /**
     * Recover the armored SSHSIG from [stanza] using [fileKey], or null if it is not a signature
     * stanza, is malformed, or does not authenticate under the derived key.
     *
     * Kept for existing callers. It opens v1 and v2 alike but cannot say which, nor tell "absent"
     * from "unreadable" (audit L-9), so a v2 signature checked the v1 way fails as invalid
     * (namespace mismatch) rather than passing. New code uses [openHeader].
     */
    fun open(fileKey: ByteArray, stanza: Stanza): String? =
        (openOne(fileKey, stanza) { ByteArray(0) } as? Opening.Opened)?.signatureArmored

    /**
     * What a header's signature stanza holds (audit L-9): [Opening.Absent] when there is none,
     * [Opening.Unreadable] when one is present but cannot be read (unknown version, short body,
     * AEAD failure, more than one), and [Opening.Opened] otherwise. [stanzas] is the whole parsed
     * header, which v2 needs to rebuild what was signed. The age header MAC must already have been
     * checked under [fileKey].
     */
    fun openHeader(fileKey: ByteArray, stanzas: List<Stanza>): Opening {
        val sigs = stanzas.filter { it.type == TYPE }
        if (sigs.isEmpty()) return Opening.Absent
        if (sigs.size > 1) return Opening.Unreadable("the header has more than one signature stanza")
        return openOne(fileKey, sigs[0]) { recipientsDigest(stanzas) }
    }

    /** Three-way result of [openHeader]. */
    sealed class Opening {
        /** No signature stanza: the file is simply unsigned. */
        object Absent : Opening()

        /** A signature stanza is present but could not be read. Show it as a failed signature, never as unsigned. */
        class Unreadable(val reason: String) : Opening()

        /**
         * The stanza opened. [version] is 1 or 2. Verify with [verify], or pass [namespace] and
         * [signedMessage] (or [messageHash] when streaming) to a verifier of your own.
         */
        class Opened internal constructor(
            val signatureArmored: String,
            val version: Int,
            private val recipientsDigest: ByteArray,
        ) : Opening() {
            /** SSHSIG namespace this version signs under. */
            val namespace: String get() = if (version >= 2) NAMESPACE_V2 else SSHSig.NAMESPACE_AGEPONY

            /**
             * True for v2: the signature also covers this file's recipient stanzas. A v1 signature
             * covers only the plaintext, which the UI should say.
             */
            val coversRecipients: Boolean get() = version >= 2

            /** The exact message the SSHSIG covers, given the decrypted [plaintext]. */
            fun signedMessage(plaintext: ByteArray): ByteArray =
                if (version >= 2) v2MessageFromDigest(sha512(plaintext), recipientsDigest, "") else plaintext

            /**
             * H(signed message) under the SSHSIG hash algorithm [alg], for a streaming verify.
             * [plaintextHash] returns the plaintext's hash under an algorithm name ("sha512",
             * "sha256"); v2 only ever asks it for "sha512".
             */
            fun messageHash(alg: String, plaintextHash: (String) -> ByteArray): ByteArray =
                if (version >= 2) {
                    SSHSig.hashMessage(v2MessageFromDigest(plaintextHash(SSHSig.HASH_SHA512), recipientsDigest, ""), alg)
                } else {
                    plaintextHash(alg)
                }

            /** Verify the signature over [plaintext] under this version's namespace and message. */
            fun verify(plaintext: ByteArray, allowNoTouch: Boolean = false): SSHSigVerifier.Result =
                SSHSigVerifier.verify(
                    signatureArmored.toByteArray(Charsets.UTF_8),
                    signedMessage(plaintext),
                    namespace,
                    allowNoTouch,
                )
        }
    }

    // --- v2 message ---

    /**
     * The v2 signed message M for a plaintext whose SHA-512 is [plaintextSha512], encrypted to
     * [headerStanzas] (the sig stanza, if present, is skipped). [originalName] is empty for the
     * sig stanza; the field exists so the layout matches [com.agepony.core.archive.SignedBundle]'s
     * intent and can carry a name if a later format has one.
     */
    fun v2Message(plaintextSha512: ByteArray, headerStanzas: List<Stanza>, originalName: String = ""): ByteArray =
        v2MessageFromDigest(plaintextSha512, recipientsDigest(headerStanzas), originalName)

    /** SHA-512(R) over every non-signature stanza of [headerStanzas], in order. See the class KDoc. */
    fun recipientsDigest(headerStanzas: List<Stanza>): ByteArray {
        val kept = headerStanzas.filter { it.type != TYPE }
        val out = ByteArrayOutputStream()
        SSHSig.writeUInt32(out, kept.size)
        for (s in kept) {
            SSHWire.writeString(out, s.type.toByteArray(Charsets.US_ASCII))
            SSHSig.writeUInt32(out, s.args.size)
            for (a in s.args) SSHWire.writeString(out, a.toByteArray(Charsets.US_ASCII))
            SSHWire.writeString(out, s.body)
        }
        return sha512(out.toByteArray())
    }

    private fun v2MessageFromDigest(plaintextSha512: ByteArray, recipientsDigest: ByteArray, originalName: String): ByteArray {
        require(plaintextSha512.size == 64) { "plaintext hash must be SHA-512 (64 bytes)" }
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, MESSAGE_DOMAIN_V2.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, plaintextSha512)
        SSHWire.writeString(out, recipientsDigest)
        SSHWire.writeString(out, originalName.toByteArray(Charsets.UTF_8))
        return out.toByteArray()
    }

    // --- Internals ---

    private fun seal(fileKey: ByteArray, info: String, version: String, signatureArmored: String): Stanza {
        val key = HKDF.derive(fileKey, EMPTY_SALT, info.toByteArray(Charsets.UTF_8), KEY_LEN)
        val nonce = ByteArray(NONCE_LEN).also { SecureRandom().nextBytes(it) }
        val sealed = ChaChaPoly.encrypt(key, nonce, signatureArmored.toByteArray(Charsets.UTF_8))
        return Stanza(TYPE, listOf(version), nonce + sealed)
    }

    private fun openOne(fileKey: ByteArray, stanza: Stanza, recipientsDigest: () -> ByteArray): Opening {
        if (stanza.type != TYPE) return Opening.Absent
        val (version, info) = when (stanza.args.firstOrNull()) {
            // v1 readers never looked past the first argument; keep that.
            VERSION -> 1 to KEY_INFO
            VERSION_V2 -> {
                if (stanza.args.size != 1) return Opening.Unreadable("v2 signature stanza has unexpected arguments")
                2 to KEY_INFO_V2
            }
            null -> return Opening.Unreadable("signature stanza has no version")
            else -> return Opening.Unreadable("unsupported signature stanza version '${stanza.args.first()}'")
        }
        if (stanza.body.size < NONCE_LEN + TAG_LEN) return Opening.Unreadable("signature stanza body is too short")
        val nonce = stanza.body.copyOfRange(0, NONCE_LEN)
        val sealed = stanza.body.copyOfRange(NONCE_LEN, stanza.body.size)
        val key = HKDF.derive(fileKey, EMPTY_SALT, info.toByteArray(Charsets.UTF_8), KEY_LEN)
        val plain = try {
            ChaChaPoly.decrypt(key, nonce, sealed)
        } catch (_: Exception) {
            return Opening.Unreadable("signature stanza does not open under this file's key")
        }
        if (plain.size > SSHSigVerifier.MAX_SIGNATURE_BYTES) return Opening.Unreadable("signature stanza is too large")
        return Opening.Opened(String(plain, Charsets.UTF_8), version, if (version >= 2) recipientsDigest() else ByteArray(0))
    }

    private fun sha512(data: ByteArray): ByteArray {
        val md = SHA512Digest()
        md.update(data, 0, data.size)
        return ByteArray(md.digestSize).also { md.doFinal(it, 0) }
    }
}
