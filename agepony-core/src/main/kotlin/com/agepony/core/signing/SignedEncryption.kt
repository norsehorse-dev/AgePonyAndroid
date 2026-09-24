package com.agepony.core.signing

import com.agepony.core.AgeHeader
import com.agepony.core.AgePayload
import com.agepony.core.Stanza
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.LabeledAgeRecipient
import java.io.InputStream
import java.io.OutputStream
import java.security.DigestInputStream
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Sign-then-encrypt with a v2 [SignatureStanza] (audit L-8), in two steps so the (possibly
 * interactive, suspending) signer runs between them:
 *
 * ```
 * val enc = SignedEncryption.prepare(recipients)              // file key made and wrapped here
 * val toSign = enc.messageHash(SSHSig.hashMessage(plaintext)) // SHA-512 of the v2 message
 * val sig = signer.signHashed(identity, toSign, SignatureStanza.NAMESPACE_V2)
 * val ageFile = enc.encrypt(plaintext, sig)                   // binary age, sig stanza last
 * ```
 *
 * The v2 message covers the recipient stanzas, which only exist once the file key is wrapped,
 * which is why this cannot be a single call the way [com.agepony.core.Age.encrypt] with a v1
 * stanza is. The output is an ordinary age file: plain age ignores the sig stanza.
 *
 * An instance holds a file key in memory. Use it for one file and drop it.
 */
class SignedEncryption private constructor(
    private val fileKey: ByteArray,
    /** The wrapped recipient stanzas, in header order. The v2 signature covers these. */
    val recipientStanzas: List<Stanza>,
) {
    /** The v2 signed message for a plaintext whose SHA-512 is [plaintextSha512]. */
    fun message(plaintextSha512: ByteArray): ByteArray =
        SignatureStanza.v2Message(plaintextSha512, recipientStanzas)

    /**
     * SHA-512 of [message]: what a hashed signer (for example `SSHSigner.signEd25519Hashed`) takes,
     * with namespace [SignatureStanza.NAMESPACE_V2] and hash algorithm sha512.
     */
    fun messageHash(plaintextSha512: ByteArray): ByteArray =
        SSHSig.hashMessage(message(plaintextSha512), SSHSig.HASH_SHA512)

    /**
     * Encrypt [plaintext] with [signatureArmored] in a v2 sig stanza. Binary age output. The
     * signature is checked first, so a signature made over the wrong message or namespace fails
     * here rather than on the recipient's phone.
     */
    fun encrypt(plaintext: ByteArray, signatureArmored: String): ByteArray {
        checkSignature(signatureArmored, SSHSig.hashMessage(plaintext, SSHSig.HASH_SHA512))
        val header = AgeHeader.serialize(recipientStanzas + SignatureStanza.buildV2(fileKey, signatureArmored), fileKey)
        return header + AgePayload.encrypt(fileKey, plaintext)
    }

    /**
     * Streaming [encrypt] for a plaintext read a second time after hashing. [plaintextSha512] is
     * the hash the signature was made over; the stream is hashed again on the way through and a
     * mismatch throws at the end, in which case [out] holds a file whose signature will not verify
     * and the caller must discard it. Does not close either stream.
     */
    fun encryptStream(plaintext: InputStream, plaintextSha512: ByteArray, signatureArmored: String, out: OutputStream) {
        checkSignature(signatureArmored, plaintextSha512)
        out.write(AgeHeader.serialize(recipientStanzas + SignatureStanza.buildV2(fileKey, signatureArmored), fileKey))
        val digest = MessageDigest.getInstance("SHA-512")
        AgePayload.encryptStream(fileKey, DigestInputStream(plaintext, digest), out)
        if (!MessageDigest.isEqual(digest.digest(), plaintextSha512)) {
            throw IllegalStateException("plaintext changed between signing and encrypting")
        }
    }

    private fun checkSignature(signatureArmored: String, plaintextSha512: ByteArray) {
        val result = SSHSigVerifier.verify(
            signatureArmored.toByteArray(Charsets.UTF_8),
            message(plaintextSha512),
            SignatureStanza.NAMESPACE_V2,
            allowNoTouch = true, // a wiring check, not a trust decision
        )
        require(result.valid) { "signature does not cover this file's v2 message: ${result.reason}" }
    }

    companion object {
        private const val FILE_KEY_SIZE = 16

        /**
         * Make a file key and wrap it to [to]. Applies the same recipient rules as
         * [com.agepony.core.Age.encrypt] (at least one recipient, all agreeing on labels), and
         * refuses a passphrase recipient outright: an scrypt stanza must stand alone, so a
         * passphrase file carries its signature in a [com.agepony.core.archive.SignedBundle].
         */
        fun prepare(to: List<AgeRecipient>): SignedEncryption {
            require(to.isNotEmpty()) { "must have at least one recipient" }
            // Same rule as Age.enforceRecipientLabels (private there): every recipient has the
            // same label set, so a post-quantum recipient is never mixed with a classical one.
            val first = labelsOf(to.first())
            require(to.all { labelsOf(it) == first }) {
                "recipients disagree on labels: all recipients must share the same labels " +
                    "(e.g. a post-quantum recipient cannot be combined with a non-post-quantum one)"
            }
            val fileKey = ByteArray(FILE_KEY_SIZE).also { SecureRandom().nextBytes(it) }
            val stanzas = to.map { it.wrap(fileKey) }
            require(stanzas.none { it.type == "scrypt" }) {
                "a signature stanza can't go with a passphrase recipient (age requires scrypt to stand alone)"
            }
            require(stanzas.none { it.type == SignatureStanza.TYPE }) { "a recipient produced a signature stanza" }
            return SignedEncryption(fileKey, stanzas)
        }

        private fun labelsOf(r: AgeRecipient): Set<String> =
            (r as? LabeledAgeRecipient)?.labels() ?: emptySet()
    }
}
