package com.agepony.app.vault

import com.agepony.app.signing.FileVerifier
import com.agepony.core.archive.SignedBundle
import com.agepony.core.archive.TarArchive
import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SignatureStanza

/**
 * Decrypt armored text that has already been de-armored, and check any signature it carries the
 * way the file decrypt does (5.1.0, iOS L-1): a signed bundle's verdict first, otherwise the
 * header stanza's. In memory, like the rest of Text mode. The passphrase path goes through
 * [FileEncryptor.decryptWithPassphrase], so a work factor that won't fit in memory is refused
 * before anything is derived (L-2).
 */
object TextDecryptor {

    /** What a signature check found. Null on [Outcome.signature] means the text carried none. */
    sealed class SignatureCheck {
        /** The signature was checked; [olderFormat] says what a v1 signature does not cover. */
        class Checked(val result: FileVerifier.Result, val olderFormat: OlderFormat? = null) : SignatureCheck()

        /** A signature stanza is there but can't be read: a failed signature, never "unsigned". */
        class Unreadable(val reason: String) : SignatureCheck()

        /** The plaintext is a signed bundle that can't be parsed: also a failure. */
        object DamagedBundle : SignatureCheck()

        /** True when the signature counts as failed (L-3). */
        val failed: Boolean
            get() = when (this) {
                is Checked -> result.trust == FileVerifier.Trust.INVALID
                is Unreadable, DamagedBundle -> true
            }
    }

    /** A v1 signature, and what it leaves out. */
    enum class OlderFormat {
        /** A v1 header stanza: covers the plaintext, not the recipients. */
        STANZA_V1,

        /** A v1 signed bundle: covers the payload, not the name. */
        BUNDLE_V1,
    }

    class Outcome(
        /** The text to show: the bundle's payload when the plaintext was a signed bundle. */
        val plaintext: ByteArray,
        val signature: SignatureCheck?,
    )

    /**
     * [passphrase] non-null means a passphrase decrypt, and [identities] is ignored. Throws what
     * [FileEncryptor] throws: [NoMatchingVaultIdentityException] (offer a passphrase),
     * [WrongPassphraseException], [ScryptMemoryException], [FileEncryptorException].
     */
    fun decrypt(
        binary: ByteArray,
        identities: List<AgeIdentity>,
        passphrase: String?,
        known: List<StoredIdentity>,
        signers: List<StoredSigner>,
    ): Outcome {
        val plaintext: ByteArray
        val stanza: SignatureStanza.Opening
        if (passphrase != null) {
            // A scrypt stanza stands alone, so a passphrase file never carries a sig stanza; its
            // signature, if any, travels in a signed bundle.
            plaintext = FileEncryptor.decryptWithPassphrase(binary, passphrase)
            stanza = SignatureStanza.Opening.Absent
        } else {
            val recovered = FileEncryptor.decryptSignedBytes(binary, identities)
            plaintext = recovered.plaintext
            stanza = recovered.signature
        }

        val bundle = SignedBundle.parse(plaintext)
        if (bundle != null) {
            val result = FileVerifier().verify(
                bundle.signatureArmored.toByteArray(Charsets.UTF_8),
                bundle.signedMessage(),
                known,
                signers,
                bundle.namespace,
            )
            return Outcome(
                bundle.payload,
                SignatureCheck.Checked(result, if (bundle.nameCovered) null else OlderFormat.BUNDLE_V1),
            )
        }
        if (looksLikeBundle(plaintext)) {
            // It says it is a signed bundle but won't parse: show it as failed, not as plain text.
            return Outcome(plaintext, SignatureCheck.DamagedBundle)
        }

        val check = when (stanza) {
            is SignatureStanza.Opening.Absent -> null
            is SignatureStanza.Opening.Unreadable -> SignatureCheck.Unreadable(stanza.reason)
            is SignatureStanza.Opening.Opened -> {
                val result = FileVerifier().verifyHashed(
                    stanza.signatureArmored.toByteArray(Charsets.UTF_8),
                    known,
                    signers,
                    stanza.namespace,
                ) { alg -> stanza.messageHash(alg) { hashAlg -> SSHSig.hashMessage(plaintext, hashAlg) } }
                SignatureCheck.Checked(result, if (stanza.coversRecipients) null else OlderFormat.STANZA_V1)
            }
        }
        return Outcome(plaintext, check)
    }

    /** A tar whose first entry is the signed-bundle marker. */
    internal fun looksLikeBundle(plaintext: ByteArray): Boolean {
        if (plaintext.size < TarArchive.BLOCK_SIZE) return false
        val block = plaintext.copyOfRange(0, TarArchive.BLOCK_SIZE)
        if (!TarArchive.looksLikeTar(block)) return false
        val nameEnd = block.indexOfFirst { it == 0.toByte() }.let { if (it in 0 until 100) it else 100 }
        return String(block, 0, nameEnd, Charsets.UTF_8) == SignedBundle.MARKER
    }
}
