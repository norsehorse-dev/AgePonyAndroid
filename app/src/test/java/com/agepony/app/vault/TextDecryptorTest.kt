package com.agepony.app.vault

import com.agepony.app.signing.FileVerifier
import com.agepony.core.Age
import com.agepony.core.archive.SignedBundle
import com.agepony.core.archive.TarArchive
import com.agepony.core.recipients.ScryptRecipient
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner
import com.agepony.core.signing.SignatureStanza
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 5.1.0, iOS L-1, L-2, L-3: Text decrypt checks a signature stanza or signed bundle the way the
 * file decrypt does, reports a failed one as failed, and refuses an oversized work factor
 * before deriving anything.
 */
class TextDecryptorTest {

    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // The same known ed25519 key FileVerifierTest uses.
    private val seed32 = ByteArray(32) { it.toByte() }
    private val pub32 = unhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")

    private fun ownIdentity() = StoredIdentity(
        id = "id-own",
        name = "Own key",
        type = StoredIdentityType.SSH_ED25519,
        publicKeyB64 = b64e(pub32),
        privateKeyB64 = b64e(seed32),
        createdAt = 0L,
    )

    @Test
    fun unsignedTextHasNoSignature() {
        val id = X25519Identity.generate()
        val ct = FileEncryptor.encrypt("hello".toByteArray(), listOf(X25519Recipient(id.publicKey)), null, armor = false)
        val out = TextDecryptor.decrypt(ct, listOf(id), null, emptyList(), emptyList())
        assertArrayEquals("hello".toByteArray(), out.plaintext)
        assertNull(out.signature)
    }

    @Test
    fun v2StanzaFromOwnKeyIsTrusted() {
        val id = X25519Identity.generate()
        val plaintext = "signed text".toByteArray()
        val prepared = FileEncryptor.prepareSigned(listOf(X25519Recipient(id.publicKey)))
        val sha = SSHSig.hashMessage(plaintext, SSHSig.HASH_SHA512)
        val sig = SSHSigner.signEd25519Hashed(seed32, pub32, prepared.messageHash(sha), SignatureStanza.NAMESPACE_V2)
        val ct = FileEncryptor.encryptSignedV2(prepared, plaintext, sig, armor = true)

        val out = TextDecryptor.decrypt(FileEncryptor.toBinary(ct), listOf(id), null, listOf(ownIdentity()), emptyList())
        assertArrayEquals(plaintext, out.plaintext)
        val check = out.signature as TextDecryptor.SignatureCheck.Checked
        assertEquals(FileVerifier.Trust.TRUSTED, check.result.trust)
        assertNull(check.olderFormat)
        assertFalse(check.failed)
    }

    @Test
    fun v1StanzaOverOtherTextFailsAndIsMarkedOlder() {
        val id = X25519Identity.generate()
        // v1 stanzas aren't checked at encrypt time, so a signature over other text gets through.
        val sig = SSHSigner.signEd25519(seed32, pub32, "something else".toByteArray())
        val ct = FileEncryptor.encryptSigned("the text".toByteArray(), listOf(X25519Recipient(id.publicKey)), sig, armor = false)

        val out = TextDecryptor.decrypt(ct, listOf(id), null, emptyList(), emptyList())
        val check = out.signature as TextDecryptor.SignatureCheck.Checked
        assertEquals(FileVerifier.Trust.INVALID, check.result.trust)
        assertEquals(TextDecryptor.OlderFormat.STANZA_V1, check.olderFormat)
        assertTrue(check.failed)
    }

    @Test
    fun signedBundleShowsItsPayloadAndVerdict() {
        val id = X25519Identity.generate()
        val payload = "bundled text".toByteArray()
        val sig = SSHSigner.signEd25519Hashed(
            seed32, pub32,
            SignedBundle.v2MessageHash("note.txt", SSHSig.hashMessage(payload, SSHSig.HASH_SHA512)),
            SignedBundle.NAMESPACE_V2,
        )
        val bundle = SignedBundle.buildV2("note.txt", payload, sig)
        val ct = FileEncryptor.encrypt(bundle, listOf(X25519Recipient(id.publicKey)), null, armor = false)

        val out = TextDecryptor.decrypt(ct, listOf(id), null, emptyList(), emptyList())
        assertArrayEquals(payload, out.plaintext)
        val check = out.signature as TextDecryptor.SignatureCheck.Checked
        assertEquals(FileVerifier.Trust.VALID_UNKNOWN, check.result.trust)
        assertFalse(check.failed)
    }

    @Test
    fun damagedBundleIsAFailureNotPlainText() {
        val id = X25519Identity.generate()
        // Only the marker entry: it says it is a signed bundle but has no payload or signature.
        val broken = TarArchive.create(listOf(TarArchive.Entry(SignedBundle.MARKER, "agepony-signed/2\nname=x\n".toByteArray())))
        val ct = FileEncryptor.encrypt(broken, listOf(X25519Recipient(id.publicKey)), null, armor = false)

        val out = TextDecryptor.decrypt(ct, listOf(id), null, emptyList(), emptyList())
        assertTrue(out.signature is TextDecryptor.SignatureCheck.DamagedBundle)
        assertTrue(out.signature!!.failed)
    }

    @Test(expected = NoMatchingVaultIdentityException::class)
    fun noIdentityMeansAskForAPassphrase() {
        val ct = Age.encrypt("x".toByteArray(), listOf(ScryptRecipient("pw", 16)))
        TextDecryptor.decrypt(ct, emptyList(), null, emptyList(), emptyList())
    }

    @Test
    fun passphraseTextDecrypts() {
        val ct = Age.encrypt("by passphrase".toByteArray(), listOf(ScryptRecipient("pw", 16)))
        val out = TextDecryptor.decrypt(ct, emptyList(), "pw", emptyList(), emptyList())
        assertArrayEquals("by passphrase".toByteArray(), out.plaintext)
        assertNull(out.signature)
    }

    @Test(expected = ScryptMemoryException::class)
    fun oversizedWorkFactorIsRefusedBeforeDeriving() {
        // L-2: 2^30 would need 128 GiB. The guard must throw before scrypt allocates.
        TextDecryptor.decrypt(withWorkFactor(30), emptyList(), "pw", emptyList(), emptyList())
    }

    @Test(expected = ScryptMemoryException::class)
    fun everyPassphrasePathSharesTheGuard() {
        // Text, Migrate, passphrase mode, notes and the share hand-off all decrypt through this.
        FileEncryptor.decryptWithPassphrase(withWorkFactor(30), "pw")
    }

    /** A real passphrase file with its scrypt work factor rewritten (the header MAC no longer matches). */
    private fun withWorkFactor(logN: Int): ByteArray {
        val ct = Age.encrypt("x".toByteArray(), listOf(ScryptRecipient("pw", 16)))
        val text = String(ct, Charsets.ISO_8859_1)
        val start = text.indexOf("-> scrypt ")
        val lineEnd = text.indexOf('\n', start)
        val line = text.substring(start, lineEnd)
        val patched = line.substring(0, line.lastIndexOf(' ') + 1) + logN
        return (text.substring(0, start) + patched + text.substring(lineEnd)).toByteArray(Charsets.ISO_8859_1)
    }
}
