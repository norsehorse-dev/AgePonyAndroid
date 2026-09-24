package com.agepony.app.vault

import com.agepony.app.signing.FileVerifier
import com.agepony.core.Stanza
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner
import com.agepony.core.signing.SignatureStanza
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * Issue #11 app-layer round trip: sign a payload, encrypt it to a recipient with the signature in
 * the agepony.com/sig stanza, then detect, decrypt, recover and verify it.
 */
class FileEncryptorSignedTest {

    private fun ed25519(): Pair<ByteArray, ByteArray> {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val kp = gen.generateKeyPair()
        return (kp.private as Ed25519PrivateKeyParameters).encoded to
            (kp.public as Ed25519PublicKeyParameters).encoded
    }

    @Test
    fun signedEncryptToRecipientRoundTripsAndVerifies() {
        val (priv, pub) = ed25519()
        val plaintext = "signed document".toByteArray()
        val sig = SSHSigner.signEd25519(priv, pub, plaintext)
        val id = X25519Identity.generate()

        val ct = FileEncryptor.encryptSigned(plaintext, listOf(X25519Recipient(id.publicKey)), sig, armor = false)

        assertTrue(FileEncryptor.headerHasSignatureStanza(ByteArrayInputStream(ct)))
        val recovered = FileEncryptor.decryptSignedBytes(ct, listOf(id))
        assertArrayEquals(plaintext, recovered.plaintext)
        assertNotNull(recovered.signatureArmored)

        val verdict = FileVerifier().verify(
            recovered.signatureArmored!!.toByteArray(), recovered.plaintext, emptyList(), emptyList(),
        )
        assertEquals(FileVerifier.Trust.VALID_UNKNOWN, verdict.trust)
    }

    @Test
    fun armoredSignedRoundTrips() {
        val (priv, pub) = ed25519()
        val plaintext = "armored signed".toByteArray()
        val sig = SSHSigner.signEd25519(priv, pub, plaintext)
        val id = X25519Identity.generate()

        val armored = FileEncryptor.encryptSigned(plaintext, listOf(X25519Recipient(id.publicKey)), sig, armor = true)
        val binary = FileEncryptor.toBinary(armored)

        assertTrue(FileEncryptor.headerHasSignatureStanza(ByteArrayInputStream(binary)))
        assertArrayEquals(plaintext, FileEncryptor.decryptSignedBytes(binary, listOf(id)).plaintext)
    }

    // audit L-8: the app now writes v2 stanzas, verified under the namespace the stanza reports.
    @Test
    fun v2StreamingSignedEncryptVerifiesUnderItsOwnNamespace() {
        val (priv, pub) = ed25519()
        val plaintext = "signed v2 document".toByteArray()
        val id = X25519Identity.generate()
        val prepared = FileEncryptor.prepareSigned(listOf(X25519Recipient(id.publicKey)))
        val sha = SSHSig.hashMessage(plaintext, SSHSig.HASH_SHA512)
        val sig = SSHSigner.signEd25519Hashed(priv, pub, prepared.messageHash(sha), SignatureStanza.NAMESPACE_V2)
        val out = ByteArrayOutputStream()
        FileEncryptor.encryptSignedV2Stream(prepared, ByteArrayInputStream(plaintext), sha, sig, armor = true, out = out)

        val recovered = FileEncryptor.decryptSignedBytes(FileEncryptor.toBinary(out.toByteArray()), listOf(id))
        assertArrayEquals(plaintext, recovered.plaintext)
        val opened = recovered.signature as SignatureStanza.Opening.Opened
        assertEquals(2, opened.version)
        val verdict = FileVerifier().verifyHashed(opened.signatureArmored.toByteArray(), emptyList(), emptyList(), opened.namespace) { alg ->
            opened.messageHash(alg) { a -> SSHSig.hashMessage(recovered.plaintext, a) }
        }
        assertEquals(FileVerifier.Trust.VALID_UNKNOWN, verdict.trust)
        // The old hard-coded "agepony" check must not pass a v2 signature.
        val asV1 = FileVerifier().verify(opened.signatureArmored.toByteArray(), recovered.plaintext, emptyList())
        assertEquals(FileVerifier.Trust.INVALID, asV1.trust)
    }

    @Test(expected = FileEncryptorException::class)
    fun v2StreamRejectsAPlaintextThatChangedAfterSigning() {
        val (priv, pub) = ed25519()
        val id = X25519Identity.generate()
        val prepared = FileEncryptor.prepareSigned(listOf(X25519Recipient(id.publicKey)))
        val sha = SSHSig.hashMessage("original".toByteArray(), SSHSig.HASH_SHA512)
        val sig = SSHSigner.signEd25519Hashed(priv, pub, prepared.messageHash(sha), SignatureStanza.NAMESPACE_V2)
        FileEncryptor.encryptSignedV2Stream(prepared, ByteArrayInputStream("swapped".toByteArray()), sha, sig, false, ByteArrayOutputStream())
    }

    @Test
    fun scryptGuardUsesTheLargestWorkFactor() {
        val stanzas = listOf(
            Stanza("scrypt", listOf("c2FsdA", "16"), ByteArray(32)),
            Stanza("scrypt", listOf("c2FsdA", "21"), ByteArray(32)),
        )
        assertEquals(21, FileEncryptor.maxScryptWorkFactor(stanzas))
        assertNull(FileEncryptor.maxScryptWorkFactor(emptyList()))
    }

    @Test
    fun unsignedFileHasNoSignatureStanza() {
        val id = X25519Identity.generate()
        val ct = FileEncryptor.encrypt("plain".toByteArray(), listOf(X25519Recipient(id.publicKey)), null, armor = false)
        assertFalse(FileEncryptor.headerHasSignatureStanza(ByteArrayInputStream(ct)))
    }
}
