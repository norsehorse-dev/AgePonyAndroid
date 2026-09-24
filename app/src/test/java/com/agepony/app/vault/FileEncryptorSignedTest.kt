package com.agepony.app.vault

import com.agepony.app.signing.FileVerifier
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.signing.SSHSigner
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
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

    @Test
    fun unsignedFileHasNoSignatureStanza() {
        val id = X25519Identity.generate()
        val ct = FileEncryptor.encrypt("plain".toByteArray(), listOf(X25519Recipient(id.publicKey)), null, armor = false)
        assertFalse(FileEncryptor.headerHasSignatureStanza(ByteArrayInputStream(ct)))
    }
}
