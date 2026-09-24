package com.agepony.core

import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.signing.SignatureStanza
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Issue #11: an encrypted-and-signed file carries its signature in an `agepony.com/sig` stanza,
 * so plain age returns the bare payload while AgePony can still recover and check the signature.
 */
class AgeSignatureStanzaTest {

    private val dummySig = "-----BEGIN SSH SIGNATURE-----\nZm9v\n-----END SSH SIGNATURE-----\n"

    private fun sign(fileKey: ByteArray) = listOf(SignatureStanza.build(fileKey, dummySig))

    @Test
    fun decryptRecoversTheSignatureAndThePayload() {
        val id = X25519Identity.generate()
        val plaintext = "the payload".toByteArray()
        val ct = Age.encrypt(plaintext, listOf(X25519Recipient(id.publicKey)), ::sign)
        val result = Age.decryptAndRecoverSignature(ct, listOf(id))
        assertArrayEquals(plaintext, result.plaintext)
        assertEquals(dummySig, result.signatureArmored)
    }

    @Test
    fun plainDecryptOfASignedFileReturnsTheBarePayload() {
        val id = X25519Identity.generate()
        val plaintext = "hello".toByteArray()
        val ct = Age.encrypt(plaintext, listOf(X25519Recipient(id.publicKey)), ::sign)
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(id)))
    }

    @Test
    fun theSigStanzaTravelsInTheHeader() {
        val id = X25519Identity.generate()
        val ct = Age.encrypt("x".toByteArray(), listOf(X25519Recipient(id.publicKey)), ::sign)
        assertNotNull(SignatureStanza.find(AgeHeader.parse(ct).stanzas))
    }

    @Test
    fun anUnsignedFileRecoversNoSignature() {
        val id = X25519Identity.generate()
        val ct = Age.encrypt("x".toByteArray(), listOf(X25519Recipient(id.publicKey)))
        assertNull(Age.decryptAndRecoverSignature(ct, listOf(id)).signatureArmored)
    }
}
