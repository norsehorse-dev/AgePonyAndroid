package com.agepony.core.signing

import com.agepony.core.Age
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * End-to-end proof of the agepony.com/sig format with a real SSHSIG: sign the plaintext, carry the
 * signature inside the encrypted stanza, decrypt, recover it, and verify it against the recovered
 * plaintext. A tampered plaintext must fail verification.
 */
class SignedFileRoundTripTest {

    private fun ed25519(): Pair<ByteArray, ByteArray> {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val kp = gen.generateKeyPair()
        val priv = (kp.private as Ed25519PrivateKeyParameters).encoded
        val pub = (kp.public as Ed25519PublicKeyParameters).encoded
        return priv to pub
    }

    @Test
    fun realSignatureSurvivesTheStanzaAndVerifies() {
        val (priv, pub) = ed25519()
        val plaintext = "the document to sign and encrypt".toByteArray()
        val sigArmored = SSHSigner.signEd25519(priv, pub, plaintext)

        val id = X25519Identity.generate()
        val ct = Age.encrypt(plaintext, listOf(X25519Recipient(id.publicKey))) { fileKey ->
            listOf(SignatureStanza.build(fileKey, sigArmored))
        }

        val result = Age.decryptAndRecoverSignature(ct, listOf(id))
        assertArrayEquals(plaintext, result.plaintext)
        assertNotNull(result.signatureArmored)
        assertTrue(SSHSigVerifier.isValid(result.signatureArmored!!.toByteArray(), result.plaintext))
        assertFalse(
            SSHSigVerifier.isValid(result.signatureArmored!!.toByteArray(), result.plaintext + 0x21.toByte())
        )
    }
}
