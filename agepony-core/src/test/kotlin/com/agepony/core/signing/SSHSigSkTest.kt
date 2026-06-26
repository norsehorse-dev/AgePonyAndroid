package com.agepony.core.signing

import com.agepony.core.crypto.SHA256
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom

/**
 * SSHSIG for the security-key (FIDO) variants: `sk-ssh-ed25519@openssh.com` and
 * `sk-ecdsa-sha2-nistp256@openssh.com`.
 *
 * P3 will drive a real YubiKey / Token2 over NFC; the authenticator's golden vectors land
 * then. Here we simulate the authenticator in software so the wire format, the FIDO
 * authenticator-data model `SHA-256(application) || flags || counter || SHA-256(signed-data)`,
 * the assemble self-verify guard, and the verifier all get exercised without a device.
 *
 * The envelope these produce was confirmed against `ssh-keygen -Y verify` during P1
 * bring-up; this test keeps that contract pinned in CI.
 */
class SSHSigSkTest {
    private val rng = SecureRandom()
    private val app = SSHSig.SK_APPLICATION_DEFAULT
    private val message = "hello agepony".toByteArray()

    // --- Wire round-trips ---

    @Test
    fun skEd25519_wireRoundTrips() {
        val pub = SSHSig.skEd25519PublicWire(ByteArray(32), app)
        val sig = SSHSig.skEd25519SigWire(ByteArray(64), 0x01, 9)
        val decoded = SSHSig.decode(SSHSig.encode(pub, SSHSig.NAMESPACE_AGEPONY, SSHSig.HASH_SHA512, sig))
        assertEquals(SSHSig.KEY_SK_ED25519, decoded.keyType)
        assertEquals(SSHSig.SIG_SK_ED25519, decoded.signatureType)
        assertEquals(SSHSig.NAMESPACE_AGEPONY, decoded.namespace)
    }

    @Test
    fun skEcdsa_wireRoundTrips() {
        val q = SSHSigner.publicPointFromScalar(randomScalar())
        val pub = SSHSig.skEcdsaP256PublicWire(q, app)
        val sig = SSHSig.skEcdsaSigWire(BigInteger.valueOf(7), BigInteger.valueOf(11), 0x05, 3)
        val decoded = SSHSig.decode(SSHSig.encode(pub, SSHSig.NAMESPACE_AGEPONY, SSHSig.HASH_SHA512, sig))
        assertEquals(SSHSig.KEY_SK_ECDSA_P256, decoded.keyType)
        assertEquals(SSHSig.SIG_SK_ECDSA_P256, decoded.signatureType)
    }

    // --- sk-ed25519 simulated authenticator ---

    @Test
    fun skEd25519_assembleAndVerify() {
        val seed = ByteArray(32).also { rng.nextBytes(it) }
        val priv = Ed25519PrivateKeyParameters(seed, 0)
        val pub32 = priv.generatePublicKey().encoded
        val flags = 0x01
        val counter = 5

        val rawSig = ed25519AuthenticatorSign(priv, app, flags, counter)
        val armored = SSHSigner.assembleSkEd25519(pub32, rawSig, flags, counter, message, app)

        assertTrue(SSHSigVerifier.isValid(armored.toByteArray(), message))
        assertFalse(SSHSigVerifier.isValid(armored.toByteArray(), "tampered".toByteArray()))
    }

    @Test
    fun skEd25519_wrongApplicationFailsSelfVerify() {
        val seed = ByteArray(32).also { rng.nextBytes(it) }
        val priv = Ed25519PrivateKeyParameters(seed, 0)
        val pub32 = priv.generatePublicKey().encoded
        val flags = 0x01
        val counter = 1

        // Authenticator signed over application "ssh:" but we package it as a different app.
        val rawSig = ed25519AuthenticatorSign(priv, app, flags, counter)
        assertThrows(SSHSigner.SSHSignerException::class.java) {
            SSHSigner.assembleSkEd25519(pub32, rawSig, flags, counter, message, "other:")
        }
    }

    // --- sk-ecdsa simulated authenticator ---

    @Test
    fun skEcdsa_assembleAndVerify() {
        val d = randomScalar()
        val q = SSHSigner.publicPointFromScalar(d)
        val flags = 0x01
        val counter = 42

        val der = ecdsaAuthenticatorSign(d, app, flags, counter)
        val armored = SSHSigner.assembleSkEcdsaP256(q, der, flags, counter, message, app)

        assertTrue(SSHSigVerifier.isValid(armored.toByteArray(), message))
        assertFalse(SSHSigVerifier.isValid(armored.toByteArray(), "tampered".toByteArray()))
    }

    // --- authenticator simulation helpers ---

    /** FIDO message: SHA-256(app) || flags || counter || SHA-256(signed-data). */
    private fun authenticatorMessage(application: String, flags: Int, counter: Int): ByteArray {
        val signedData = SSHSig.signedData(
            SSHSig.NAMESPACE_AGEPONY,
            SSHSig.HASH_SHA512,
            SSHSig.hashMessage(message, SSHSig.HASH_SHA512),
        )
        val out = ByteArrayOutputStream()
        out.write(SHA256.digest(application.toByteArray(Charsets.UTF_8)))
        out.write(flags and 0xff)
        SSHSig.writeUInt32(out, counter)
        out.write(SHA256.digest(signedData))
        return out.toByteArray()
    }

    private fun ed25519AuthenticatorSign(
        priv: Ed25519PrivateKeyParameters,
        application: String,
        flags: Int,
        counter: Int,
    ): ByteArray {
        val authMsg = authenticatorMessage(application, flags, counter)
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(authMsg, 0, authMsg.size)
        return signer.generateSignature()
    }

    private fun ecdsaAuthenticatorSign(
        d: BigInteger,
        application: String,
        flags: Int,
        counter: Int,
    ): ByteArray {
        val authMsg = authenticatorMessage(application, flags, counter)
        val signer = ECDSASigner()
        signer.init(true, ParametersWithRandom(ECPrivateKeyParameters(d, SSHSigner.p256Domain()), rng))
        val sig = signer.generateSignature(SHA256.digest(authMsg))
        val seq = DERSequence(arrayOf<ASN1Encodable>(ASN1Integer(sig[0]), ASN1Integer(sig[1])))
        return seq.getEncoded("DER")
    }

    private fun randomScalar(): BigInteger {
        val n = SSHSigner.p256Domain().n
        var d: BigInteger
        do {
            d = BigInteger(n.bitLength(), rng)
        } while (d < BigInteger.ONE || d >= n)
        return d
    }
}
