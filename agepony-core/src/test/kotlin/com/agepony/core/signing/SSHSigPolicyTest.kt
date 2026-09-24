package com.agepony.core.signing

import com.agepony.core.crypto.SHA256
import com.agepony.core.ssh.AllowedSigners
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

/**
 * Verifier policy: security-key signatures need the touch flag (audit L-7), RSA signers need a
 * sane key (audit AS-8), and oversized signature input is refused before parsing.
 */
class SSHSigPolicyTest {
    private val rng = SecureRandom()
    private val app = SSHSig.SK_APPLICATION_DEFAULT
    private val message = "policy".toByteArray()

    // --- L-7: user presence ---

    private fun skEd(flags: Int): String {
        val priv = Ed25519PrivateKeyParameters(ByteArray(32).also { rng.nextBytes(it) }, 0)
        val raw = Ed25519Signer().run {
            init(true, priv)
            val m = authMessage(flags, 7)
            update(m, 0, m.size)
            generateSignature()
        }
        // Assembly checks structure only, so an untouched signature still assembles.
        return SSHSigner.assembleSkEd25519(priv.generatePublicKey().encoded, raw, flags, 7, message, app)
    }

    private fun skEc(flags: Int): String {
        val n = SSHSigner.p256Domain().n
        var d: BigInteger
        do { d = BigInteger(n.bitLength(), rng) } while (d < BigInteger.ONE || d >= n)
        val signer = ECDSASigner()
        signer.init(true, ParametersWithRandom(ECPrivateKeyParameters(d, SSHSigner.p256Domain()), rng))
        val rs = signer.generateSignature(SHA256.digest(authMessage(flags, 3)))
        val der = DERSequence(arrayOf<ASN1Encodable>(ASN1Integer(rs[0]), ASN1Integer(rs[1]))).getEncoded("DER")
        return SSHSigner.assembleSkEcdsaP256(SSHSigner.publicPointFromScalar(d), der, flags, 3, message, app)
    }

    @Test
    fun skEd25519WithoutTouchIsRejectedByDefault() {
        val sig = skEd(0x00).toByteArray()
        val r = SSHSigVerifier.verify(sig, message)
        assertFalse(r.valid)
        assertTrue(r.reason!!.contains("touch"))
        assertEquals(false, r.userPresent)
        assertFalse(SSHSigVerifier.isValid(sig, message))
        assertTrue(SSHSigVerifier.verify(sig, message, allowNoTouch = true).valid)
        assertFalse(SSHSigVerifier.verifyHashed(sig) { SSHSig.hashMessage(message, it) }.valid)
        assertTrue(SSHSigVerifier.verifyHashed(sig, SSHSig.NAMESPACE_AGEPONY, true) { SSHSig.hashMessage(message, it) }.valid)
    }

    @Test
    fun skEcdsaWithoutTouchIsRejectedByDefault() {
        val sig = skEc(0x04).toByteArray()
        val r = SSHSigVerifier.verify(sig, message)
        assertFalse(r.valid)
        assertEquals(false, r.userPresent)
        assertEquals(true, r.userVerified)
        assertTrue(SSHSigVerifier.verify(sig, message, allowNoTouch = true).valid)
    }

    @Test
    fun touchedSignaturesReportTheirFlags() {
        val r = SSHSigVerifier.verify(skEd(0x05).toByteArray(), message)
        assertTrue(r.valid)
        assertEquals(0x05, r.skFlags)
        assertEquals(true, r.userPresent)
        assertEquals(true, r.userVerified)
        val plain = SSHSigVerifier.verify(skEc(0x01).toByteArray(), message)
        assertTrue(plain.valid)
        assertEquals(false, plain.userVerified)
    }

    @Test
    fun nonSkSignaturesHaveNoFlags() {
        val seed = ByteArray(32).also { rng.nextBytes(it) }
        val pub = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
        val r = SSHSigVerifier.verify(SSHSigner.signEd25519(seed, pub, message).toByteArray(), message)
        assertTrue(r.valid)
        assertNull(r.skFlags)
        assertNull(r.userPresent)
        assertNull(r.userVerified)
    }

    @Test
    fun allowedSignerEntryDecidesOnTheFlags() {
        val untouched = SSHSigVerifier.verify(skEd(0x00).toByteArray(), message, allowNoTouch = true)
        val touched = SSHSigVerifier.verify(skEd(0x01).toByteArray(), message)
        val verified = SSHSigVerifier.verify(skEd(0x05).toByteArray(), message)
        val key = Base64.getEncoder().encodeToString(untouched.signerPublicWire)
        fun entry(opts: String?) = AllowedSigners.parseLine(
            "a ${opts?.let { "$it " } ?: ""}sk-ssh-ed25519@openssh.com $key"
        )!!
        val now = Instant.now()
        assertFalse(entry(null).accepts(untouched, now, ZoneOffset.UTC))
        assertTrue(entry("no-touch-required").accepts(untouched, now, ZoneOffset.UTC))
        assertTrue(entry(null).accepts(touched, now, ZoneOffset.UTC))
        assertFalse(entry("verify-required").accepts(touched, now, ZoneOffset.UTC))
        assertTrue(entry("verify-required").accepts(verified, now, ZoneOffset.UTC))
        assertFalse(entry("namespaces=\"git\"").accepts(touched, now, ZoneOffset.UTC))
    }

    // --- AS-8: RSA key checks ---

    private fun rsaKey(bits: Int): RSAPrivateCrtKeyParameters {
        val gen = RSAKeyPairGenerator()
        gen.init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), rng, bits, 80))
        return gen.generateKeyPair().private as RSAPrivateCrtKeyParameters
    }

    @Test
    fun rsaUnder1024BitsIsRefused() {
        val k = rsaKey(768)
        val sig = SSHSigner.signRsaSha512(k.modulus, k.publicExponent, k.exponent, message)
        val r = SSHSigVerifier.verify(sig.toByteArray(), message)
        assertFalse(r.valid)
        assertTrue(r.reason!!.contains("too small"))
    }

    @Test
    fun rsa1024AndUpVerifies() {
        val k = rsaKey(1024)
        val sig = SSHSigner.signRsaSha512(k.modulus, k.publicExponent, k.exponent, message)
        assertTrue(SSHSigVerifier.verify(sig.toByteArray(), message).valid)
    }

    @Test
    fun badRsaExponentsAreRefused() {
        val k = rsaKey(1024)
        val bad = listOf(
            BigInteger.valueOf(65536),                    // even
            BigInteger.ONE,                               // below 3
            BigInteger.ONE.shiftLeft(32).add(BigInteger.ONE), // 2^32 + 1
            BigInteger.ONE.shiftLeft(4000).add(BigInteger.ONE), // a CPU-burning exponent
        )
        for (e in bad) {
            // The envelope carries the bogus exponent; the check fires before any arithmetic.
            val sig = SSHSigner.signRsaSha512(k.modulus, e, k.exponent, message)
            val r = SSHSigVerifier.verify(sig.toByteArray(), message)
            assertFalse(r.valid, "e=$e")
            assertTrue(r.reason!!.contains("exponent"), "e=$e: ${r.reason}")
        }
    }

    @Test
    fun oversizedSignatureInputIsRefused() {
        val huge = ByteArray(SSHSigVerifier.MAX_SIGNATURE_BYTES + 1) { 'A'.code.toByte() }
        assertThrows(SSHSig.SSHSigFormatException::class.java) { SSHSigVerifier.verify(huge, message) }
        assertThrows(SSHSig.SSHSigFormatException::class.java) { SSHSigVerifier.verifyHashed(huge) { ByteArray(64) } }
    }

    // --- helpers ---

    private fun authMessage(flags: Int, counter: Int): ByteArray {
        val signedData = SSHSig.signedData(
            SSHSig.NAMESPACE_AGEPONY,
            SSHSig.HASH_SHA512,
            SSHSig.hashMessage(message, SSHSig.HASH_SHA512),
        )
        val out = ByteArrayOutputStream()
        out.write(SHA256.digest(app.toByteArray(Charsets.UTF_8)))
        out.write(flags and 0xff)
        SSHSig.writeUInt32(out, counter)
        out.write(SHA256.digest(signedData))
        return out.toByteArray()
    }
}
