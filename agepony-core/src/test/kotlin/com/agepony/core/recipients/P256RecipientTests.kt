package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.HKDF
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

//
// piv-p256 (age-plugin-yubikey) recipient. AgePony only encrypts to these
// (the YubiKey decrypts), so there is no real identity to round-trip against.
// The test stands in a software P-256 private key for the YubiKey and unwraps
// the stanza by following the spec independently, which checks the whole
// ECDH -> HKDF -> ChaCha20Poly1305 chain and the exact stanza shape.
//
// Algorithm verified against str4d/age-plugin-yubikey src/piv_p256.rs and
// src/recipient.rs. Byte-for-byte interop must still be confirmed on-device by
// decrypting an AgePony-produced file with `age` + a real YubiKey.
//
class P256RecipientTests {

    private fun domain(): ECDomainParameters {
        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        return ECDomainParameters(spec.curve, spec.g, spec.n, spec.h)
    }

    private fun randomScalar(n: BigInteger): BigInteger {
        val rng = SecureRandom()
        while (true) {
            val d = BigInteger(n.bitLength(), rng)
            if (d >= BigInteger.ONE && d < n) return d
        }
    }

    private fun randomFileKey() = ByteArray(16).also { SecureRandom().nextBytes(it) }

    @Test
    fun wrap_producesPivP256Stanza() {
        val dom = domain()
        val d = randomScalar(dom.n)
        val pub = dom.g.multiply(d).normalize().getEncoded(true)
        val recipient = P256Recipient(pub)
        val stanza = recipient.wrap(randomFileKey())

        assertEquals("piv-p256", stanza.type)
        assertEquals(2, stanza.args.size)

        // arg[0] is SHA-256(compressed recipient)[..4]
        val expectedTag = MessageDigest.getInstance("SHA-256").digest(pub).copyOf(4)
        assertArrayEquals(expectedTag, Stanza.base64Decode(stanza.args[0]))

        // arg[1] is the compressed ephemeral public key (33 bytes, 0x02/0x03)
        val epk = Stanza.base64Decode(stanza.args[1])
        assertEquals(33, epk.size)
        assertTrue(epk[0] == 0x02.toByte() || epk[0] == 0x03.toByte())

        // body = ChaCha20Poly1305(16-byte file key) + 16-byte tag
        assertEquals(32, stanza.body.size)
    }

    @Test
    fun roundTrip_unwrapWithTheStandInPrivateKey() {
        val dom = domain()
        val d = randomScalar(dom.n)
        val pub = dom.g.multiply(d).normalize().getEncoded(true)
        val recipient = P256Recipient(pub)

        val fileKey = randomFileKey()
        val stanza = recipient.wrap(fileKey)

        // Unwrap the way the YubiKey would, following the spec independently.
        val epkBytes = Stanza.base64Decode(stanza.args[1])
        val epk = dom.curve.decodePoint(epkBytes)
        val shared = epk.multiply(d).normalize().affineXCoord.encoded
        val salt = epkBytes + pub
        val wrapKey = HKDF.derive(shared, salt, "piv-p256".toByteArray(Charsets.US_ASCII), 32)
        val recovered = ChaChaPoly.decrypt(wrapKey, ByteArray(12), stanza.body)

        assertArrayEquals(fileKey, recovered)
    }

    @Test
    fun bech32RoundTrips() {
        val dom = domain()
        val d = randomScalar(dom.n)
        val pub = dom.g.multiply(d).normalize().getEncoded(true)
        val recipient = P256Recipient(pub)
        val text = recipient.toBech32()
        assertTrue(text.startsWith("age1yubikey1"))
        assertArrayEquals(pub, P256Recipient(text).compressedPublicKey)
    }
}
