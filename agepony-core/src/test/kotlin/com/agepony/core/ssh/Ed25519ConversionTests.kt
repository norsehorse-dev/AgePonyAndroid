package com.agepony.core.ssh

import com.agepony.core.crypto.X25519Crypto
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class Ed25519ConversionTests {
    @Test
    fun publicKeyToX25519_returns32Bytes() {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val priv = Ed25519PrivateKeyParameters(seed, 0)
        val edPub = priv.generatePublicKey().encoded
        val x25519Pub = Ed25519Conversion.publicKeyToX25519(edPub)
        assertEquals(32, x25519Pub.size)
    }

    @Test
    fun privateKeyToX25519_returns32Bytes_andApplyesClamp() {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val x25519Priv = Ed25519Conversion.privateKeyToX25519(seed)
        assertEquals(32, x25519Priv.size)
        // RFC 7748 X25519 clamping: bottom 3 bits of byte 0 cleared,
        // top bit of byte 31 cleared, second-to-top bit of byte 31 set.
        assertEquals(0, x25519Priv[0].toInt() and 0x07)
        assertEquals(0, x25519Priv[31].toInt() and 0x80)
        assertEquals(0x40, x25519Priv[31].toInt() and 0x40)
    }

    /**
     * The X25519 derivation must be consistent: deriving the X25519 private scalar from
     * a seed and multiplying by the basepoint must give the X25519 public key converted
     * from the corresponding Ed25519 public key.
     */
    @Test
    fun roundTrip_consistency_xPubMatchesScalarMul() {
        repeat(5) {
            val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val edPriv = Ed25519PrivateKeyParameters(seed, 0)
            val edPub = edPriv.generatePublicKey().encoded

            val x25519Priv = Ed25519Conversion.privateKeyToX25519(seed)
            val x25519PubFromConversion = Ed25519Conversion.publicKeyToX25519(edPub)
            val x25519PubFromScalarMul = X25519Crypto.publicKey(x25519Priv)

            assertArrayEquals(
                x25519PubFromConversion, x25519PubFromScalarMul,
                "round-trip mismatch: scalar-mul pubkey differs from converted Ed25519 pubkey"
            )
        }
    }

    @Test
    fun publicKeyToX25519_rejectsWrongSize() {
        assertThrows(IllegalArgumentException::class.java) {
            Ed25519Conversion.publicKeyToX25519(ByteArray(16))
        }
    }

    @Test
    fun privateKeyToX25519_rejectsWrongSize() {
        assertThrows(IllegalArgumentException::class.java) {
            Ed25519Conversion.privateKeyToX25519(ByteArray(16))
        }
    }
}
