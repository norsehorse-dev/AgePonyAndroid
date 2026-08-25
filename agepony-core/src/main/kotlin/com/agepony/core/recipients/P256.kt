package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.bech32.Bech32
import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.HKDF
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

private const val YUBIKEY_HRP = "age1yubikey"
private const val PIV_P256_STANZA_TYPE = "piv-p256"
private const val PIV_P256_TAG_BYTES = 4
private val PIV_P256_INFO = "piv-p256".toByteArray(Charsets.US_ASCII)
private val ZERO_NONCE_12 = ByteArray(12)

/**
 * An age piv-p256 recipient, i.e. an `age1yubikey1...` recipient produced by
 * age-plugin-yubikey. AgePony can *encrypt to* one of these in software; only
 * the YubiKey itself can decrypt, so there is no matching identity here.
 *
 * The recipient is a compressed SEC1 P-256 public key (33 bytes). Wrap follows
 * the same ECDH pattern as X25519, over P-256:
 *
 *   ephemeral (e, E),  E = compressed 33-byte point,
 *   shared   = ECDH(e, recipientPub) x-coordinate (32 bytes),
 *   salt     = E || recipientPub          (33 + 33),
 *   wrapKey  = HKDF-SHA256(ikm=shared, salt=salt, info="piv-p256", L=32),
 *   body     = ChaCha20Poly1305(wrapKey, 0-nonce, fileKey),
 *   tag      = SHA-256(recipientPub)[0..4].
 *
 * Stanza: type="piv-p256", args=[base64NoPad(tag), base64NoPad(E)], body.
 *
 * Verified against str4d/age-plugin-yubikey `src/piv_p256.rs` (wrap_file_key,
 * salt, STANZA_KEY_LABEL) and `src/recipient.rs` (static_tag, TAG_BYTES=4).
 */
class P256Recipient(val compressedPublicKey: ByteArray) : AgeRecipient {
    init {
        require(compressedPublicKey.size == 33) {
            "piv-p256 recipient must be a 33-byte compressed SEC1 point"
        }
        require(compressedPublicKey[0] == 0x02.toByte() || compressedPublicKey[0] == 0x03.toByte()) {
            "piv-p256 recipient must start with a 0x02 or 0x03 compression byte"
        }
        // Validate the point is actually on the curve; decodePoint throws otherwise.
        domain().curve.decodePoint(compressedPublicKey)
    }

    /** Parse a Bech32 `age1yubikey1...` recipient string. */
    constructor(bech32: String) : this(decodeBech32(bech32))

    override fun wrap(fileKey: ByteArray): Stanza {
        val dom = domain()
        val recipientPoint = dom.curve.decodePoint(compressedPublicKey)

        val d = randomScalar(dom.n)
        val ephemeralPoint = dom.g.multiply(d).normalize()
        val epkBytes = ephemeralPoint.getEncoded(true) // compressed, 33 bytes

        val sharedPoint = recipientPoint.multiply(d).normalize()
        if (sharedPoint.isInfinity) {
            throw IllegalArgumentException("piv-p256 shared secret is the point at infinity")
        }
        // Fixed-length 32-byte big-endian x-coordinate, as age uses.
        val shared = sharedPoint.affineXCoord.encoded

        val salt = epkBytes + compressedPublicKey
        val wrapKey = HKDF.derive(shared, salt, PIV_P256_INFO, 32)
        val body = ChaChaPoly.encrypt(wrapKey, ZERO_NONCE_12, fileKey)

        val tag = MessageDigest.getInstance("SHA-256")
            .digest(compressedPublicKey)
            .copyOf(PIV_P256_TAG_BYTES)

        return Stanza(
            PIV_P256_STANZA_TYPE,
            listOf(Stanza.base64NoPad(tag), Stanza.base64NoPad(epkBytes)),
            body,
        )
    }

    /** Encode this recipient back to its Bech32 `age1yubikey1...` string. */
    fun toBech32(): String = Bech32.encode(YUBIKEY_HRP, compressedPublicKey)

    companion object {
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

        private fun decodeBech32(s: String): ByteArray {
            val (hrp, bytes) = Bech32.decode(s)
            if (hrp != YUBIKEY_HRP) {
                throw IllegalArgumentException("expected HRP '$YUBIKEY_HRP', got '$hrp'")
            }
            if (bytes.size != 33) {
                throw IllegalArgumentException(
                    "expected 33-byte compressed P-256 point, got ${bytes.size}"
                )
            }
            return bytes
        }
    }
}
