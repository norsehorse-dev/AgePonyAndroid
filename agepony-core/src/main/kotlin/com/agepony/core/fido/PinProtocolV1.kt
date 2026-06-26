package com.agepony.core.fido

import com.agepony.core.crypto.AESCBC
import com.agepony.core.crypto.SHA256
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.ECNamedCurveTable
import java.math.BigInteger
import java.security.SecureRandom

/**
 * FIDO PIN/UV auth protocol one, the crypto behind clientPin.
 *
 * The platform and authenticator each hold a P-256 key; the shared secret is
 * SHA-256 of the ECDH X coordinate. PIN material is wrapped with AES-256-CBC (zero IV,
 * no padding) under that shared secret, and request authentication tags are the first 16
 * bytes of HMAC-SHA-256. Every primitive here was checked against python-fido2's
 * PinProtocolV1 in the JVM tests.
 */
object PinProtocolV1 {
    const val VERSION = 1

    private val rng = SecureRandom()

    class Encapsulation(val platformCose: LinkedHashMap<Any, Any?>, val sharedSecret: ByteArray)

    /**
     * Generate a fresh platform key pair, derive the shared secret against the
     * authenticator's keyAgreement key, and return the platform COSE key to send plus the
     * shared secret.
     */
    fun encapsulate(authKeyAgreement: Map<Long, Any?>): Encapsulation {
        val authPub = CoseKey.decode(authKeyAgreement)
        val authX963 = when (authPub) {
            is CoseKey.Decoded.P256 -> authPub.x963
            else -> throw Cbor.CborException("authenticator keyAgreement key is not P-256")
        }
        val d = randomScalar()
        return Encapsulation(platformCose(d), sharedSecret(authX963, d))
    }

    /** Shared secret = SHA-256(ECDH X coordinate). [authPublicX963] is `04 || X || Y`. */
    fun sharedSecret(authPublicX963: ByteArray, platformPrivate: BigInteger): ByteArray {
        val dom = domain()
        val authPoint = dom.curve.decodePoint(authPublicX963)
        val shared = authPoint.multiply(platformPrivate).normalize()
        return SHA256.digest(shared.affineXCoord.encoded)
    }

    /** Platform keyAgreement public key as an EC2 COSE map (kty EC2, alg -25, crv P-256). */
    fun platformCose(platformPrivate: BigInteger): LinkedHashMap<Any, Any?> {
        val dom = domain()
        val q = dom.g.multiply(platformPrivate).normalize()
        val map = LinkedHashMap<Any, Any?>()
        map[CoseKey.KTY] = CoseKey.KTY_EC2
        map[CoseKey.ALG] = CoseKey.ALG_ECDH_HKDF256
        map[CoseKey.CRV] = CoseKey.CRV_P256
        map[CoseKey.X] = q.affineXCoord.encoded
        map[CoseKey.Y] = q.affineYCoord.encoded
        return map
    }

    fun encrypt(sharedSecret: ByteArray, data: ByteArray): ByteArray =
        AESCBC.encrypt(sharedSecret, AESCBC.ZERO_IV, data)

    fun decrypt(sharedSecret: ByteArray, data: ByteArray): ByteArray =
        AESCBC.decrypt(sharedSecret, AESCBC.ZERO_IV, data)

    /** Authentication tag = HMAC-SHA-256(key, data) truncated to 16 bytes. */
    fun authenticate(key: ByteArray, data: ByteArray): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        val full = ByteArray(mac.macSize)
        mac.doFinal(full, 0)
        return full.copyOf(16)
    }

    /** pinHashEnc = AES-CBC(sharedSecret, SHA-256(pin)[:16]). */
    fun pinHashEnc(sharedSecret: ByteArray, pin: String): ByteArray {
        val pinHash = SHA256.digest(pin.toByteArray(Charsets.UTF_8)).copyOf(16)
        return encrypt(sharedSecret, pinHash)
    }

    private fun domain(): ECDomainParameters {
        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        return ECDomainParameters(spec.curve, spec.g, spec.n, spec.h)
    }

    private fun randomScalar(): BigInteger {
        val n = domain().n
        while (true) {
            val d = BigInteger(n.bitLength(), rng)
            if (d.signum() > 0 && d < n) return d
        }
    }
}
