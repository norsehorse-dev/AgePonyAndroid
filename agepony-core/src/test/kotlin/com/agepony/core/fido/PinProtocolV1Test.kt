package com.agepony.core.fido

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.math.BigInteger

/** PIN protocol v1 vectors from python-fido2 PinProtocolV1 with fixed P-256 keys. */
class PinProtocolV1Test {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // Fixed platform private scalar 0x2222... and the authenticator's keyAgreement key.
    private val platformPrivate = BigInteger("2222222222222222222222222222222222222222222222222222222222222222", 16)
    private val authKeyAgreementCose = "a5010203381820012158200217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed225820194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"
    private val sharedSecret = "98f5bf15dbc72627acd9a8ab61ce21349ea3496d79136adf08ad381cc9c0fa25"
    private val platformX = "d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf3"
    private val platformY = "50185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285"
    private val pinHashEnc1234 = "cd782dd78eb3517e6279ff687e577f00"
    private val pinToken = "000102030405060708090a0b0c0d0e0f"
    private val pinTokenEnc = "3a6fce1f2c0517ade8dc3b3f9f6dbb4b"
    private val pinUvAuthParam = "1341af864f792990bbee1f036c20ff72"

    private fun authX963(): ByteArray {
        val d = CoseKey.decodeBytes(unhex(authKeyAgreementCose))
        return (d as CoseKey.Decoded.P256).x963
    }

    @Test
    fun derivesSharedSecretFromEcdh() {
        assertEquals(sharedSecret, hex(PinProtocolV1.sharedSecret(authX963(), platformPrivate)))
    }

    @Test
    fun buildsPlatformCoseKey() {
        val map = PinProtocolV1.platformCose(platformPrivate)
        assertEquals(CoseKey.KTY_EC2, Cbor.asLong(map[CoseKey.KTY]))
        assertEquals(CoseKey.ALG_ECDH_HKDF256, Cbor.asLong(map[CoseKey.ALG]))
        assertEquals(CoseKey.CRV_P256, Cbor.asLong(map[CoseKey.CRV]))
        assertEquals(platformX, hex(Cbor.asBytes(map[CoseKey.X])))
        assertEquals(platformY, hex(Cbor.asBytes(map[CoseKey.Y])))
    }

    @Test
    fun encryptsPinHash() {
        assertEquals(pinHashEnc1234, hex(PinProtocolV1.pinHashEnc(unhex(sharedSecret), "1234")))
    }

    @Test
    fun decryptsPinToken() {
        assertArrayEquals(unhex(pinToken), PinProtocolV1.decrypt(unhex(sharedSecret), unhex(pinTokenEnc)))
    }

    @Test
    fun authenticatesWithPinToken() {
        val cdh = ByteArray(32) { it.toByte() }
        assertEquals(pinUvAuthParam, hex(PinProtocolV1.authenticate(unhex(pinToken), cdh)))
    }

    @Test
    fun encryptDecryptRoundTrips() {
        val shared = unhex(sharedSecret)
        val data = ByteArray(32) { (it * 5 + 1).toByte() }
        assertArrayEquals(data, PinProtocolV1.decrypt(shared, PinProtocolV1.encrypt(shared, data)))
    }
}
