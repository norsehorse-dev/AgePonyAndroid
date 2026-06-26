package com.agepony.core.fido

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.math.BigInteger

/** clientPin request/response vectors from python-fido2 + cbor2 with fixed keys. */
class ClientPinTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val platformPrivate = BigInteger("2222222222222222222222222222222222222222222222222222222222222222", 16)
    private val getKeyAgreementReq = "06a201010202"
    private val getKeyAgreementResp = "00a101a5010203381820012158200217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed225820194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"
    private val pinHashEnc = "cd782dd78eb3517e6279ff687e577f00"
    private val getPinTokenReq = "06a40101020503a501020338182001215820d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf322582050185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c912850650cd782dd78eb3517e6279ff687e577f00"
    private val getPinTokenResp = "00a102503a6fce1f2c0517ade8dc3b3f9f6dbb4b"
    private val pinTokenEnc = "3a6fce1f2c0517ade8dc3b3f9f6dbb4b"

    @Test
    fun buildsGetKeyAgreement() {
        assertEquals(getKeyAgreementReq, hex(Ctap2.buildGetKeyAgreement()))
    }

    @Test
    fun parsesGetKeyAgreement() {
        val cose = Ctap2.parseGetKeyAgreement(unhex(getKeyAgreementResp))
        assertEquals(CoseKey.KTY_EC2, Cbor.asLong(cose[CoseKey.KTY]))
        assertEquals(CoseKey.ALG_ECDH_HKDF256, Cbor.asLong(cose[CoseKey.ALG]))
        val decoded = CoseKey.decode(cose)
        assertEquals(65, (decoded as CoseKey.Decoded.P256).x963.size)
    }

    @Test
    fun buildsGetPinToken() {
        val platformCose = PinProtocolV1.platformCose(platformPrivate)
        val req = Ctap2.buildGetPinToken(platformCose, unhex(pinHashEnc))
        assertEquals(getPinTokenReq, hex(req))
    }

    @Test
    fun parsesGetPinToken() {
        assertEquals(pinTokenEnc, hex(Ctap2.parseGetPinToken(unhex(getPinTokenResp))))
    }
}
