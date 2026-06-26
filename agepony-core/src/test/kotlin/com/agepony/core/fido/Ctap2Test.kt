package com.agepony.core.fido

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** CTAP2 request/response vectors from python-fido2 + cbor2. */
class Ctap2Test {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val cdh = ByteArray(32) { it.toByte() }
    private val userId = ByteArray(8) { 1 }
    private val allowId = ByteArray(32) { 0xcc.toByte() }
    private val pin = ByteArray(16) { 0x99.toByte() }

    private val makeCredEd25519 = "a5015820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f02a1626964647373683a03a2626964480101010101010101646e616d6567616765706f6e790481a263616c672764747970656a7075626c69632d6b657907a162726bf5"
    private val makeCredEsPin = "a7015820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f02a1626964647373683a03a2626964480101010101010101646e616d6567616765706f6e790481a263616c672664747970656a7075626c69632d6b657907a162726bf50850999999999999999999999999999999990901"
    private val getAssert = "a401647373683a025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0381a26269645820cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc64747970656a7075626c69632d6b657905a1627570f5"
    private val getAssertPin = "a601647373683a025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0381a26269645820cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc64747970656a7075626c69632d6b657905a1627570f50650999999999999999999999999999999990701"

    private val credId = "abababababababababababababababab"
    private val ed25519Pub = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    private val mcResponse = "00a301646e6f6e65025871e30610e8a162115960fe1ec223e6529c9f4b6e80200dcb5e5c321c8af1e2b1bf4100000007000000000000000000000000000000000010ababababababababababababababababa401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b803a0"
    private val gaResponse = "00a301a262696450abababababababababababababababab64747970656a7075626c69632d6b6579025825e30610e8a162115960fe1ec223e6529c9f4b6e80200dcb5e5c321c8af1e2b1bf0100000007035840cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    private val gaSig = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

    private fun body(req: ByteArray) = req.copyOfRange(1, req.size)

    @Test
    fun buildsMakeCredentialMatchingOracle() {
        val req = Ctap2.buildMakeCredential(cdh, "ssh:", userId, "agepony", listOf(Ctap2.ALG_EDDSA))
        assertEquals(Ctap2.CMD_MAKE_CREDENTIAL, req[0].toInt() and 0xff)
        assertEquals(makeCredEd25519, hex(body(req)))
    }

    @Test
    fun buildsGetAssertionMatchingOracle() {
        val req = Ctap2.buildGetAssertion("ssh:", cdh, listOf(allowId), up = true)
        assertEquals(Ctap2.CMD_GET_ASSERTION, req[0].toInt() and 0xff)
        assertEquals(getAssert, hex(body(req)))
    }

    @Test
    fun pinKeysDifferByCommand() {
        val mc = Ctap2.buildMakeCredential(
            cdh, "ssh:", userId, "agepony", listOf(Ctap2.ALG_ES256),
            pinUvAuthParam = pin, pinUvAuthProtocol = 1
        )
        // makeCredential carries pinUvAuthParam/protocol as keys 8/9
        assertEquals(makeCredEsPin, hex(body(mc)))

        val ga = Ctap2.buildGetAssertion(
            "ssh:", cdh, listOf(allowId), up = true,
            pinUvAuthParam = pin, pinUvAuthProtocol = 1
        )
        // getAssertion carries them as keys 6/7
        assertEquals(getAssertPin, hex(body(ga)))
    }

    @Test
    fun parsesMakeCredentialResponse() {
        val r = Ctap2.parseMakeCredential(unhex(mcResponse))
        assertEquals(credId, hex(r.authData.credentialId!!))
        val pub = r.authData.credentialPublicKey
        assertTrue(pub is CoseKey.Decoded.Ed25519)
        assertEquals(ed25519Pub, hex((pub as CoseKey.Decoded.Ed25519).raw32))
    }

    @Test
    fun parsesGetAssertionResponse() {
        val r = Ctap2.parseGetAssertion(unhex(gaResponse))
        assertEquals(gaSig, hex(r.signature))
        assertEquals(0x01, r.authData.flags)
        assertEquals(7L, r.authData.signCount)
        assertEquals(credId, hex(r.credentialId!!))
    }

    @Test
    fun nonZeroStatusRaisesCtapError() {
        val err = runCatching { Ctap2.parseGetAssertion(byteArrayOf(0x36.toByte())) }.exceptionOrNull()
        assertTrue(err is Ctap2.CtapError && err.code == Ctap2.ERR_PIN_REQUIRED)
    }
}
