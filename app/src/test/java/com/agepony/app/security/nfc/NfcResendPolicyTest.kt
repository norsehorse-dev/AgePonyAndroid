package com.agepony.app.security.nfc

import com.agepony.core.fido.Ctap2
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 5.1.0, L-8: a PIN check is never sent twice after a lost NFC answer. Same cases as iOS. */
class NfcResendPolicyTest {
    private fun apdu(ins: Int) = byteArrayOf(0x00, ins.toByte(), 0x00, 0x80.toByte(), 0x00)

    @Test
    fun verifyIsNeverResent() {
        val verify = byteArrayOf(0x00, 0x20, 0x00, 0x80.toByte(), 0x08) + ByteArray(8) { 0x31 }
        assertFalse(NfcResendPolicy.mayResend(verify))
        assertTrue(NfcResendPolicy.isVerify(verify))
    }

    @Test
    fun idempotentCommandsMayBeResent() {
        for (ins in listOf(0xA4, 0xCB, 0x87, 0xF7, 0xF8)) {
            assertTrue("INS %02X".format(ins), NfcResendPolicy.mayResend(apdu(ins)))
            assertFalse(NfcResendPolicy.isVerify(apdu(ins)))
        }
    }

    @Test
    fun getResponseAndUnknownCommandsAreNot() {
        assertFalse(NfcResendPolicy.mayResend(apdu(0xC0)))
        assertFalse(NfcResendPolicy.mayResend(apdu(0x24))) // CHANGE REFERENCE DATA
        assertFalse(NfcResendPolicy.mayResend(byteArrayOf(0x00, 0xA4.toByte())))
    }

    @Test
    fun ctapClientPinIsNeverResent() {
        assertFalse(NfcResendPolicy.mayResendCtap(byteArrayOf(Ctap2.CMD_CLIENT_PIN.toByte(), 0xA1.toByte())))
        assertTrue(NfcResendPolicy.mayResendCtap(byteArrayOf(Ctap2.CMD_MAKE_CREDENTIAL.toByte())))
        assertTrue(NfcResendPolicy.mayResendCtap(byteArrayOf(Ctap2.CMD_GET_ASSERTION.toByte())))
        assertFalse(NfcResendPolicy.mayResendCtap(ByteArray(0)))
    }
}
