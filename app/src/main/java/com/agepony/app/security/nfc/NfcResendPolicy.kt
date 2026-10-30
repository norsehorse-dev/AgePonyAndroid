package com.agepony.app.security.nfc

import com.agepony.core.fido.Ctap2

/**
 * Which commands may be sent a second time after a transient NFC error (5.1.0, L-8). When the
 * answer is lost, the key may still have run the command. Selecting, reading and ECDH are safe
 * to repeat. A PIN check is not: a wrong PIN sent twice costs two tries, so the user is asked to
 * hold the key again instead. Mirrors iOS `NFCResendPolicy`.
 */
object NfcResendPolicy {
    /**
     * ISO 7816 / PIV instructions that change no PIN state: SELECT, GET DATA, GENERAL
     * AUTHENTICATE, GET METADATA, GET SERIAL. GET RESPONSE (C0) is left out: if its answer is
     * lost the card has already moved to the next chunk, so a resend would return the wrong one.
     */
    val RESENDABLE_ISO_INS: Set<Int> = setOf(0xA4, 0xCB, 0x87, 0xF7, 0xF8)

    /** PIV VERIFY. */
    const val INS_VERIFY = 0x20

    /** Whether a raw APDU (CLA INS P1 P2 ...) may be resent. Anything not known to be safe, VERIFY included, is not. */
    fun mayResend(apdu: ByteArray): Boolean =
        apdu.size >= 4 && (apdu[1].toInt() and 0xff) in RESENDABLE_ISO_INS

    /** Whether [apdu] is a PIV VERIFY (the PIN check). */
    fun isVerify(apdu: ByteArray): Boolean = apdu.size >= 4 && (apdu[1].toInt() and 0xff) == INS_VERIFY

    /** Whether a CTAP2 request (command byte + CBOR) may be resent. Never for clientPIN, which carries the PIN hash. */
    fun mayResendCtap(frame: ByteArray): Boolean =
        frame.isNotEmpty() && (frame[0].toInt() and 0xff) != Ctap2.CMD_CLIENT_PIN
}
