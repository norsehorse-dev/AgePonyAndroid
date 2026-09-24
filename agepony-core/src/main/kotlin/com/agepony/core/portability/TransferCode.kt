package com.agepony.core.portability

import com.agepony.core.Armor
import java.security.MessageDigest

/**
 * A short code over the exact sealed transfer, for the two people to compare before the receiver
 * imports anything (audit M-6). The wire format is unchanged; this only adds something to show.
 *
 * The threat: the receive QR code holds a public one-time recipient and a LAN token, so anyone who
 * photographs it (and, for the network route, is on the same Wi-Fi) can seal their own bundle to
 * that recipient and deliver it first. The receiver cannot tell that bundle from the real one, and
 * importing it would plant the attacker's keys as the victim's identities and trusted signers. The
 * [KeyTransfer.confirmationCode] check does not help here: it only proves the sender scanned the
 * right receiver.
 *
 * The fix is a code over what was actually delivered. The sender shows [of] over the sealed bytes
 * it sent; the receiver shows [of] over the bytes it received, after receiving and before Import.
 * They match only if the receiver holds the sender's exact transfer, and a forged transfer would
 * need a 60-bit second preimage of a code the attacker never sees, so the user refuses a mismatch.
 *
 * code = first 60 bits of SHA-256(DOMAIN || 0x00 || sealed), formatted like
 * [KeyTransfer.confirmationCode] (Crockford base32, `XXXX-XXXX-XXXX`). `sealed` is the binary age
 * file: an armored transfer (the paste route) is de-armored first, so every route gives the same
 * code for the same transfer.
 */
object TransferCode {
    const val DOMAIN = "agepony.com/transfer-code v1"

    /** The code for [sealed], the transfer as sent or received (binary or armored age). */
    fun of(sealed: ByteArray): String {
        val binary = if (KeyTransfer.looksArmored(sealed)) {
            // An armored transfer that doesn't decode can't be opened either; hash it as given.
            runCatching { Armor.decode(String(sealed, Charsets.UTF_8)) }.getOrDefault(sealed)
        } else {
            sealed
        }
        val md = MessageDigest.getInstance("SHA-256")
        md.update(DOMAIN.toByteArray(Charsets.US_ASCII))
        md.update(0)
        md.update(binary)
        return KeyTransfer.code60(md.digest())
    }
}
