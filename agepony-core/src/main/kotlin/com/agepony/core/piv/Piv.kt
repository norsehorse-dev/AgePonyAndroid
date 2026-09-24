package com.agepony.core.piv

import com.agepony.core.crypto.P256Curve
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec

/**
 * The slice of the PIV card interface (NIST SP 800-73-4, plus YubiKey's GET SERIAL) that
 * decrypting with an age-plugin-yubikey key needs: select the applet, read a slot's certificate
 * for its public key, verify the PIN, and have the card do a P-256 ECDH.
 *
 * Transport-free: this builds APDUs and parses responses, and [Card] is whatever carries them
 * (NFC IsoDep on Android). Response chaining (SW 61xx) is handled in [transceive].
 */
object Piv {
    class PivException(message: String, val sw: Int = 0) : Exception(message)
    class WrongPinException(val retriesLeft: Int) : Exception(
        if (retriesLeft == 0) "The YubiKey PIN is blocked." else "Wrong PIN, $retriesLeft tries left."
    )
    class PinRequiredException : Exception("This YubiKey slot needs its PIN.")

    fun interface Card {
        /** Send one APDU, return response data followed by the two status bytes. */
        fun transmit(apdu: ByteArray): ByteArray
    }

    const val SW_OK = 0x9000
    const val SW_SECURITY_STATUS = 0x6982
    const val SW_AUTH_BLOCKED = 0x6983
    private const val ALG_ECC_P256 = 0x11

    /**
     * Caps on 61xx GET RESPONSE chaining (audit L-11). The largest PIV object read here is a
     * certificate of a few KiB; a card that keeps answering 61xx, or streams more than this,
     * is broken or hostile and must not hang or exhaust the app.
     */
    const val MAX_RESPONSE_BYTES = 64 * 1024
    const val MAX_CHAINED_RESPONSES = 256

    private val AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x03, 0x08)

    fun select(card: Card) {
        val (_, sw) = transceive(card, apdu(0x00, 0xA4, 0x04, 0x00, AID, le = true))
        if (sw != SW_OK) throw PivException("This isn't a PIV card (select failed, SW %04X).".format(sw), sw)
    }

    /** YubiKey serial number (YubiKey 5 firmware; older keys answer with an error, returned as null). */
    fun serial(card: Card): Long? {
        val (data, sw) = transceive(card, apdu(0x00, 0xF8, 0x00, 0x00, ByteArray(0), le = true))
        if (sw != SW_OK || data.size != 4) return null
        return data.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
    }

    /** Verify [pin] (6 to 8 characters). Throws [WrongPinException] with the tries left. */
    fun verifyPin(card: Card, pin: String) {
        val bytes = pin.toByteArray(Charsets.UTF_8)
        require(bytes.size in 1..8) { "A PIV PIN is 6 to 8 characters." }
        val padded = ByteArray(8) { 0xFF.toByte() }.also { bytes.copyInto(it) }
        val (_, sw) = transceive(card, apdu(0x00, 0x20, 0x00, 0x80, padded, le = false))
        padded.fill(0)
        when {
            sw == SW_OK -> Unit
            sw and 0xFFF0 == 0x63C0 -> throw WrongPinException(sw and 0x0F)
            sw == SW_AUTH_BLOCKED -> throw WrongPinException(0)
            else -> throw PivException("PIN check failed (SW %04X).".format(sw), sw)
        }
    }

    /** The public key in [slot]'s certificate, as a 33-byte compressed point. */
    fun readPublicKey(card: Card, slot: Int): ByteArray {
        val objectId = certObjectId(slot)
        val data = byteArrayOf(0x5C, 0x03) + objectId
        val (resp, sw) = transceive(card, apdu(0x00, 0xCB, 0x3F, 0xFF, data, le = true))
        if (sw != SW_OK) throw PivException("No age key in slot %02X of this YubiKey (SW %04X).".format(slot, sw), sw)
        val outer = Tlv.find(resp, 0x53) ?: throw PivException("Unexpected certificate object layout.")
        val der = Tlv.find(outer, 0x70) ?: throw PivException("Slot %02X holds no certificate.".format(slot))
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        val pub = cert.publicKey as? ECPublicKey ?: throw PivException("Slot %02X key isn't elliptic-curve.".format(slot))
        if (!isP256(pub.params)) throw PivException("Slot %02X key isn't P-256.".format(slot))
        val x = fixed32(pub.w.affineX.toByteArray())
        val y = pub.w.affineY
        val compressed = byteArrayOf(if (y.testBit(0)) 0x03 else 0x02) + x
        // The point itself must be on the curve (decode validates it).
        try {
            P256Curve.decode(compressed)
        } catch (e: Exception) {
            throw PivException("Slot %02X holds an invalid P-256 public key.".format(slot))
        }
        return compressed
    }

    /**
     * True only for secp256r1 itself: same prime field, coefficients, generator, order and
     * cofactor. Checking the field size alone would also accept any other 256-bit curve
     * (secp256k1, brainpoolP256r1), whose points would then be misread as P-256.
     */
    internal fun isP256(spec: ECParameterSpec): Boolean {
        val d = P256Curve.domain
        val field = spec.curve.field as? ECFieldFp ?: return false
        return field.p == d.curve.field.characteristic &&
            spec.curve.a == d.curve.a.toBigInteger() &&
            spec.curve.b == d.curve.b.toBigInteger() &&
            spec.generator.affineX == d.g.affineXCoord.toBigInteger() &&
            spec.generator.affineY == d.g.affineYCoord.toBigInteger() &&
            spec.order == d.n &&
            spec.cofactor.toBigInteger() == d.h
    }

    /**
     * P-256 ECDH on the card with the key in [slot]. [peerUncompressed] is 65 bytes. Returns the
     * 32-byte shared x-coordinate. Throws [PinRequiredException] if the slot's PIN policy wants
     * the PIN first.
     */
    fun ecdh(card: Card, slot: Int, peerUncompressed: ByteArray): ByteArray {
        require(peerUncompressed.size == 65 && peerUncompressed[0] == 0x04.toByte()) { "peer point must be uncompressed" }
        val inner = Tlv.encode(0x82, ByteArray(0)) + Tlv.encode(0x85, peerUncompressed)
        val (resp, sw) = transceive(card, apdu(0x00, 0x87, ALG_ECC_P256, slot, Tlv.encode(0x7C, inner), le = true))
        when (sw) {
            SW_OK -> Unit
            SW_SECURITY_STATUS -> throw PinRequiredException()
            else -> throw PivException("The YubiKey refused the decryption (SW %04X).".format(sw), sw)
        }
        val template = Tlv.find(resp, 0x7C) ?: throw PivException("Unexpected ECDH response.")
        val secret = Tlv.find(template, 0x82) ?: throw PivException("ECDH response had no shared secret.")
        if (secret.size != 32) throw PivException("Unexpected shared secret size ${secret.size}.")
        return secret
    }

    /** Object id of a retired key-management slot's certificate: 82 -> 5FC10D ... 95 -> 5FC120. */
    fun certObjectId(slot: Int): ByteArray {
        require(slot in 0x82..0x95) { "not a retired slot" }
        return byteArrayOf(0x5F, 0xC1.toByte(), (0x0D + (slot - 0x82)).toByte())
    }

    /**
     * Send [command], following 61xx GET RESPONSE chaining. Returns (data, SW). Chaining stops
     * with a [PivException] after [MAX_CHAINED_RESPONSES] rounds or [MAX_RESPONSE_BYTES] bytes.
     */
    fun transceive(card: Card, command: ByteArray): Pair<ByteArray, Int> {
        val acc = ByteArrayOutputStream()
        var r = split(card.transmit(command))
        acc.write(r.first)
        var rounds = 0
        while (r.second shr 8 == 0x61) {
            if (++rounds > MAX_CHAINED_RESPONSES) throw PivException("The card kept chaining its response.")
            val le = r.second and 0xff
            r = split(card.transmit(byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, le.toByte())))
            acc.write(r.first)
            if (acc.size() > MAX_RESPONSE_BYTES) throw PivException("The card's response is too large.")
        }
        if (acc.size() > MAX_RESPONSE_BYTES) throw PivException("The card's response is too large.")
        return acc.toByteArray() to r.second
    }

    /** Short APDU. PIV commands here stay under 256 bytes of data. */
    fun apdu(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Boolean): ByteArray {
        require(data.size <= 255)
        val out = ByteArrayOutputStream()
        out.write(cla); out.write(ins); out.write(p1); out.write(p2)
        if (data.isNotEmpty()) { out.write(data.size); out.write(data) }
        if (le) out.write(0x00)
        return out.toByteArray()
    }

    private fun split(r: ByteArray): Pair<ByteArray, Int> {
        if (r.size < 2) throw PivException("Short response from the card.")
        val sw = ((r[r.size - 2].toInt() and 0xff) shl 8) or (r[r.size - 1].toInt() and 0xff)
        return r.copyOfRange(0, r.size - 2) to sw
    }

    private fun fixed32(b: ByteArray): ByteArray = when {
        b.size == 32 -> b
        b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
        else -> ByteArray(32 - b.size) + b
    }
}

/** BER-TLV with single-byte tags and short/long lengths, as PIV uses. */
object Tlv {
    fun encode(tag: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        when {
            value.size < 0x80 -> out.write(value.size)
            value.size <= 0xff -> { out.write(0x81); out.write(value.size) }
            else -> { out.write(0x82); out.write(value.size shr 8); out.write(value.size and 0xff) }
        }
        out.write(value)
        return out.toByteArray()
    }

    /**
     * Value of the first top-level [tag] in [data], or null if no such tag is present. A
     * truncated or malformed length (including a long-form length whose bytes run past the end)
     * throws [Piv.PivException] instead of indexing out of bounds (audit L-11).
     */
    fun find(data: ByteArray, tag: Int): ByteArray? {
        var i = 0
        while (i < data.size) {
            val t = data[i].toInt() and 0xff
            i++
            if (i >= data.size) throw Piv.PivException("Malformed card response (TLV with no length).")
            var len = data[i].toInt() and 0xff
            i++
            if (len == 0x81) {
                if (i + 1 > data.size) throw Piv.PivException("Malformed card response (truncated TLV length).")
                len = data[i].toInt() and 0xff
                i++
            } else if (len == 0x82) {
                if (i + 2 > data.size) throw Piv.PivException("Malformed card response (truncated TLV length).")
                len = ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)
                i += 2
            } else if (len >= 0x80) {
                throw Piv.PivException("Malformed card response (unsupported TLV length form).")
            }
            if (len > data.size - i) throw Piv.PivException("Malformed card response (TLV runs past the end).")
            if (t == tag) return data.copyOfRange(i, i + len)
            i += len
        }
        return null
    }
}
