package com.agepony.core.piv

import com.agepony.core.crypto.P256Curve
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve

/** A hostile card must not hang or crash the PIV layer (audit L-11). */
class PivHardeningTest {
    private fun sw(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())

    @Test
    fun endlessChainingIsCapped() {
        var calls = 0
        val emptyForever = Piv.Card { calls++; sw(0x6100) }
        assertThrows(Piv.PivException::class.java) { Piv.transceive(emptyForever, byteArrayOf(0, 0xCB.toByte(), 0x3F, 0xFF.toByte())) }
        assertTrue(calls <= Piv.MAX_CHAINED_RESPONSES + 1, "made $calls calls")

        val floodForever = Piv.Card { ByteArray(256) + sw(0x6100) }
        assertThrows(Piv.PivException::class.java) { Piv.transceive(floodForever, byteArrayOf(0, 0xCB.toByte(), 0x3F, 0xFF.toByte())) }

        // Ordinary chaining still assembles the whole response.
        var n = 0
        val threeParts = Piv.Card { n++; if (n < 3) ByteArray(10) { n.toByte() } + sw(0x610A) else ByteArray(5) + sw(0x9000) }
        val (data, status) = Piv.transceive(threeParts, byteArrayOf(0, 0xCB.toByte(), 0x3F, 0xFF.toByte()))
        assertEquals(25, data.size)
        assertEquals(Piv.SW_OK, status)
    }

    @Test
    fun malformedTlvThrowsPivException() {
        val bad = listOf(
            byteArrayOf(0x53),                               // tag with no length
            byteArrayOf(0x53, 0x81.toByte()),                // long form, no length byte
            byteArrayOf(0x53, 0x82.toByte(), 0x01),          // long form, one of two length bytes
            byteArrayOf(0x53, 0x05, 1, 2),                   // value runs past the end
            byteArrayOf(0x53, 0x82.toByte(), 0x7F, 0xFF.toByte(), 1), // 32 KiB claimed, 1 byte present
            byteArrayOf(0x53, 0x83.toByte(), 0, 0, 1, 0),    // unsupported length form
            byteArrayOf(0x53, 0x80.toByte()),                // indefinite length
        )
        for (b in bad) assertThrows(Piv.PivException::class.java) { Tlv.find(b, 0x70) }

        val good = Tlv.encode(0x71, byteArrayOf(9)) + Tlv.encode(0x70, ByteArray(300) { 7 })
        assertArrayEquals(ByteArray(300) { 7 }, Tlv.find(good, 0x70))
        assertNull(Tlv.find(good, 0x72))
    }

    @Test
    fun onlySecp256r1IsAcceptedAsP256() {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
        assertTrue(Piv.isP256(params.getParameterSpec(ECParameterSpec::class.java)))

        // secp256k1: also a 256-bit prime field, so a field-size check alone accepted it.
        val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
        val k1 = ECParameterSpec(
            EllipticCurve(ECFieldFp(p), BigInteger.ZERO, BigInteger.valueOf(7)),
            ECPoint(
                BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
                BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16),
            ),
            BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),
            1,
        )
        assertFalse(Piv.isP256(k1))

        // P-256 with one parameter changed.
        val d = P256Curve.domain
        val tweaked = ECParameterSpec(
            EllipticCurve(ECFieldFp(d.curve.field.characteristic), d.curve.a.toBigInteger(), d.curve.b.toBigInteger().add(BigInteger.ONE)),
            ECPoint(d.g.affineXCoord.toBigInteger(), d.g.affineYCoord.toBigInteger()),
            d.n,
            1,
        )
        assertFalse(Piv.isP256(tweaked))
    }
}
