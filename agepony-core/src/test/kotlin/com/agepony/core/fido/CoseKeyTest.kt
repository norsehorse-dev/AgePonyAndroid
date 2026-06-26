package com.agepony.core.fido

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** COSE vectors from python cryptography + cbor2. */
class CoseKeyTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val coseOkp = "a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    private val ed25519Pub = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    private val coseEc2 = "a501020326200121582051590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed225820e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4"
    private val p256X963 = "0451590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ede0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4"

    @Test
    fun decodesEd25519() {
        val d = CoseKey.decodeBytes(unhex(coseOkp))
        assertTrue(d is CoseKey.Decoded.Ed25519)
        assertEquals(ed25519Pub, hex((d as CoseKey.Decoded.Ed25519).raw32))
    }

    @Test
    fun decodesP256() {
        val d = CoseKey.decodeBytes(unhex(coseEc2))
        assertTrue(d is CoseKey.Decoded.P256)
        assertEquals(p256X963, hex((d as CoseKey.Decoded.P256).x963))
    }

    @Test
    fun encodesPlatformEc2WithCanonicalLabels() {
        val x = unhex("51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed")
        val y = unhex("e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4")
        val enc = CoseKey.encodePlatformEc2(x, y) // alg defaults to ECDH-ES+HKDF-256 (-25)
        val m = Cbor.asMap(Cbor.decode(enc))
        assertEquals(CoseKey.KTY_EC2, Cbor.asLong(m[CoseKey.KTY]))
        assertEquals(CoseKey.ALG_ECDH_HKDF256, Cbor.asLong(m[CoseKey.ALG]))
        assertEquals(CoseKey.CRV_P256, Cbor.asLong(m[CoseKey.CRV]))
        assertArrayEquals32(x, Cbor.asBytes(m[CoseKey.X]))
        assertArrayEquals32(y, Cbor.asBytes(m[CoseKey.Y]))
        // re-encoding the decoded map reproduces the same canonical bytes
        assertEquals(hex(enc), hex(Cbor.encode(m)))
    }

    private fun assertArrayEquals32(expected: ByteArray, actual: ByteArray) =
        assertEquals(hex(expected), hex(actual))
}
