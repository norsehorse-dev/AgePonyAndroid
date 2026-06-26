package com.agepony.core.fido

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/** Vectors from python cbor2 (canonical=True), the CTAP2 canonical reference. */
class CborTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun encodesIntegersCanonically() {
        assertEquals("00", hex(Cbor.encode(0)))
        assertEquals("17", hex(Cbor.encode(23)))
        assertEquals("1818", hex(Cbor.encode(24)))
        assertEquals("18ff", hex(Cbor.encode(255)))
        assertEquals("190100", hex(Cbor.encode(256)))
        assertEquals("1a000f4240", hex(Cbor.encode(1000000)))
        assertEquals("20", hex(Cbor.encode(-1)))
        assertEquals("37", hex(Cbor.encode(-24)))
        assertEquals("3818", hex(Cbor.encode(-25)))
    }

    @Test
    fun encodesStringsBytesArrays() {
        assertEquals("43010203", hex(Cbor.encode(byteArrayOf(1, 2, 3))))
        assertEquals("67616765706f6e79", hex(Cbor.encode("agepony")))
        assertEquals("83010203", hex(Cbor.encode(listOf(1, 2, 3))))
        assertEquals("83f5f4f6", hex(Cbor.encode(listOf(true, false, null))))
    }

    @Test
    fun sortsMapKeysCanonically() {
        val m = linkedMapOf<Any, Any?>(3 to "c", 1 to "a", 2 to "b")
        assertEquals("a3016161026162036163", hex(Cbor.encode(m)))
        // length-first: key 1 (1 byte), 24 (2 bytes), 256 (3 bytes)
        val mixed = linkedMapOf<Any, Any?>(256 to "big", 1 to "one", 24 to "two")
        assertEquals("a301636f6e6518186374776f19010063626967", hex(Cbor.encode(mixed)))
    }

    @Test
    fun decodeRoundTrips() {
        val m = linkedMapOf<Any, Any?>(
            1 to byteArrayOf(9, 9), 2 to "x", 3 to listOf(1, 2), 4 to true, 5 to null
        )
        val dec = Cbor.asMap(Cbor.decode(Cbor.encode(m)))
        assertArrayEquals(byteArrayOf(9, 9), Cbor.asBytes(dec[1L]))
        assertEquals("x", Cbor.asText(dec[2L]))
        assertEquals(listOf(1L, 2L), dec[3L])
        assertEquals(true, dec[4L])
        assertNull(dec[5L])
        assertEquals(7L, Cbor.asLong(Cbor.decode(Cbor.encode(7))))
        assertEquals(-25L, Cbor.decode(Cbor.encode(-25)))
        assertArrayEquals(unhex("010203"), Cbor.asBytes(Cbor.decode(unhex("43010203"))))
    }
}
