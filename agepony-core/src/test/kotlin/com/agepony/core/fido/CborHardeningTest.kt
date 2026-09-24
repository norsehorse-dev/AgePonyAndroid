package com.agepony.core.fido

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * CBOR from an NFC authenticator is attacker-controlled (audit L-11). Every malformed input
 * must end in a [Cbor.CborException], never an OutOfMemoryError or StackOverflowError.
 */
class CborHardeningTest {
    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private fun rejects(input: ByteArray, what: String) {
        assertThrows(Cbor.CborException::class.java, { Cbor.decode(input) }, what)
    }

    @Test
    fun hugeDeclaredLengthsAreRefusedBeforeAllocation() {
        rejects(bytes(0x9a, 0x80, 0x00, 0x00, 0x00), "array of 2^31 items")
        rejects(bytes(0x9a, 0x7f, 0xff, 0xff, 0xff, 0x00), "array of 2^31-1 items with one byte")
        rejects(bytes(0x9b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00), "array of 2^32 items")
        rejects(bytes(0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), "array of 2^64-1 items")
        rejects(bytes(0xba, 0x40, 0x00, 0x00, 0x00, 0x01, 0x02), "map of 2^30 entries")
        rejects(bytes(0xa2, 0x01, 0x02), "map short by one entry")
        rejects(bytes(0x5a, 0x7f, 0xff, 0xff, 0xff), "byte string of 2^31-1 bytes")
        rejects(bytes(0x5b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00), "byte string over Int.MAX")
        rejects(bytes(0x7b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), "text string of 2^63-1 bytes")
        rejects(bytes(0x9f), "indefinite-length array")
        rejects(bytes(0x1c), "reserved additional info")
    }

    @Test
    fun deepNestingIsCapped() {
        val ok = ByteArray(Cbor.MAX_DEPTH) { 0x81.toByte() } + byteArrayOf(0x00)
        var v: Any? = Cbor.decode(ok)
        var depth = 0
        while (v is List<*>) { v = v[0]; depth++ }
        assertEquals(Cbor.MAX_DEPTH, depth)

        rejects(ByteArray(Cbor.MAX_DEPTH + 1) { 0x81.toByte() } + byteArrayOf(0x00), "one level too deep")
        rejects(ByteArray(100_000) { 0x81.toByte() } + byteArrayOf(0x00), "stack bomb of arrays")
        rejects(ByteArray(100_000) { if (it % 2 == 0) 0xa1.toByte() else 0x01 } + byteArrayOf(0x00), "stack bomb of maps")
    }

    @Test
    fun normalResponsesStillDecode() {
        val m = mapOf(1 to "fido", 2 to byteArrayOf(1, 2, 3), 3 to listOf(1, -2, true, null))
        val back = Cbor.asMap(Cbor.decode(Cbor.encode(m)))
        assertEquals("fido", back[1L])
        assertEquals(listOf(1L, -2L, true, null), back[3L])
    }
}
