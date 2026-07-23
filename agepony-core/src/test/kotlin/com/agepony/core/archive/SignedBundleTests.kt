package com.agepony.core.archive

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class SignedBundleTests {
    private val sig = "-----BEGIN SSH SIGNATURE-----\nAAAAB2FnZQ==\n-----END SSH SIGNATURE-----\n"

    @Test
    fun buildParseRoundTrips() {
        val payload = "hello post-quantum age\n".toByteArray()
        val bundle = SignedBundle.build("note.txt", payload, sig)
        val parsed = SignedBundle.parse(bundle)
        requireNotNull(parsed)
        assertEquals("note.txt", parsed.name)
        assertArrayEquals(payload, parsed.payload)
        assertEquals(sig, parsed.signatureArmored)
    }

    @Test
    fun firstEntryIsTheMarker() {
        val bundle = SignedBundle.build("a.bin", byteArrayOf(1, 2, 3), sig)
        val entries = TarArchive.extract(bundle)
        assertEquals(SignedBundle.MARKER, entries[0].name)
        assertEquals(3, entries.size)
    }

    @Test
    fun preservesBinaryPayloadAcrossBlockBoundaries() {
        val payload = ByteArray(1000) { (it % 256).toByte() } // spans multiple 512B blocks
        val parsed = SignedBundle.parse(SignedBundle.build("big.dat", payload, sig))
        requireNotNull(parsed)
        assertArrayEquals(payload, parsed.payload)
    }

    @Test
    fun parseReturnsNullForPlainFile() {
        assertNull(SignedBundle.parse("just some text, not a tar".toByteArray()))
    }

    @Test
    fun parseReturnsNullForOrdinaryTarBundle() {
        val tar = TarArchive.create(
            listOf(
                TarArchive.Entry("a.txt", "A".toByteArray()),
                TarArchive.Entry("b.txt", "B".toByteArray()),
            )
        )
        assertNull(SignedBundle.parse(tar))
    }
}
