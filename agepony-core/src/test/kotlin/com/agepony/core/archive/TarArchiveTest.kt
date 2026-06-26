package com.agepony.core.archive

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test
import java.security.MessageDigest

/**
 * Compact USTAR vectors cross-checked against python tarfile (USTAR) and GNU tar. The
 * reference archive of two fixed files hashes to a known SHA-256, proving byte-for-byte
 * parity with the iOS reference.
 */
class TarArchiveTest {
    private fun sha256(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Test
    fun matchesReferenceArchiveBytes() {
        val archive = TarArchive.create(
            listOf(
                TarArchive.Entry("hello.txt", "Hello, AgePony!\n".toByteArray()),
                TarArchive.Entry("notes.md", "# Notes\nsecond file\n".toByteArray()),
            )
        )
        assertEquals(3072, archive.size)
        assertEquals("7fb5872bf17de060cb7d1ac9f88bb0afb118ca5fde5daf3c4d9fe6a1d0f392bb", sha256(archive))
    }

    @Test
    fun roundTripsBinaryEmptyAndUnaligned() {
        val entries = listOf(
            TarArchive.Entry("a.bin", ByteArray(600) { (it * 3 + 1).toByte() }), // spans two blocks
            TarArchive.Entry("empty.dat", ByteArray(0)),
            TarArchive.Entry("exact.dat", ByteArray(512) { 0x5a }),
        )
        val back = TarArchive.extract(TarArchive.create(entries))
        assertEquals(listOf("a.bin", "empty.dat", "exact.dat"), back.map { it.name })
        for (i in entries.indices) assertArrayEquals(entries[i].data, back[i].data)
    }

    @Test
    fun detectsChecksumTamper() {
        val archive = TarArchive.create(listOf(TarArchive.Entry("x.txt", "payload".toByteArray())))
        archive[105] = (archive[105] + 1).toByte() // flip a byte in the mode field of the first header
        assertThrows<TarArchive.TarException> { TarArchive.extract(archive) }
    }

    @Test
    fun rejectsOverlongName() {
        assertThrows<TarArchive.TarException> {
            TarArchive.create(listOf(TarArchive.Entry("a".repeat(101), ByteArray(1))))
        }
    }
}
