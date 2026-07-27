package com.agepony.core.archive

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertThrows
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Random

/**
 * Streaming tar must produce archives byte-identical to [TarArchive.create] and read them back
 * without materializing them, so a multi-file encrypt never holds every input at once.
 */
class TarArchiveStreamTests {

    private fun data(n: Int, seed: Long): ByteArray =
        ByteArray(n).also { Random(seed).nextBytes(it) }

    private val entries = listOf(
        TarArchive.Entry("a.txt", "hello".toByteArray()),
        TarArchive.Entry("b.bin", ByteArray(1000).also { Random(2).nextBytes(it) }),
        TarArchive.Entry("c-empty", ByteArray(0)),
        TarArchive.Entry("d-exact-block.bin", ByteArray(512).also { Random(3).nextBytes(it) }),
    )

    private fun streamedArchive(): ByteArray {
        val out = ByteArrayOutputStream()
        for (e in entries) TarArchive.writeEntry(out, e.name, e.data.size.toLong(), ByteArrayInputStream(e.data))
        TarArchive.finish(out)
        return out.toByteArray()
    }

    @Test
    fun writeEntryFromStream_matchesCreate() {
        assertArrayEquals(TarArchive.create(entries), streamedArchive())
    }

    @Test
    fun writeEntryFromBytes_matchesCreate() {
        val out = ByteArrayOutputStream()
        for (e in entries) TarArchive.writeEntry(out, e.name, e.data)
        TarArchive.finish(out)
        assertArrayEquals(TarArchive.create(entries), out.toByteArray())
    }

    @Test
    fun forEachEntry_readsWhatExtractReads() {
        val archive = TarArchive.create(entries)
        val seen = ArrayList<Pair<String, ByteArray>>()
        TarArchive.forEachEntry(ByteArrayInputStream(archive)) { name, size, data ->
            val body = data.readBytes()
            assertEquals(size, body.size.toLong(), "declared size differs from body for '$name'")
            seen.add(name to body)
        }
        assertEquals(entries.size, seen.size)
        for (i in entries.indices) {
            assertEquals(entries[i].name, seen[i].first)
            assertArrayEquals(entries[i].data, seen[i].second)
        }
    }

    @Test
    fun forEachEntry_survivesUnreadAndPartiallyReadBodies() {
        val archive = TarArchive.create(entries)

        val skipped = ArrayList<String>()
        TarArchive.forEachEntry(ByteArrayInputStream(archive)) { name, _, _ -> skipped.add(name) }
        assertEquals(entries.map { it.name }, skipped)

        val partial = ArrayList<String>()
        TarArchive.forEachEntry(ByteArrayInputStream(archive)) { name, _, body ->
            body.read(ByteArray(3))
            partial.add(name)
        }
        assertEquals(entries.map { it.name }, partial)
    }

    @Test
    fun writeEntry_rejectsSizeMismatches() {
        assertThrows(TarArchive.TarException::class.java) {
            TarArchive.writeEntry(ByteArrayOutputStream(), "short", 100L, ByteArrayInputStream(data(10, 1)))
        }
        assertThrows(TarArchive.TarException::class.java) {
            TarArchive.writeEntry(ByteArrayOutputStream(), "long", 5L, ByteArrayInputStream(data(10, 1)))
        }
        // Non-strict is for streams that carry further entries; extra bytes are left alone.
        TarArchive.writeEntry(ByteArrayOutputStream(), "long", 5L, ByteArrayInputStream(data(10, 1)), strict = false)
    }

    @Test
    fun forEachEntry_rejectsCorruptHeaders() {
        val archive = TarArchive.create(entries)

        val badChecksum = archive.copyOf()
        badChecksum[150] = 'X'.code.toByte()
        assertThrows(TarArchive.TarException::class.java) {
            TarArchive.forEachEntry(ByteArrayInputStream(badChecksum)) { _, _, _ -> }
        }

        assertThrows(TarArchive.TarException::class.java) {
            TarArchive.forEachEntry(ByteArrayInputStream(data(4096, 9))) { _, _, _ -> }
        }

        assertThrows(TarArchive.TarException::class.java) {
            TarArchive.forEachEntry(ByteArrayInputStream(archive.copyOfRange(0, 300))) { _, _, _ -> }
        }
    }
}
