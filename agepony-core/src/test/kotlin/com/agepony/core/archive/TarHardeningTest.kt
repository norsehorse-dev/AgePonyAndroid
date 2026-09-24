package com.agepony.core.archive

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream

/** Tar entries that are not plain files, or sizes that do not fit, are refused. */
class TarHardeningTest {

    /** A one-entry archive with header byte edits applied and the checksum recomputed. */
    private fun archive(data: ByteArray = "hello".toByteArray(), edit: (ByteArray) -> Unit): ByteArray {
        val tar = TarArchive.create(listOf(TarArchive.Entry("a.txt", data)))
        val h = tar.copyOfRange(0, 512)
        edit(h)
        for (i in 148..155) h[i] = ' '.code.toByte()
        val sum = h.sumOf { it.toInt() and 0xff }
        val cs = Integer.toOctalString(sum).padStart(6, '0')
        for (i in 0 until 6) h[148 + i] = cs[i].code.toByte()
        h[154] = 0
        h[155] = ' '.code.toByte()
        System.arraycopy(h, 0, tar, 0, 512)
        return tar
    }

    private fun setSize(h: ByteArray, octal: String) {
        for (i in 124 until 136) h[i] = 0
        for (i in octal.indices) h[124 + i] = octal[i].code.toByte()
    }

    @Test
    fun sizeAboveIntMaxIsRefusedNotTruncated() {
        // 2^32 + 5 truncates to 5 with toInt(), so the old reader "extracted" 5 bytes.
        val tar = archive { setSize(it, java.lang.Long.toOctalString((1L shl 32) + 5).padStart(11, '0')) }
        assertThrows(TarArchive.TarException::class.java) { TarArchive.extract(tar) }
        assertThrows(TarArchive.TarException::class.java) {
            TarArchive.forEachEntry(ByteArrayInputStream(tar)) { _, _, d -> d.readBytes() }
        }
        val huge = archive { setSize(it, "77777777777") }
        assertThrows(TarArchive.TarException::class.java) { TarArchive.extract(huge) }
    }

    @Test
    fun onlyRegularFileEntriesAreAccepted() {
        for (flag in listOf('5', '2', '1', 'x', 'g', 'L', 'K', '3', '4', '6', '7')) {
            val tar = archive { it[156] = flag.code.toByte() }
            assertThrows(TarArchive.TarException::class.java, { TarArchive.extract(tar) }, "typeflag $flag")
            assertThrows(TarArchive.TarException::class.java, {
                TarArchive.forEachEntry(ByteArrayInputStream(tar)) { _, _, _ -> }
            }, "typeflag $flag (stream)")
            assertFalse(TarArchive.looksLikeTar(tar), "typeflag $flag looked like a tar")
        }
        // Pre-POSIX NUL typeflag is a regular file.
        val old = archive { it[156] = 0 }
        val entries = TarArchive.extract(old)
        assertEquals(1, entries.size)
        assertArrayEquals("hello".toByteArray(), entries[0].data)
    }
}
