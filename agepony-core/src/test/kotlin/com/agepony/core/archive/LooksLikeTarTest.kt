package com.agepony.core.archive

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * looksLikeTar is the cheap sniff DecryptFlow uses to decide whether a decrypted
 * payload is a multi-file bundle worth offering to extract.
 */
class LooksLikeTarTest {

    @Test
    fun trueForRealArchiveHeader() {
        val archive = TarArchive.create(
            listOf(
                TarArchive.Entry("a.txt", "hello".toByteArray()),
                TarArchive.Entry("b.bin", ByteArray(1000)),
            ),
        )
        assertTrue(TarArchive.looksLikeTar(archive))
        // A caller may hand it exactly one block, too.
        assertTrue(TarArchive.looksLikeTar(archive.copyOfRange(0, TarArchive.BLOCK_SIZE)))
    }

    @Test
    fun falseForRandomBytes() {
        val junk = ByteArray(TarArchive.BLOCK_SIZE) { (it * 31 + 7).toByte() }
        assertFalse(TarArchive.looksLikeTar(junk))
    }

    @Test
    fun falseForAllZeroBlock() {
        assertFalse(TarArchive.looksLikeTar(ByteArray(TarArchive.BLOCK_SIZE)))
    }

    @Test
    fun falseForShortInput() {
        assertFalse(TarArchive.looksLikeTar(ByteArray(10)))
        assertFalse(TarArchive.looksLikeTar(ByteArray(0)))
    }
}
