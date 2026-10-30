package com.agepony.app.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** The cache sweep behind iOS 5.1.1 M-2's Android check: staging plaintext never outlives a lock. */
class TempFilesTest {

    @Test
    fun sweepRemovesPrefixedEntriesAndKeepsOthers() {
        val dir = Files.createTempDirectory("tempfiles-test").toFile()
        try {
            val staged = File(dir, TempFiles.PREFIX + "stage123.tmp").apply { writeText("plaintext") }
            val nested = File(dir, TempFiles.PREFIX + "batch").apply { mkdirs() }
            File(nested, "inner.txt").writeText("plaintext")
            val other = File(dir, "image_cache").apply { writeText("keep") }

            TempFiles.sweepDir(dir)

            assertFalse(staged.exists())
            assertFalse(nested.exists())
            assertTrue(other.exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun sweepDoesNotFollowALinkOutOfTheCache() {
        val dir = Files.createTempDirectory("tempfiles-test").toFile()
        val outside = Files.createTempDirectory("tempfiles-outside").toFile()
        try {
            val keep = File(outside, "keep.txt").apply { writeText("keep") }
            val link = File(dir, TempFiles.PREFIX + "link")
            Files.createSymbolicLink(link.toPath(), outside.toPath())

            TempFiles.sweepDir(dir)

            assertFalse(Files.exists(link.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS))
            assertTrue(keep.exists())
        } finally {
            dir.deleteRecursively()
            outside.deleteRecursively()
        }
    }
}
