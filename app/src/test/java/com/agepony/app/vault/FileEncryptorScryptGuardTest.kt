package com.agepony.app.vault

import com.agepony.core.Age
import com.agepony.core.recipients.ScryptRecipient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Issue #12: a passphrase decrypt must be refused before scrypt allocates, whenever the file's
 * work factor would need more memory than the device has. These cover the pure pieces of that
 * guard, so the decision can be verified without controlling the real heap.
 */
class FileEncryptorScryptGuardTest {

    @Test
    fun readsWorkFactorFromPassphraseFile() {
        val ct = Age.encrypt("hello".toByteArray(), listOf(ScryptRecipient("pw", 16)))
        assertEquals(16, FileEncryptor.scryptWorkFactorOf(ct))
    }

    @Test
    fun readsADifferentWorkFactor() {
        val ct = Age.encrypt("hello".toByteArray(), listOf(ScryptRecipient("pw", 17)))
        assertEquals(17, FileEncryptor.scryptWorkFactorOf(ct))
    }

    @Test
    fun returnsNullForNonAgeInput() {
        assertNull(FileEncryptor.scryptWorkFactorOf("not an age file".toByteArray()))
    }

    @Test
    fun memoryBytesMatchScryptFormula() {
        // 128 * N * r, r = 8: 256 MiB at 2^18, 1 GiB at 2^20.
        assertEquals(256L shl 20, FileEncryptor.scryptMemoryBytes(18))
        assertEquals(1L shl 30, FileEncryptor.scryptMemoryBytes(20))
    }

    @Test
    fun fitPredicateAllowsWhatFits() {
        // 2^16 needs 64 MiB, plus 32 MiB headroom = 96 MiB.
        assertTrue(FileEncryptor.scryptFitsIn(16, 200L * 1024 * 1024))
    }

    @Test
    fun fitPredicateRefusesWhatDoesNot() {
        // 2^20 needs 1 GiB; 200 MiB free is not enough (this is the aesop.age case, rage picked 20).
        assertFalse(FileEncryptor.scryptFitsIn(20, 200L * 1024 * 1024))
        // Even 2^16 is refused when almost nothing is free.
        assertFalse(FileEncryptor.scryptFitsIn(16, 50L * 1024 * 1024))
    }
}
