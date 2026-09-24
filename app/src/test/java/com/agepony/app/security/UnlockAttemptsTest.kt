package com.agepony.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * The persisted failed-attempt counter behind the app password (audit M-1): the backoff
 * schedule, persistence across process death, and that neither a reboot nor a corrupt
 * file shortens a wait it shouldn't.
 */
class UnlockAttemptsTest {

    private val dir: File = Files.createTempDirectory("attempts").toFile()
    private val file = File(dir, "unlock.attempts")
    private var now = 1_000_000L
    private var boot = 7

    private fun counter() = UnlockAttempts(file, { now }, { boot })

    @Test
    fun scheduleIsFreeThenThirtySecondsDoublingToAnHour() {
        for (n in 0 until UnlockAttempts.BACKOFF_AFTER) assertEquals(0L, UnlockAttempts.lockoutFor(n))
        assertEquals(30_000L, UnlockAttempts.lockoutFor(5))
        assertEquals(60_000L, UnlockAttempts.lockoutFor(6))
        assertEquals(120_000L, UnlockAttempts.lockoutFor(7))
        assertEquals(1_920_000L, UnlockAttempts.lockoutFor(11))
        assertEquals(3_600_000L, UnlockAttempts.lockoutFor(12))
        assertEquals(3_600_000L, UnlockAttempts.lockoutFor(10_000))
    }

    @Test
    fun noWaitBeforeTheFifthWrongAttempt() {
        val c = counter()
        repeat(4) { c.recordAttempt() }
        assertEquals(0L, c.remainingLockoutMillis())
        assertEquals(5, c.recordAttempt())
        assertEquals(30_000L, c.remainingLockoutMillis())
        now += 10_000L
        assertEquals(20_000L, c.remainingLockoutMillis())
        now += 20_000L
        assertEquals(0L, c.remainingLockoutMillis())
    }

    @Test
    fun theCountSurvivesANewProcess() {
        val c = counter()
        repeat(6) { c.recordAttempt() }
        now += 5_000L
        val next = counter()
        assertEquals(6, next.failures())
        assertEquals(55_000L, next.remainingLockoutMillis())
    }

    @Test
    fun aRebootRestartsTheWaitInsteadOfEndingIt() {
        val c = counter()
        repeat(5) { c.recordAttempt() }
        // After a reboot elapsedRealtime starts again near zero and the boot count moves on.
        now = 2_000L
        boot = 8
        val afterReboot = counter()
        assertEquals(30_000L, afterReboot.remainingLockoutMillis())
    }

    @Test
    fun aClockBehindTheLastAttemptCountsAsAReboot() {
        boot = -1 // boot count unavailable on this device
        val c = counter()
        repeat(5) { c.recordAttempt() }
        now = 500L
        assertEquals(30_000L, counter().remainingLockoutMillis())
    }

    @Test
    fun resetForgetsEverything() {
        val c = counter()
        repeat(7) { c.recordAttempt() }
        c.reset()
        assertEquals(0, c.failures())
        assertEquals(0L, c.remainingLockoutMillis())
        assertFalse(file.exists())
        assertEquals(0, counter().failures())
    }

    @Test
    fun aCorruptFileReadsAsNoAttempts() {
        file.writeText("garbage")
        val c = counter()
        assertEquals(0, c.failures())
        assertEquals(1, c.recordAttempt())
        assertTrue(file.readText().startsWith("a1 1 "))
    }

    @Test
    fun waitsAreDescribedRoundedUp() {
        assertEquals("30 seconds", UnlockAttempts.describeWait(29_001L))
        assertEquals("1 second", UnlockAttempts.describeWait(1L))
        assertEquals("2 minutes", UnlockAttempts.describeWait(120_000L))
        assertEquals("1 hour", UnlockAttempts.describeWait(3_600_000L))
    }
}
