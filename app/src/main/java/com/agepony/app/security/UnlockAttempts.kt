package com.agepony.app.security

import java.io.File

/** Result of an in-app check of the app password (see Vault.verifyAppPassword). */
sealed class PasswordCheck {
    object Ok : PasswordCheck()
    object Wrong : PasswordCheck()
    class LockedOut(val remainingMillis: Long) : PasswordCheck()
}

/**
 * Persisted failed-attempt counter for the app password/PIN (audit M-1).
 *
 * After [BACKOFF_AFTER] wrong attempts in a row every further try waits: 30 s, then
 * doubling, capped at one hour. A success resets it. The duress secret counts as a success
 * (its wipe resets the counter too), so the counter never tells a decoy from the real thing.
 *
 * Stored in the vault directory (filesDir/vault/unlock.attempts) rather than
 * noBackupFilesDir: it lives and dies with the blobs it protects, Vault.reset clears it with
 * them, and the vault/ backup and device-transfer exclusion already covers it. Survives
 * process death, which is the point: an attempt is counted before it is checked
 * ([recordAttempt]), so killing the app mid-attempt doesn't make a guess free.
 *
 * Time is SystemClock.elapsedRealtime, not the wall clock, so changing the date doesn't
 * skip a wait. elapsedRealtime restarts at boot, so a reboot (detected by the boot count,
 * or by the clock being behind the last attempt) restarts the current wait rather than
 * ending it. That check runs once per process, when the file is first read, since a reboot
 * always starts a new process.
 *
 * Pure JVM apart from the injected clock and boot count, so it is unit-tested directly.
 */
class UnlockAttempts(
    private val file: File,
    private val elapsedNow: () -> Long,
    private val bootCount: () -> Int,
) {
    private var loaded = false
    private var failures = 0
    private var lastAttemptAt = 0L
    private var boot = -1

    /** Attempts counted since the last success (including one in progress). */
    @Synchronized
    fun failures(): Int {
        load()
        return failures
    }

    /** Milliseconds until the next attempt is allowed; 0 when it may go ahead now. */
    @Synchronized
    fun remainingLockoutMillis(): Long {
        load()
        val wait = lockoutFor(failures)
        if (wait == 0L) return 0L
        return (lastAttemptAt + wait - elapsedNow()).coerceIn(0L, wait)
    }

    /**
     * Count one attempt, before it is checked, and persist it. Returns the new count. A
     * success must follow with [reset].
     */
    @Synchronized
    fun recordAttempt(): Int {
        load()
        failures = (failures + 1).coerceAtMost(MAX_COUNT)
        lastAttemptAt = elapsedNow()
        boot = bootCount()
        save()
        return failures
    }

    /** Forget every counted attempt (a success, a reset, or a wipe). */
    @Synchronized
    fun reset() {
        failures = 0
        lastAttemptAt = 0L
        boot = -1
        loaded = true
        file.delete()
    }

    private fun load() {
        if (loaded) return
        loaded = true
        val parts = runCatching { file.readText().trim().split(' ') }.getOrNull()
        if (parts == null || parts.size != 4 || parts[0] != FORMAT) return
        failures = parts[1].toIntOrNull()?.coerceIn(0, MAX_COUNT) ?: return
        lastAttemptAt = parts[2].toLongOrNull() ?: 0L
        boot = parts[3].toIntOrNull() ?: -1
        if (failures == 0) return
        val now = elapsedNow()
        val currentBoot = bootCount()
        val rebooted = now < lastAttemptAt || (boot >= 0 && currentBoot >= 0 && boot != currentBoot)
        if (rebooted) {
            lastAttemptAt = now
            boot = currentBoot
            save()
        }
    }

    private fun save() {
        runCatching {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText("$FORMAT $failures $lastAttemptAt $boot\n")
            if (!tmp.renameTo(file)) {
                file.writeText("$FORMAT $failures $lastAttemptAt $boot\n")
                tmp.delete()
            }
        }
    }

    companion object {
        /** Wrong attempts allowed before waits begin. */
        const val BACKOFF_AFTER = 5

        /** Wrong attempts after which the optional erase setting wipes the vault. */
        const val ERASE_AFTER = 10

        private const val FIRST_WAIT_MILLIS = 30_000L
        private const val MAX_WAIT_MILLIS = 60L * 60L * 1000L
        private const val MAX_COUNT = 10_000
        private const val FORMAT = "a1"

        /** The wait imposed after [failures] wrong attempts: 0, then 30 s doubling up to 1 h. */
        fun lockoutFor(failures: Int): Long {
            if (failures < BACKOFF_AFTER) return 0L
            val doublings = (failures - BACKOFF_AFTER).coerceAtMost(10)
            return (FIRST_WAIT_MILLIS shl doublings).coerceAtMost(MAX_WAIT_MILLIS)
        }

        /** "30 seconds", "4 minutes", "1 hour": a wait for display, rounded up. */
        fun describeWait(millis: Long): String {
            val seconds = ((millis + 999L) / 1000L).coerceAtLeast(1L)
            return when {
                seconds < 90L -> if (seconds == 1L) "1 second" else "$seconds seconds"
                seconds < 3600L -> "${(seconds + 59L) / 60L} minutes"
                else -> "1 hour"
            }
        }

        /** The message shown when an attempt is refused because of the backoff. */
        fun lockoutMessage(millis: Long): String =
            "Too many wrong attempts. Try again in ${describeWait(millis)}."
    }
}
