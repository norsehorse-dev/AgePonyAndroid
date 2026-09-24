package com.agepony.app.security

import android.app.Activity
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Looper
import android.os.SystemClock
import androidx.core.content.ContextCompat
import com.agepony.app.vault.SharedVault
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * The one background auto-lock timer, owned by the process rather than any activity
 * (audit H-3).
 *
 * The timer used to live in an activity's ViewModel. Finishing ShareActivity (or Back out
 * of MainActivity on API 30 and lower) cleared that ViewModel and cancelled the pending
 * lock, so the process-wide vault stayed open until the process died. Now:
 *   - started activities are counted through ActivityLifecycleCallbacks; when the count
 *     reaches 0 the lock is scheduled after the grace period on a process-lifetime scope,
 *     and an activity starting again cancels it;
 *   - an unlock that completes with nothing on screen schedules the same lock;
 *   - ACTION_SCREEN_OFF makes sure a lock is scheduled on the same grace period, even in
 *     the odd case where the screen goes off without our activity stopping. It does not
 *     lock at once: a long encrypt or decrypt with the screen timing out would otherwise
 *     be cut off after a few seconds, where 5.0.0 gave it the grace period;
 *   - while a system picker round trip is exempt (Vault.autoLockSuppressed) the lock is
 *     still scheduled, after max(grace, 5 minutes) (audit M-4).
 *
 * The coroutine delay runs on the main looper, which doesn't advance in deep sleep or
 * while the process is frozen, so the deadline is also kept in elapsedRealtime and checked
 * when an activity starts: an overdue lock happens before anything is shown.
 *
 * Main thread only, except [lockNow], which the Vault's own lock makes safe anywhere.
 */
object AutoLock {

    /** Upper bound on the picker exemption (audit M-4). */
    private const val SUPPRESSED_LOCK_MILLIS = 5L * 60L * 1000L

    /**
     * Least wait for a lock scheduled because an unlock finished with nothing on screen. A
     * system credential screen can briefly stop our activity mid-unlock; this keeps a
     * zero grace period from re-locking the vault before the activity comes back.
     */
    private const val UNLOCKED_IN_BACKGROUND_MILLIS = 5_000L

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private var app: Application? = null
    private var startedActivities = 0
    private var pendingLock: Job? = null
    private var lockDeadline = 0L

    /** Register the lifecycle callbacks and screen-off receiver. Called once from Application.onCreate. */
    fun install(application: Application) {
        if (app != null) return
        app = application
        application.registerActivityLifecycleCallbacks(callbacks)
        // ACTION_SCREEN_OFF is a protected system broadcast and can only be registered at
        // runtime. Not exported: nothing but the system should be able to reach it.
        ContextCompat.registerReceiver(
            application,
            screenOffReceiver,
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        SharedVault.get(application).onUnlocked = {
            scope.launch {
                if (startedActivities == 0 && pendingLock == null) scheduleLock(UNLOCKED_IN_BACKGROUND_MILLIS)
            }
        }
    }

    /** Lock the vault now and drop any pending timer. The single entry point for "lock". */
    fun lockNow(context: Context) {
        if (Looper.myLooper() == Looper.getMainLooper()) cancelPending() else scope.launch { cancelPending() }
        SharedVault.get(context).lock()
    }

    /**
     * A ViewModel was cleared (its activity finished). If nothing is on screen and no lock
     * is pending, make sure one is: belt and braces for H-3, since onStop already schedules.
     */
    fun onViewModelCleared() {
        if (app == null) return
        if (startedActivities == 0 && pendingLock == null) scheduleLock()
    }

    private fun scheduleLock(minWaitMillis: Long = 0L) {
        val context = app ?: return
        val vault = SharedVault.get(context)
        cancelPending()
        val graceMillis = maxOf(vault.autoLockGraceSeconds.coerceAtLeast(0) * 1000L, minWaitMillis)
        val waitMillis = if (vault.autoLockSuppressed) maxOf(graceMillis, SUPPRESSED_LOCK_MILLIS) else graceMillis
        if (waitMillis == 0L) {
            vault.lock()
            return
        }
        lockDeadline = SystemClock.elapsedRealtime() + waitMillis
        pendingLock = scope.launch {
            delay(waitMillis)
            pendingLock = null
            lockDeadline = 0L
            vault.lock()
        }
    }

    private fun cancelPending() {
        pendingLock?.cancel()
        pendingLock = null
        lockDeadline = 0L
    }

    private val callbacks = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityStarted(activity: Activity) {
            startedActivities++
            if (startedActivities == 1) {
                val overdue = lockDeadline != 0L && SystemClock.elapsedRealtime() >= lockDeadline
                cancelPending()
                val vault = SharedVault.get(activity)
                if (overdue) vault.lock()
                // Back in the foreground: any picker round trip is over.
                vault.autoLockSuppressed = false
            }
        }

        override fun onActivityResumed(activity: Activity) {
            // A picker can also finish without our activity ever stopping (multi-window).
            SharedVault.get(activity).autoLockSuppressed = false
        }

        override fun onActivityStopped(activity: Activity) {
            if (startedActivities > 0) startedActivities--
            // A configuration change stops and restarts the activity at once; not a background.
            if (startedActivities == 0 && !activity.isChangingConfigurations) scheduleLock()
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
        override fun onActivityPaused(activity: Activity) = Unit
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
        override fun onActivityDestroyed(activity: Activity) = Unit
    }

    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == Intent.ACTION_SCREEN_OFF && pendingLock == null) scheduleLock()
        }
    }
}
