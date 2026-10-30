package com.agepony.app.security.keystore

import android.os.Handler
import android.os.Looper
import androidx.annotation.StringRes
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import com.agepony.app.security.BiometricGate
import kotlinx.coroutines.launch
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Lets crypto code running on a worker thread ask for a biometric / device-credential prompt.
 *
 * A hardware decryption key only reports that it needs the user in the middle of an ECDH, deep
 * inside the age decrypt. Rather than teach every decrypt path to catch that and retry, the key
 * agreement blocks its worker thread here, the prompt runs on the main thread against the
 * foreground activity, and the ECDH retries once the user has confirmed.
 */
object HardwareAuthBroker {
    /**
     * The hardware key's user check didn't pass. [reason] is what the app shows, and [cause] the
     * prompt's own error when there was one; the message is internal (5.1.0, UI plan U5).
     */
    class AuthCancelled(
        val reason: AuthCancelled.Reason,
        cause: Throwable? = null,
    ) : Exception(reason.name, cause) {
        enum class Reason { APP_NOT_OPEN, CANCELLED, TIMED_OUT, FAILED }
    }

    @Volatile private var current: WeakReference<FragmentActivity>? = null

    /** Called from each activity's onResume / onPause. */
    fun attach(activity: FragmentActivity) { current = WeakReference(activity) }
    fun detach(activity: FragmentActivity) { if (current?.get() === activity) current = null }

    /**
     * Block the calling (non-main) thread until the user authenticates. Throws if they don't.
     * The prompt's [title] and [subtitle] are resources, read from the foreground activity.
     */
    fun awaitAuthentication(@StringRes title: Int, @StringRes subtitle: Int?) {
        check(Looper.myLooper() != Looper.getMainLooper()) { "awaitAuthentication must not run on the main thread" }
        val activity = current?.get() ?: throw AuthCancelled(AuthCancelled.Reason.APP_NOT_OPEN)
        val latch = CountDownLatch(1)
        var failure: Throwable? = null // published to the waiting thread by the latch
        Handler(Looper.getMainLooper()).post {
            if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                failure = AuthCancelled(AuthCancelled.Reason.APP_NOT_OPEN)
                latch.countDown()
                return@post
            }
            val job = activity.lifecycleScope.launch {
                try {
                    BiometricGate.confirm(activity, activity.getString(title), subtitle?.let { activity.getString(it) })
                } catch (e: Throwable) {
                    failure = e
                }
            }
            // Runs even if the scope was cancelled before the body started, so the worker
            // thread is never left waiting on a prompt that will not appear.
            job.invokeOnCompletion { cause ->
                if (cause != null && failure == null) failure = AuthCancelled(AuthCancelled.Reason.CANCELLED)
                latch.countDown()
            }
        }
        if (!latch.await(3, TimeUnit.MINUTES)) throw AuthCancelled(AuthCancelled.Reason.TIMED_OUT)
        failure?.let { f ->
            if (f is AuthCancelled) throw f
            // Keep the prompt's error as the cause, so its code reaches the message, not its text.
            throw AuthCancelled(AuthCancelled.Reason.FAILED, f)
        }
    }
}
