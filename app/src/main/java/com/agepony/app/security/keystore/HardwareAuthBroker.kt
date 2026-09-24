package com.agepony.app.security.keystore

import android.os.Handler
import android.os.Looper
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
    class AuthCancelled(message: String) : Exception(message)

    @Volatile private var current: WeakReference<FragmentActivity>? = null

    /** Called from each activity's onResume / onPause. */
    fun attach(activity: FragmentActivity) { current = WeakReference(activity) }
    fun detach(activity: FragmentActivity) { if (current?.get() === activity) current = null }

    /** Block the calling (non-main) thread until the user authenticates. Throws if they don't. */
    fun awaitAuthentication(title: String, subtitle: String?) {
        check(Looper.myLooper() != Looper.getMainLooper()) { "awaitAuthentication must not run on the main thread" }
        val activity = current?.get() ?: throw AuthCancelled("AgePony needs to be open to use this hardware key.")
        val latch = CountDownLatch(1)
        var failure: Throwable? = null // published to the waiting thread by the latch
        Handler(Looper.getMainLooper()).post {
            if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                failure = AuthCancelled("AgePony needs to be open to use this hardware key.")
                latch.countDown()
                return@post
            }
            val job = activity.lifecycleScope.launch {
                try {
                    BiometricGate.confirm(activity, title, subtitle)
                } catch (e: Throwable) {
                    failure = e
                }
            }
            // Runs even if the scope was cancelled before the body started, so the worker
            // thread is never left waiting on a prompt that will not appear.
            job.invokeOnCompletion { cause ->
                if (cause != null && failure == null) failure = AuthCancelled("Authentication cancelled.")
                latch.countDown()
            }
        }
        if (!latch.await(3, TimeUnit.MINUTES)) throw AuthCancelled("Timed out waiting for authentication.")
        failure?.let { throw AuthCancelled(it.message ?: "Authentication cancelled.") }
    }
}
