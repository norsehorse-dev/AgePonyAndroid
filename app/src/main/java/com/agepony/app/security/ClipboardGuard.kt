package com.agepony.app.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.security.MessageDigest

//
// Auto-clears sensitive copies (key material, encrypted text) from the clipboard about
// 60 seconds after they are copied, mirroring iOS's expiring pasteboard item.
//
// Platform reality this works within: on Android 10+ (API 29) an app that is not in the
// foreground can neither read nor write the clipboard. Reading is required to honor the
// "don't wipe a newer copy" rule, so the clear can only run while AgePony is foreground.
// The timer clears at ~60s if the app is still open; otherwise the clear is deferred and
// runs the next time AgePony returns to the foreground (MainActivity.onStart calls
// onForeground). If the user copies, switches to another app to paste, and never comes
// back, the copy is left for the OS to age out. There is no portable way around that.
//
object ClipboardGuard {

    private const val CLEAR_DELAY_MS = 60_000L

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var pending: Job? = null

    // SHA-256 of the copied text (so the plaintext is not retained here) and the moment it
    // was armed. Null when nothing is being tracked.
    private var armedDigest: ByteArray? = null
    private var armedAt: Long = 0L

    /** Copy [text] to the clipboard as sensitive content and arm the 60s auto-clear. */
    fun copySensitive(context: Context, text: String) {
        val cm = context.clipboard() ?: return
        val clip = ClipData.newPlainText("AgePony", text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        cm.setPrimaryClip(clip)

        armedDigest = sha256(text)
        armedAt = SystemClock.elapsedRealtime()
        pending?.cancel()
        val appContext = context.applicationContext
        pending = scope.launch {
            delay(CLEAR_DELAY_MS)
            attemptClear(appContext)
        }
    }

    /** Called when AgePony returns to the foreground; clears an overdue armed copy. */
    fun onForeground(context: Context) {
        if (armedDigest != null && SystemClock.elapsedRealtime() - armedAt >= CLEAR_DELAY_MS) {
            attemptClear(context.applicationContext)
        }
    }

    private fun attemptClear(appContext: Context) {
        val want = armedDigest ?: return
        val cm = appContext.clipboard() ?: return
        // Reading only succeeds while foreground on API 29+. Null means we cannot see the
        // clipboard right now; leave it armed and try again on the next foreground.
        val current = try {
            cm.primaryClip?.getItemAt(0)?.coerceToText(appContext)?.toString()
        } catch (e: Exception) {
            null
        } ?: return

        if (MessageDigest.isEqual(sha256(current), want)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                cm.clearPrimaryClip()
            } else {
                cm.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }
        // Either our copy was cleared, or the clipboard holds something the user put there
        // since; either way stop tracking it.
        disarm()
    }

    private fun disarm() {
        pending?.cancel()
        pending = null
        armedDigest = null
        armedAt = 0L
    }

    private fun Context.clipboard(): ClipboardManager? =
        getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager

    private fun sha256(s: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
}
