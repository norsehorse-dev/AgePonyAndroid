// Haptics.kt
// AgePony Android 4.3.0
//
// Lightweight haptic helpers usable from any Composable. Compose's
// LocalHapticFeedback only exposes LongPress/TextHandleMove, which can't tell
// "operation succeeded" from "tapped a button", so we fall through to
// View.performHapticFeedback with the platform constants and gate the newer
// ones on API level.

package com.agepony.app.ui.util

import android.os.Build
import android.view.HapticFeedbackConstants
import android.view.View
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalView

/** Callbacks bundle returned from [rememberHaptics]. */
class HapticsCallbacks internal constructor(private val view: View) {

    /** Strong "operation succeeded" feedback, after an encrypt, decrypt, import, or scan. */
    fun success() {
        val c = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
            HapticFeedbackConstants.CONFIRM else HapticFeedbackConstants.VIRTUAL_KEY
        view.performHapticFeedback(c)
    }

    /** "Something went wrong" feedback, after a failed operation. */
    fun error() {
        val c = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
            HapticFeedbackConstants.REJECT else HapticFeedbackConstants.LONG_PRESS
        view.performHapticFeedback(c)
    }

    /** Light tick for a discrete step completing (e.g. a QR part scanned). */
    fun tick() {
        view.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
    }
}

@Composable
fun rememberHaptics(): HapticsCallbacks {
    val view = LocalView.current
    return remember(view) { HapticsCallbacks(view) }
}
