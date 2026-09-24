package com.agepony.app

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.snapshotFlow
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.agepony.app.security.ClipboardGuard
import com.agepony.app.security.keystore.HardwareAuthBroker
import com.agepony.app.security.piv.YubiKeyBroker
import com.agepony.app.ui.security.YubiKeyPromptHost
import com.agepony.app.ui.VaultGate
import com.agepony.app.ui.theme.AgePonyTheme
import com.agepony.app.vault.Vault
import com.agepony.app.vault.VaultViewModel
import kotlinx.coroutines.launch

class MainActivity : FragmentActivity() {

    private val vaultViewModel: VaultViewModel by viewModels()

    override fun onResume() {
        super.onResume()
        HardwareAuthBroker.attach(this)
        YubiKeyBroker.attach(this)
    }

    override fun onPause() {
        HardwareAuthBroker.detach(this)
        YubiKeyBroker.detach(this)
        super.onPause()
    }

    override fun onStart() {
        super.onStart()
        // Clear a sensitive clipboard copy that came due while AgePony was backgrounded
        // (the clipboard can only be read/cleared while we are foreground on API 29+).
        ClipboardGuard.onForeground(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Count fresh launches only (not configuration-change recreations) so the
        // in-app review nudge fires after genuine repeat use. See AgePonyApp.
        if (savedInstanceState == null) {
            vaultViewModel.vault.incrementLaunchCount()
        }
        installWindowProtection(vaultViewModel.vault)
        enableEdgeToEdge()
        setContent {
            AgePonyTheme {
                VaultGate(vaultViewModel)
                YubiKeyPromptHost()
            }
        }
    }
}

/**
 * Window-level protections shared by [MainActivity] and the share activity.
 *
 * FLAG_SECURE is on by default and lifted only while `vault.allowScreenshots` is true, so
 * decrypted text, notes and keys stay out of screenshots and the Recents card (audit M-5). The
 * setting is observed, so toggling it in Settings applies at once. Screens that show a secret
 * (key reveal, paper backup) add the flag themselves and only clear it again when screenshots
 * are allowed.
 *
 * Non-system overlays are hidden over our windows on API 31+, against tapjacking (audit L-22).
 * Window-wide filterTouchesWhenObscured was tried and left out: on API 26 to 30 it drops every
 * tap while any overlay is on screen, so a blue-light filter or screen dimmer would make the app
 * unusable. API 31+ also blocks touches through untrusted overlays at the system level.
 */
internal fun FragmentActivity.installWindowProtection(vault: Vault) {
    if (Build.VERSION.SDK_INT >= 31) {
        try {
            window.setHideOverlayWindows(true)
        } catch (_: SecurityException) {
            // HIDE_OVERLAY_WINDOWS missing from the manifest; the system's own untrusted-touch
            // blocking on API 31+ still applies.
        }
    }
    var applied = vault.allowScreenshots
    applyScreenshotPolicy(secure = !applied)
    // Main.immediate, so collection starts before the first frame; only react to real changes so
    // a screen that forced FLAG_SECURE is not undone by the initial emission.
    lifecycleScope.launch {
        snapshotFlow { vault.allowScreenshots }.collect { allow ->
            if (allow != applied) {
                applied = allow
                applyScreenshotPolicy(secure = !allow)
            }
        }
    }
}

private fun FragmentActivity.applyScreenshotPolicy(secure: Boolean) {
    if (secure) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    } else {
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
    if (Build.VERSION.SDK_INT >= 33) {
        setRecentsScreenshotEnabled(!secure)
    }
}
