package com.agepony.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.fragment.app.FragmentActivity
import com.agepony.app.security.ClipboardGuard
import com.agepony.app.security.keystore.HardwareAuthBroker
import com.agepony.app.security.piv.YubiKeyBroker
import com.agepony.app.ui.security.YubiKeyPromptHost
import com.agepony.app.ui.VaultGate
import com.agepony.app.ui.theme.AgePonyTheme
import com.agepony.app.vault.VaultViewModel

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
        enableEdgeToEdge()
        setContent {
            AgePonyTheme {
                VaultGate(vaultViewModel)
                YubiKeyPromptHost()
            }
        }
    }
}
