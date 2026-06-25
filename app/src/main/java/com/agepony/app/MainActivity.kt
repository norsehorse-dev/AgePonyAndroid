package com.agepony.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.fragment.app.FragmentActivity
import com.agepony.app.ui.VaultGate
import com.agepony.app.ui.theme.AgePonyTheme
import com.agepony.app.vault.VaultViewModel

class MainActivity : FragmentActivity() {

    private val vaultViewModel: VaultViewModel by viewModels()

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
            }
        }
    }
}
