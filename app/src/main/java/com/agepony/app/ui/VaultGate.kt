package com.agepony.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.agepony.app.vault.VaultViewModel

//
// Gates the five-tab app shell behind the vault state, mirroring the iOS launch
// gate: first run shows "create vault", a provisioned-but-locked vault shows
// "unlock", and an unlocked vault shows AgePonyApp(). The vault locks again when
// the app stops (backgrounds) — UNLESS a system picker (SAF) was launched from
// inside the app, in which case the round trip is exempt so the in-progress
// flow and its result launcher survive. When biometric is disabled the locked
// vault unlocks automatically (no prompt).
//
@Composable
fun VaultGate(vm: VaultViewModel) {
    val activity = LocalContext.current as FragmentActivity

    // Lock when backgrounding, but skip the lock for an in-app SAF round trip.
    DisposableEffect(activity) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> if (!vm.vault.autoLockSuppressed) vm.lock()
                Lifecycle.Event.ON_START -> vm.vault.autoLockSuppressed = false
                else -> Unit
            }
        }
        activity.lifecycle.addObserver(observer)
        onDispose { activity.lifecycle.removeObserver(observer) }
    }

    // Biometric off: unlock silently when provisioned but locked.
    LaunchedEffect(vm.provisioned, vm.vault.isUnlocked, vm.biometricEnabled, vm.isBusy, vm.error) {
        if (vm.provisioned && !vm.vault.isUnlocked && !vm.biometricEnabled &&
            !vm.isBusy && vm.error == null
        ) {
            vm.unlock(activity)
        }
    }

    when {
        !vm.provisioned -> GateScaffold(
            heading = "Welcome to AgePony",
            body = "AgePony stores your keys, recipients, and notes in a vault " +
                "sealed on this device and unlocked with your biometric. " +
                "Create your vault to get started.",
            actionLabel = "Create secure vault",
            busy = vm.isBusy,
            error = vm.error,
            onAction = { vm.bootstrap(activity) }
        )

        !vm.vault.isUnlocked -> GateScaffold(
            heading = "AgePony is locked",
            body = if (vm.biometricEnabled) {
                "Unlock your vault to access your keys and notes."
            } else {
                "Opening your vault…"
            },
            actionLabel = "Unlock",
            busy = vm.isBusy,
            error = vm.error,
            onAction = { vm.unlock(activity) }
        )

        else -> AgePonyApp(vm)
    }
}

@Composable
private fun GateScaffold(
    heading: String,
    body: String,
    actionLabel: String,
    busy: Boolean,
    error: String?,
    onAction: () -> Unit
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = heading,
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary,
                textAlign = TextAlign.Center
            )
            Text(
                text = body,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 16.dp, bottom = 32.dp)
            )
            if (busy) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            } else {
                Button(onClick = onAction, modifier = Modifier.width(240.dp)) {
                    Text(actionLabel)
                }
            }
            if (error != null) {
                Text(
                    text = error,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 24.dp)
                )
            }
        }
    }
}
