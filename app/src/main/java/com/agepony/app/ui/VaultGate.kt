package com.agepony.app.ui

import android.app.Activity
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.LocalView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import kotlinx.coroutines.delay
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.agepony.app.security.BiometricGate
import com.agepony.app.vault.LockMode
import com.agepony.app.vault.VaultViewModel

//
// Gates the app shell behind the vault state, mirroring the iOS launch gate:
// first run shows "create vault", a provisioned-but-locked vault shows "unlock",
// and an unlocked vault shows AgePonyApp(). The vault locks again when the app
// stops (backgrounds) — UNLESS a system picker (SAF) was launched from inside
// the app, in which case the round trip is exempt so the in-progress flow and
// its result launcher survive.
//
// Creation offers two paths: a biometric-sealed vault (when the device has a
// screen lock or fingerprint), and an app-owned password/PIN vault (always, and
// the only option on a device with no lock enrolled — this is what makes setup
// possible without a screen lock, 4.0.0).
//
// Unlock paths, in the order the locked screen offers them:
//   - biometric, when enabled;
//   - app-owned password / PIN, when enrolled; the same field is where a decoy
//     password is entered, and the wipe it triggers is invisible here — it just
//     resolves to an unlocked, empty vault;
//   - silent (no-lock) auto-unlock, only when biometric is off AND a plain blob
//     exists — the deliberate "no lock at all" mode.
//
@Composable
fun VaultGate(vm: VaultViewModel) {
    val activity = LocalContext.current as FragmentActivity

    // Lock when backgrounding, but skip the lock for an in-app SAF round trip.
    DisposableEffect(activity) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> vm.onEnterBackground()
                Lifecycle.Event.ON_START -> vm.onEnterForeground()
                else -> Unit
            }
        }
        activity.lifecycle.addObserver(observer)
        onDispose { activity.lifecycle.removeObserver(observer) }
    }

    // "No lock" mode only: biometric off and a plain (non-auth) blob present.
    // Password-enrolled vaults are NOT auto-unlocked — the password is the gate.
    LaunchedEffect(vm.provisioned, vm.vault.isUnlocked, vm.lockMode, vm.isBusy, vm.error) {
        if (vm.provisioned && !vm.vault.isUnlocked && vm.lockMode == LockMode.OFF &&
            vm.vault.plainKeyBlobExists() && !vm.isBusy && vm.error == null
        ) {
            vm.unlock(activity)
        }
    }

    when {
        !vm.provisioned -> WelcomeScreen(vm, activity)
        !vm.vault.isUnlocked -> LockedScreen(vm, activity)
        else -> AgePonyApp(vm)
    }
}

@Composable
private fun WelcomeScreen(vm: VaultViewModel, activity: FragmentActivity) {
    // Recomputed on each composition; cheap, and it can change if the user leaves to set
    // up a screen lock and comes back.
    val biometricAvailable = remember(vm.isBusy) { BiometricGate.canAuthenticate(activity) }
    var showCreatePassword by remember { mutableStateOf(false) }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier.fillMaxSize().padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                "Welcome to AgePony",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary,
                textAlign = TextAlign.Center,
            )
            Text(
                if (biometricAvailable) {
                    "AgePony stores your keys, recipients, and notes in a vault sealed on " +
                        "this device. Unlock it with your biometric, a password, or both."
                } else {
                    "AgePony stores your keys, recipients, and notes in a vault sealed on " +
                        "this device. No screen lock is set up, so protect it with a password " +
                        "or PIN. To unlock with a fingerprint instead, set up a screen lock in " +
                        "Android settings first, then create the vault."
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 16.dp, bottom = 32.dp),
            )

            if (vm.isBusy) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            } else if (biometricAvailable) {
                Button(onClick = { vm.bootstrap(activity) }, modifier = Modifier.width(260.dp)) {
                    Text("Create with biometric")
                }
                TextButton(
                    onClick = { showCreatePassword = true },
                    modifier = Modifier.padding(top = 12.dp),
                ) { Text("Use a password instead") }
            } else {
                val credentialCreate = Build.VERSION.SDK_INT < Build.VERSION_CODES.R &&
                    BiometricGate.isDeviceSecure(activity)
                if (credentialCreate) {
                    Button(
                        onClick = { vm.bootstrapWithDeviceCredential() },
                        modifier = Modifier.width(260.dp),
                    ) { Text("Use device PIN or password") }
                    TextButton(
                        onClick = { showCreatePassword = true },
                        modifier = Modifier.padding(top = 12.dp),
                    ) { Text("Use an app password instead") }
                } else {
                    Button(onClick = { showCreatePassword = true }, modifier = Modifier.width(260.dp)) {
                        Text("Create with a password")
                    }
                }
            }

            if (vm.error != null) {
                Text(
                    vm.error!!,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 24.dp),
                )
            }
        }
    }

    if (showCreatePassword) {
        CreateSecretDialog(
            onConfirm = { secret, kind ->
                vm.bootstrapWithPassword(secret, kind)
                showCreatePassword = false
            },
            onDismiss = { showCreatePassword = false },
        )
    }
}

@Composable
private fun LockedScreen(vm: VaultViewModel, activity: FragmentActivity) {
    val isPin = vm.unlockSecretKind == "pin"
    val secretNoun = if (isPin) "PIN" else "password"
    // With an OS gate, that gate leads and the password field is opt-in; a no-lock
    // (OFF) vault shows the password field straight away.
    var showPasswordField by remember { mutableStateOf(vm.lockMode == LockMode.OFF) }
    val credentialLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) vm.unlockAfterDeviceCredential()
    }
    var secret by remember { mutableStateOf("") }
    val focusRequester = remember { FocusRequester() }
    val keyboard = LocalSoftwareKeyboardController.current
    val view = LocalView.current

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier.fillMaxSize().padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                "AgePony is locked",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary,
                textAlign = TextAlign.Center,
            )
            Text(
                when (vm.lockMode) {
                    LockMode.BIOMETRIC -> "Unlock your vault to access your keys and notes."
                    LockMode.DEVICE_CREDENTIAL ->
                        "Confirm your device PIN, pattern, or password to unlock."
                    LockMode.OFF -> "Enter your $secretNoun to unlock."
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 16.dp, bottom = 32.dp),
            )

            if (vm.isBusy) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            } else {
                when (vm.lockMode) {
                    LockMode.BIOMETRIC ->
                        Button(onClick = { vm.unlock(activity) }, modifier = Modifier.width(240.dp)) {
                            Text("Unlock")
                        }
                    LockMode.DEVICE_CREDENTIAL ->
                        Button(
                            onClick = {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                    vm.unlock(activity)
                                } else {
                                    val intent = BiometricGate.deviceCredentialIntent(
                                        activity,
                                        "Unlock AgePony",
                                        "Confirm your PIN, pattern, or password",
                                    )
                                    if (intent != null) credentialLauncher.launch(intent)
                                    else vm.noteError("No device PIN, pattern, or password is set.")
                                }
                            },
                            modifier = Modifier.width(240.dp),
                        ) { Text("Unlock") }
                    LockMode.OFF -> Unit
                }

                if (vm.passwordEnrolled) {
                    if (showPasswordField) {
                        OutlinedTextField(
                            value = secret,
                            onValueChange = { secret = it },
                            singleLine = true,
                            label = { Text(secretNoun.replaceFirstChar { it.uppercase() }) },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(
                                keyboardType = if (isPin) KeyboardType.NumberPassword else KeyboardType.Password
                            ),
                            modifier = Modifier.fillMaxWidth()
                                .focusRequester(focusRequester)
                                .padding(top = if (vm.lockMode != LockMode.OFF) 24.dp else 0.dp),
                        )
                        LaunchedEffect(Unit) {
                            // Cold start and some OEM skins (MIUI) hand the window focus late, so
                            // an immediate requestFocus is dropped and the field never selects.
                            // Wait for real window focus, then focus the field and force the IME up.
                            var tries = 0
                            while (!view.hasWindowFocus() && tries < 50) {
                                delay(20)
                                tries++
                            }
                            focusRequester.requestFocus()
                            keyboard?.show()
                            WindowInsetsControllerCompat(activity.window, view)
                                .show(WindowInsetsCompat.Type.ime())
                        }
                        Button(
                            onClick = {
                                val chars = secret.toCharArray()
                                secret = ""
                                vm.unlockWithPassword(chars)
                            },
                            enabled = secret.isNotEmpty(),
                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                        ) { Text("Unlock with $secretNoun") }
                    } else {
                        TextButton(
                            onClick = { showPasswordField = true },
                            modifier = Modifier.padding(top = 16.dp),
                        ) { Text("Use your $secretNoun instead") }
                    }
                }
            }

            if (vm.error != null) {
                Text(
                    vm.error!!,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 24.dp),
                )
            }
        }
    }
}

/**
 * Create-time secret entry: password or PIN, with a confirm field so a typo doesn't lock
 * the user out of a vault they can't recover. Mirrors the Settings SetSecretDialog, kept
 * separate so the gate doesn't depend on Settings internals.
 */
@Composable
private fun CreateSecretDialog(
    onConfirm: (CharArray, String) -> Unit,
    onDismiss: () -> Unit,
) {
    var kind by remember { mutableStateOf("password") }
    var value by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    val focusRequester = remember { FocusRequester() }
    val keyboard = LocalSoftwareKeyboardController.current
    val view = LocalView.current
    val isPin = kind == "pin"
    val mismatch = again.isNotEmpty() && value != again
    val valid = value.isNotEmpty() && value == again

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Protect your vault") },
        text = {
            Column {
                Text(
                    "Choose a password or PIN to unlock AgePony. There is no recovery if you " +
                        "forget it — the vault is sealed with it.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Row(modifier = Modifier.padding(top = 8.dp)) {
                    TextButton(onClick = { kind = "password" }) {
                        Text(
                            "Password",
                            color = if (!isPin) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TextButton(onClick = { kind = "pin" }) {
                        Text(
                            "PIN",
                            color = if (isPin) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                val kb = KeyboardOptions(
                    keyboardType = if (isPin) KeyboardType.NumberPassword else KeyboardType.Password
                )
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    singleLine = true,
                    label = { Text(if (isPin) "PIN" else "Password") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = kb,
                    modifier = Modifier.padding(top = 8.dp).focusRequester(focusRequester),
                )
                LaunchedEffect(Unit) {
                    // The dialog window takes focus a beat after it opens; wait for it,
                    // then focus the first field and force the IME up. getWindowInsetsController
                    // targets the dialog's own window, not the activity's.
                    var tries = 0
                    while (!view.hasWindowFocus() && tries < 50) {
                        delay(20)
                        tries++
                    }
                    focusRequester.requestFocus()
                    keyboard?.show()
                    ViewCompat.getWindowInsetsController(view)?.show(WindowInsetsCompat.Type.ime())
                }
                OutlinedTextField(
                    value = again,
                    onValueChange = { again = it },
                    singleLine = true,
                    label = { Text("Confirm") },
                    isError = mismatch,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = kb,
                    modifier = Modifier.padding(top = 8.dp),
                )
                if (mismatch) {
                    Text(
                        "They don't match.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(value.toCharArray(), kind) }, enabled = valid) {
                Text("Create vault")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
