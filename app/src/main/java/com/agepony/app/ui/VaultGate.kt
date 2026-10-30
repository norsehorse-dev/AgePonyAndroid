package com.agepony.app.ui

import android.app.Activity
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
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
import com.agepony.app.security.BiometricGate
import com.agepony.app.security.PasswordVault
import com.agepony.app.security.UnlockAttempts
import com.agepony.app.ui.passphrase.PassphraseOnlyScreen
import com.agepony.app.ui.components.ChoiceField
import com.agepony.app.ui.components.PrimaryAction
import com.agepony.app.ui.components.SecondaryAction
import com.agepony.app.vault.LockMode
import com.agepony.app.vault.VaultViewModel
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll

//
// Gates the app shell behind the vault state, mirroring the iOS launch gate:
// first run shows "create vault", a provisioned-but-locked vault shows "unlock",
// and an unlocked vault shows AgePonyApp(). Locking itself is process-level since
// 5.0.1 (security/AutoLock, audit H-3): after the grace period once no AgePony
// activity is visible, at once on screen off, and after at most 5 minutes during
// a system picker (SAF) round trip launched from inside the app.
//
// Creation offers two paths: a biometric-sealed vault (when the device has a
// screen lock or fingerprint), and an app-owned password/PIN vault (always, and
// the only option on a device with no lock enrolled — this is what makes setup
// possible without a screen lock, 4.0.0).
//
// Unlock paths, in the order the locked screen offers them:
//   - biometric or device credential, when that is the lock mode and no duress
//     secret is set (a duress secret makes the vault PIN-only, audit H-1);
//   - app-owned password / PIN, when enrolled; the same field is where a decoy
//     password is entered, and the wipe it triggers is invisible here: it just
//     resolves to an unlocked, empty vault. Wrong entries are counted, with a
//     backoff after 5 (audit M-1);
//   - silent (no-lock) auto-unlock, only when the mode is No lock, a plain blob
//     exists AND no password is set: the deliberate "no lock at all" mode. No lock
//     plus a password is password-only (audit H-4).
//
// Biometrics only (5.1.0, iOS E6): the biometric prompt starts by itself when the screen
// shows, with no way to the device credential. When the biometric can't open the vault (a
// fingerprint or face added or removed, none enrolled, a lockout) the password field comes up
// at once with a sentence saying why, and the prompt stops starting by itself until the next
// successful unlock. After a password unlock in that state, the unlocked app offers to turn
// biometric unlock back on.
//
@Composable
fun VaultGate(
    vm: VaultViewModel,
    passphraseOnlyContent: @Composable (onClose: () -> Unit) -> Unit = { close ->
        PassphraseOnlyScreen(vault = vm.vault, onClose = close)
    },
    unlockedContent: @Composable () -> Unit = { AgePonyApp(vm) },
) {
    // Issue #13: passphrase work is available from the lock screen without unlocking the vault.
    var passphraseOnly by rememberSaveable { mutableStateOf(false) }

    val activity = LocalContext.current as FragmentActivity

    // "No lock" mode only: biometric off and a plain (non-auth) blob present.
    // Password-enrolled vaults are NOT auto-unlocked: the password is the gate (audit H-4).
    LaunchedEffect(vm.provisioned, vm.vault.isUnlocked, vm.lockMode, vm.passwordEnrolled, vm.isBusy, vm.error) {
        if (vm.provisioned && !vm.vault.isUnlocked && vm.lockMode == LockMode.OFF &&
            !vm.passwordEnrolled && vm.vault.plainKeyBlobExists() && !vm.isBusy && vm.error == null
        ) {
            vm.unlock(activity)
        }
    }

    when {
        !vm.provisioned -> WelcomeScreen(vm, activity)
        !vm.vault.isUnlocked && passphraseOnly -> passphraseOnlyContent { passphraseOnly = false }
        !vm.vault.isUnlocked -> LockedScreen(vm, activity, onPassphraseOnly = { passphraseOnly = true })
        else -> {
            unlockedContent()
            if (vm.biometricOnlyNeedsRefresh && vm.lockMode == LockMode.BIOMETRIC_ONLY) {
                BiometricRefreshDialog(vm, activity)
            }
        }
    }
}

/** Biometrics only, opened with the password after the mode's key stopped working (E6). */
@Composable
private fun BiometricRefreshDialog(vm: VaultViewModel, activity: FragmentActivity) {
    AlertDialog(
        onDismissRequest = { vm.dismissBiometricOnlyRefresh() },
        title = { Text(stringResource(R.string.app_biometric_refresh_title)) },
        text = { Text(stringResource(R.string.app_biometric_refresh_body)) },
        confirmButton = {
            TextButton(onClick = { vm.restoreBiometricOnly(activity) }, enabled = !vm.isBusy) {
                Text(stringResource(R.string.app_biometric_refresh_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = { vm.dismissBiometricOnlyRefresh() }) {
                Text(stringResource(R.string.app_biometric_refresh_later))
            }
        },
    )
}

@Composable
private fun WelcomeScreen(vm: VaultViewModel, activity: FragmentActivity) {
    // Recomputed on each composition; cheap, and it can change if the user leaves to set
    // up a screen lock and comes back.
    val biometricAvailable = remember(vm.isBusy) { BiometricGate.canAuthenticate(activity) }
    var showCreatePassword by remember { mutableStateOf(false) }

    // No Scaffold here, so the screen pads for the system bars and the keyboard itself, and
    // scrolls when the keyboard leaves too little room (content stays centred otherwise).
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        BoxWithConstraints(Modifier.fillMaxSize().systemBarsPadding().imePadding()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .heightIn(min = maxHeight)
                .padding(horizontal = 24.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                stringResource(R.string.app_welcome_title),
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
            )
            Text(
                if (biometricAvailable) {
                    stringResource(R.string.app_welcome_body_biometric)
                } else {
                    stringResource(R.string.app_welcome_body_no_lock)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 16.dp, bottom = 32.dp),
            )

            if (vm.isBusy) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            } else if (biometricAvailable) {
                Button(onClick = { vm.bootstrap(activity) }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.app_create_with_biometrics))
                }
                TextButton(
                    onClick = { showCreatePassword = true },
                    modifier = Modifier.padding(top = 12.dp),
                ) { Text(stringResource(R.string.app_create_use_password_instead)) }
            } else {
                val credentialCreate = Build.VERSION.SDK_INT < Build.VERSION_CODES.R &&
                    BiometricGate.isDeviceSecure(activity)
                if (credentialCreate) {
                    Button(
                        onClick = { vm.bootstrapWithDeviceCredential() },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(stringResource(R.string.app_create_use_device_credential)) }
                    TextButton(
                        onClick = { showCreatePassword = true },
                        modifier = Modifier.padding(top = 12.dp),
                    ) { Text(stringResource(R.string.app_create_use_app_password_instead)) }
                } else {
                    Button(onClick = { showCreatePassword = true }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.app_create_with_password))
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
private fun LockedScreen(vm: VaultViewModel, activity: FragmentActivity, onPassphraseOnly: () -> Unit) {
    val isPin = vm.unlockSecretKind == "pin"
    // A duress secret makes the vault PIN-only: no OS gate is offered (audit H-1).
    val hardwareUnlock = !vm.duressEnrolled
    // With an OS gate, that gate leads and the password field is opt-in; a no-lock
    // (OFF) or PIN-only vault shows the password field straight away.
    var showPasswordField by remember {
        mutableStateOf(vm.lockMode == LockMode.OFF || !hardwareUnlock || vm.biometricOnlyProblem != null)
    }
    val biometricOnly = hardwareUnlock && vm.lockMode == LockMode.BIOMETRIC_ONLY
    // Biometrics only: when the biometric can't open the vault, the password comes up at once (E6).
    LaunchedEffect(vm.biometricOnlyProblem) {
        if (vm.biometricOnlyProblem != null) showPasswordField = true
    }
    // Biometrics only: start the prompt by itself once the activity is in front, unless the last
    // try already said the biometric can't open the vault.
    var autoStarted by remember { mutableStateOf(false) }
    LaunchedEffect(biometricOnly) {
        if (!biometricOnly || autoStarted || vm.biometricOnlyProblem != null) return@LaunchedEffect
        var waited = 0
        while (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) && waited < 600) {
            delay(50)
            waited++
        }
        if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) &&
            !vm.isBusy && !vm.vault.isUnlocked && vm.biometricOnlyProblem == null
        ) {
            autoStarted = true
            vm.unlock(activity)
        }
    }
    val fingerprintOnly = remember { BiometricGate.fingerprintOnlyHardware(activity) }
    // Failed-attempt backoff (audit M-1): count down while a wait is running.
    var lockoutSeconds by remember { mutableStateOf(0L) }
    var confirmLegacyOpen by remember { mutableStateOf(false) }
    LaunchedEffect(vm.isBusy, vm.error) {
        while (true) {
            val remaining = vm.lockoutRemainingMillis()
            lockoutSeconds = (remaining + 999L) / 1000L
            if (remaining <= 0L) break
            delay(1000L)
        }
    }
    val credentialLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) vm.unlockAfterDeviceCredential()
    }
    var secret by remember { mutableStateOf("") }
    val focusRequester = remember { FocusRequester() }
    val keyboard = LocalSoftwareKeyboardController.current
    val view = LocalView.current

    // No Scaffold here, so the screen pads for the system bars and the keyboard itself, and
    // scrolls when the keyboard leaves too little room (content stays centred otherwise).
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        BoxWithConstraints(Modifier.fillMaxSize().systemBarsPadding().imePadding()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .heightIn(min = maxHeight)
                .padding(horizontal = 24.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                stringResource(R.string.app_locked_title),
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
            )
            Text(
                when {
                    !hardwareUnlock -> stringResource(
                        if (isPin) R.string.app_locked_enter_pin else R.string.app_locked_enter_password
                    )
                    vm.lockMode == LockMode.BIOMETRIC -> stringResource(R.string.app_locked_biometric)
                    vm.lockMode == LockMode.BIOMETRIC_ONLY -> stringResource(
                        if (isPin) R.string.app_locked_biometric_only_pin else R.string.app_locked_biometric_only_password
                    )
                    vm.lockMode == LockMode.DEVICE_CREDENTIAL ->
                        stringResource(R.string.app_locked_device_credential)
                    else -> stringResource(
                        if (isPin) R.string.app_locked_enter_pin else R.string.app_locked_enter_password
                    )
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 16.dp, bottom = 32.dp),
            )

            if (vm.isBusy) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            } else {
                when (if (hardwareUnlock) vm.lockMode else LockMode.OFF) {
                    LockMode.BIOMETRIC ->
                        Button(onClick = { vm.unlock(activity) }, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.app_unlock))
                        }
                    LockMode.DEVICE_CREDENTIAL ->
                        Button(
                            onClick = {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                    vm.unlock(activity)
                                } else {
                                    val intent = BiometricGate.deviceCredentialIntent(
                                        activity,
                                        activity.getString(R.string.security_prompt_unlock_title),
                                        activity.getString(R.string.security_device_credential_subtitle),
                                    )
                                    if (intent != null) credentialLauncher.launch(intent)
                                    else vm.noteError(activity.getString(R.string.app_no_device_credential))
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(stringResource(R.string.app_unlock)) }
                    LockMode.BIOMETRIC_ONLY ->
                        Button(onClick = { vm.unlock(activity) }, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(if (fingerprintOnly) R.string.app_use_fingerprint else R.string.app_use_biometrics))
                        }
                    LockMode.OFF -> Unit
                }

                if (vm.passwordEnrolled) {
                    if (showPasswordField) {
                        OutlinedTextField(
                            value = secret,
                            onValueChange = { secret = it },
                            singleLine = true,
                            label = { Text(stringResource(if (isPin) R.string.app_pin else R.string.app_password)) },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(
                                keyboardType = if (isPin) KeyboardType.NumberPassword else KeyboardType.Password
                            ),
                            modifier = Modifier.fillMaxWidth()
                                .focusRequester(focusRequester)
                                .padding(top = if (hardwareUnlock && vm.lockMode != LockMode.OFF) 24.dp else 0.dp),
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
                        // One filled button per screen (5.1.0, U4): with an OS gate button above,
                        // the password button is the outlined one.
                        val unlockLabel = stringResource(
                            if (isPin) R.string.app_unlock_with_pin else R.string.app_unlock_with_password
                        )
                        val submitSecret: () -> Unit = {
                            val chars = secret.toCharArray()
                            secret = ""
                            vm.unlockWithPassword(chars)
                        }
                        val submitEnabled = secret.isNotEmpty() && lockoutSeconds == 0L
                        if (hardwareUnlock && vm.lockMode != LockMode.OFF) {
                            SecondaryAction(
                                text = unlockLabel,
                                onClick = submitSecret,
                                enabled = submitEnabled,
                                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                            )
                        } else {
                            PrimaryAction(
                                text = unlockLabel,
                                onClick = submitSecret,
                                enabled = submitEnabled,
                                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                            )
                        }
                        if (lockoutSeconds > 0L) {
                            Text(
                                stringResource(
                                    R.string.app_lockout_wait,
                                    UnlockAttempts.describeWait(LocalContext.current, lockoutSeconds * 1000L),
                                ),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                        }
                        // 5.0.0 opened a No lock vault without ever asking for its password, so
                        // someone upgrading may not remember it. Offered only while that
                        // vault's old no-prompt key is still on disk (gone after the first
                        // password unlock) and never with a duress secret set (audit H-4).
                        if (vm.legacyNoLockFallbackAvailable) {
                            TextButton(
                                onClick = { confirmLegacyOpen = true },
                                modifier = Modifier.padding(top = 8.dp),
                            ) {
                                Text(
                                    stringResource(
                                        if (isPin) R.string.app_legacy_open_pin else R.string.app_legacy_open_password
                                    )
                                )
                            }
                        }
                        if (confirmLegacyOpen) {
                            AlertDialog(
                                onDismissRequest = { confirmLegacyOpen = false },
                                title = {
                                    Text(
                                        stringResource(
                                            if (isPin) R.string.app_legacy_open_title_pin
                                            else R.string.app_legacy_open_title_password
                                        )
                                    )
                                },
                                text = {
                                    Text(
                                        stringResource(
                                            if (isPin) R.string.app_legacy_open_body_pin
                                            else R.string.app_legacy_open_body_password
                                        ),
                                    )
                                },
                                confirmButton = {
                                    TextButton(onClick = {
                                        confirmLegacyOpen = false
                                        vm.openLegacyNoLockAndRemovePassword()
                                    }) { Text(stringResource(R.string.app_legacy_open_confirm)) }
                                },
                                dismissButton = {
                                    TextButton(onClick = { confirmLegacyOpen = false }) { Text(stringResource(R.string.action_cancel)) }
                                },
                            )
                        }
                    } else {
                        TextButton(
                            onClick = { showPasswordField = true },
                            modifier = Modifier.padding(top = 16.dp),
                        ) {
                            Text(
                                stringResource(
                                    if (isPin) R.string.app_use_pin_instead else R.string.app_use_password_instead
                                )
                            )
                        }
                    }
                }
            }

            if (biometricOnly) {
                Text(
                    stringResource(R.string.app_locked_screen_lock_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 16.dp),
                )
            }

            if (!vm.isBusy) {
                TextButton(onClick = onPassphraseOnly, modifier = Modifier.padding(top = 24.dp)) {
                    Text(stringResource(R.string.app_passphrase_only_entry))
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
    // Minimum length for a new secret (audit M-1).
    val policyError = if (value.isEmpty()) null else PasswordVault.secretPolicyError(LocalContext.current, value, kind)
    val valid = value.isNotEmpty() && policyError == null && value == again

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.app_create_secret_title)) },
        text = {
            Column {
                Text(
                    stringResource(R.string.app_create_secret_body),
                    style = MaterialTheme.typography.bodyMedium,
                )
                // A menu, not two text buttons posing as segments (5.1.0, U4).
                ChoiceField(
                    label = stringResource(R.string.app_secret_type),
                    selected = kind,
                    options = listOf("password", "pin"),
                    optionLabel = { stringResource(if (it == "pin") R.string.app_pin else R.string.app_password) },
                    onSelect = { kind = it },
                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                )
                val kb = KeyboardOptions(
                    keyboardType = if (isPin) KeyboardType.NumberPassword else KeyboardType.Password
                )
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    singleLine = true,
                    label = { Text(stringResource(if (isPin) R.string.app_pin else R.string.app_password)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = kb,
                    isError = policyError != null,
                    supportingText = {
                        Text(
                            policyError ?: if (isPin) {
                                pluralStringResource(
                                    R.plurals.app_min_pin_digits,
                                    PasswordVault.MIN_PIN_LENGTH,
                                    PasswordVault.MIN_PIN_LENGTH,
                                )
                            } else {
                                pluralStringResource(
                                    R.plurals.app_min_password_chars,
                                    PasswordVault.MIN_PASSWORD_LENGTH,
                                    PasswordVault.MIN_PASSWORD_LENGTH,
                                )
                            }
                        )
                    },
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
                    label = { Text(stringResource(R.string.app_confirm_secret)) },
                    isError = mismatch,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = kb,
                    modifier = Modifier.padding(top = 8.dp),
                )
                if (mismatch) {
                    Text(
                        stringResource(R.string.app_secret_mismatch),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(value.toCharArray(), kind) }, enabled = valid) {
                Text(stringResource(R.string.app_create_vault))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}
