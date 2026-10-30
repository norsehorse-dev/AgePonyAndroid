package com.agepony.app.ui.security

import com.agepony.app.ui.UserMessage
import android.app.Activity
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.agepony.app.R
import com.agepony.app.security.BiometricGate
import com.agepony.app.security.BiometricGateException
import com.agepony.app.security.OwnerCheckPolicy
import com.agepony.app.security.PasswordCheck
import com.agepony.app.security.UnlockAttempts
import com.agepony.app.vault.KeystoreMasterKey
import com.agepony.app.vault.LockMode
import com.agepony.app.vault.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Re-authentication before private key material leaves the app (sending keys to another device,
 * printing a paper backup), before a lock setting is loosened (audit L-15), and before the first
 * app password is set (5.1.0, iOS H-1). Same rule as revealing a private key: biometric or device
 * credential when available, otherwise the app password or PIN, otherwise straight through for a
 * vault on a phone with no screen lock at all.
 *
 * On a password-only vault (No lock plus a password, or any vault with a duress secret, which
 * is PIN-only) the app password is asked instead of the device credential: the device
 * credential doesn't open that vault, so it shouldn't unlock its settings either (L-11). With
 * [requireAppPassword] the app password is asked whenever one is set, for changes that only
 * make sense if the user still knows it (switching to No lock, or leaving Biometrics only).
 * Password checks go through the vault's failed-attempt counter (audit M-1).
 *
 * Biometrics only (5.1.0, E6, M-3): a strong biometric bound to the mode's Keystore key, never
 * the device credential. After a biometric was added or removed, or while none can run, the app
 * password is asked instead, with a sentence saying why. On a phone with a screen lock where no
 * check can run at all, the action is refused rather than let through (H-1). Below API 30, a
 * phone with a screen lock and no strong biometric gets the system credential screen.
 *
 * The decision itself is [OwnerCheckPolicy.route]. Returns a function to call with a title and
 * the action to run once the user has confirmed.
 */
@Composable
fun rememberSensitiveConfirm(
    vault: Vault,
    requireAppPassword: Boolean = false,
): (title: String, onGranted: () -> Unit) -> Unit {
    val activity = LocalContext.current as FragmentActivity
    val scope = rememberCoroutineScope()
    var pending by remember { mutableStateOf<Pair<String, () -> Unit>?>(null) }
    var askPassword by remember { mutableStateOf(false) }
    var passwordNote by remember { mutableStateOf<String?>(null) }
    var credentialAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val isPin = vault.unlockSecretKind == "pin"

    // Below API 30: the Keyguard credential screen, for a phone with a screen lock and no strong
    // biometric, where the system prompt can't offer the device credential.
    val credentialLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val action = credentialAction
        credentialAction = null
        if (result.resultCode == Activity.RESULT_OK) {
            BiometricGate.noteOwnerConfirmed()
            action?.invoke()
        }
    }

    if (askPassword && pending != null) {
        var value by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { askPassword = false; pending = null; passwordNote = null },
            title = { Text(stringResource(if (isPin) R.string.security_confirm_pin else R.string.security_confirm_password)) },
            text = {
                Column {
                    passwordNote?.let { note ->
                        Text(
                            note,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                    }
                    OutlinedTextField(
                        value = value,
                        onValueChange = { value = it },
                        singleLine = true,
                        label = { Text(stringResource(if (isPin) R.string.app_pin else R.string.app_password)) },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = if (isPin) KeyboardType.NumberPassword else KeyboardType.Password,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                TextButton(enabled = value.isNotEmpty(), onClick = {
                    val chars = value.toCharArray()
                    value = ""
                    askPassword = false
                    passwordNote = null
                    val action = pending
                    pending = null
                    scope.launch {
                        val result = try {
                            withContext(Dispatchers.IO) { vault.verifyAppPassword(chars) }
                        } catch (e: Exception) {
                            error = UserMessage.text(
                                activity, e,
                                if (isPin) R.string.security_check_pin_failed else R.string.security_check_password_failed,
                            )
                            null
                        } finally {
                            chars.fill(' ')
                        }
                        when (result) {
                            PasswordCheck.Ok -> action?.second?.invoke()
                            PasswordCheck.Wrong -> error = activity.getString(
                                if (isPin) R.string.security_wrong_pin else R.string.security_wrong_password
                            )
                            is PasswordCheck.LockedOut -> error = UnlockAttempts.lockoutMessage(activity, result.remainingMillis)
                            null -> Unit
                        }
                    }
                }) { Text(stringResource(R.string.security_continue)) }
            },
            dismissButton = {
                TextButton(onClick = { askPassword = false; pending = null; passwordNote = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
    if (error != null) {
        AlertDialog(
            onDismissRequest = { error = null },
            title = { Text(stringResource(R.string.security_confirm_failed_title)) },
            text = { Text(error ?: "") },
            confirmButton = { TextButton(onClick = { error = null }) { Text(stringResource(R.string.security_ok)) } },
        )
    }

    return { title, onGranted ->
        val hasPassword = vault.passwordKeyBlobExists()
        val biometricOnly = vault.lockMode == LockMode.BIOMETRIC_ONLY && !vault.duressBlobExists()
        val keyState = if (biometricOnly) KeystoreMasterKey.biometricOnlyKeyState() else null
        val keyValid = keyState == KeystoreMasterKey.BiometricOnlyKeyState.VALID
        val changedNote = activity.getString(
            if (isPin) R.string.security_biometric_changed_note_pin else R.string.security_biometric_changed_note_password
        )
        val unavailableNote = activity.getString(
            if (isPin) R.string.security_biometric_unavailable_note_pin else R.string.security_biometric_unavailable_note_password
        )

        fun askForPassword(note: String?) {
            pending = title to onGranted
            passwordNote = note
            askPassword = true
        }

        val route = OwnerCheckPolicy.route(
            hasAppPassword = hasPassword,
            requireAppPassword = requireAppPassword,
            passwordIsOnlyUnlock = vault.passwordIsOnlyUnlock(),
            biometricOnlyMode = biometricOnly,
            biometricOnlyUsable = biometricOnly && keyValid && BiometricGate.hasBiometric(activity),
            systemPromptAvailable = BiometricGate.canAuthenticateDefault(activity),
            deviceSecure = BiometricGate.isDeviceSecure(activity),
            legacyCredentialScreen = Build.VERSION.SDK_INT < Build.VERSION_CODES.R,
        )
        when (route) {
            OwnerCheckPolicy.Route.APP_PASSWORD -> askForPassword(
                when {
                    !biometricOnly || requireAppPassword -> null
                    !keyValid -> changedNote
                    else -> unavailableNote
                }
            )
            OwnerCheckPolicy.Route.BIOMETRIC_ONLY, OwnerCheckPolicy.Route.SYSTEM_PROMPT -> scope.launch {
                try {
                    BiometricGate.confirm(activity, title, activity.getString(R.string.security_confirm_subtitle))
                    onGranted()
                } catch (e: BiometricGateException) {
                    when {
                        BiometricGate.isCancelCode(e.code) -> Unit
                        // Biometrics only and the biometric can't count right now: the password,
                        // never the device credential (E6, M-3).
                        route == OwnerCheckPolicy.Route.BIOMETRIC_ONLY && hasPassword &&
                            BiometricGate.isUnavailableCode(e.code) -> askForPassword(
                            if (e.code == BiometricGate.CODE_ENROLMENT_CHANGED) changedNote else unavailableNote
                        )
                        else -> error = UserMessage.text(activity, e, R.string.core_auth_failed)
                    }
                }
            }
            OwnerCheckPolicy.Route.DEVICE_CREDENTIAL_SCREEN -> {
                val intent = BiometricGate.deviceCredentialIntent(
                    activity, title, activity.getString(R.string.security_device_credential_subtitle),
                )
                if (intent != null) {
                    credentialAction = onGranted
                    // The credential screen is a round trip out of the app, like a file picker.
                    vault.autoLockSuppressed = true
                    credentialLauncher.launch(intent)
                } else {
                    error = activity.getString(R.string.security_owner_check_unavailable)
                }
            }
            OwnerCheckPolicy.Route.REFUSE -> error = activity.getString(R.string.security_owner_check_unavailable)
            OwnerCheckPolicy.Route.PASS -> onGranted()
        }
    }
}
