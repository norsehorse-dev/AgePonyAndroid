package com.agepony.app.ui.security

import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.fragment.app.FragmentActivity
import com.agepony.app.security.BiometricGate
import com.agepony.app.security.BiometricGateException
import com.agepony.app.security.PasswordVault
import com.agepony.app.vault.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Re-authentication before private key material leaves the app (sending keys to another device,
 * printing a paper backup). Same rule as revealing a private key: biometric or device credential
 * when available, otherwise the app password or PIN, otherwise straight through for a vault with
 * no lock at all.
 *
 * Returns a function to call with a title and the action to run once the user has confirmed.
 */
@Composable
fun rememberSensitiveConfirm(vault: Vault): (title: String, onGranted: () -> Unit) -> Unit {
    val activity = LocalContext.current as FragmentActivity
    val scope = rememberCoroutineScope()
    var pending by remember { mutableStateOf<Pair<String, () -> Unit>?>(null) }
    var askPassword by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val isPin = vault.unlockSecretKind == "pin"
    val noun = if (isPin) "PIN" else "password"

    if (askPassword && pending != null) {
        var value by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { askPassword = false; pending = null },
            title = { Text("Confirm your $noun") },
            text = {
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    singleLine = true,
                    label = { Text(noun.replaceFirstChar { it.uppercase() }) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = if (isPin) KeyboardType.NumberPassword else KeyboardType.Password,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                TextButton(enabled = value.isNotEmpty(), onClick = {
                    val chars = value.toCharArray()
                    value = ""
                    askPassword = false
                    val action = pending
                    pending = null
                    scope.launch {
                        val ok = withContext(Dispatchers.IO) {
                            val real = if (vault.passwordKeyBlobExists()) vault.readPasswordKeyBlob() else null
                            real != null && PasswordVault.tryUnlock(chars, real, null) is PasswordVault.Outcome.Real
                        }
                        chars.fill(' ')
                        if (ok) action?.second?.invoke() else error = "Wrong $noun."
                    }
                }) { Text("Continue") }
            },
            dismissButton = { TextButton(onClick = { askPassword = false; pending = null }) { Text("Cancel") } },
        )
    }
    if (error != null) {
        AlertDialog(
            onDismissRequest = { error = null },
            title = { Text("Couldn't confirm it's you") },
            text = { Text(error ?: "") },
            confirmButton = { TextButton(onClick = { error = null }) { Text("OK") } },
        )
    }

    return { title, onGranted ->
        when {
            BiometricGate.canAuthenticate(activity) -> scope.launch {
                try {
                    BiometricGate.confirm(activity, title, "Confirm it's you")
                    onGranted()
                } catch (e: BiometricGateException) {
                    if (e.code != BiometricPrompt.ERROR_USER_CANCELED && e.code != BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        error = e.message
                    }
                }
            }
            vault.passwordKeyBlobExists() -> { pending = title to onGranted; askPassword = true }
            else -> onGranted()
        }
    }
}
