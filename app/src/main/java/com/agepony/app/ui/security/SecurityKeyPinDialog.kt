package com.agepony.app.ui.security

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.agepony.app.security.SecurityKeyService
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Detect-and-prompt PIN flow for security keys. Touch-only keys never see this; the dialog
 * appears only when the authenticator reports PIN required (CTAP 0x36) and re-appears with a
 * wrong-PIN message after 0x31.
 *
 * [PinPromptController] implements [SecurityKeyService.PinProvider]. Pass it to the service,
 * and render [SecurityKeyPinPrompt] with the same controller in the signing screen; the
 * suspend handshake parks on the channel until the user submits or cancels.
 */
class PinPromptController : SecurityKeyService.PinProvider {
    private val _visible = MutableStateFlow(false)
    val visible: StateFlow<Boolean> = _visible.asStateFlow()

    private val _wrongAttempt = MutableStateFlow(false)
    val wrongAttempt: StateFlow<Boolean> = _wrongAttempt.asStateFlow()

    private val responses = Channel<String?>(capacity = 1)

    override suspend fun providePin(wrongPreviousAttempt: Boolean): String? {
        _wrongAttempt.value = wrongPreviousAttempt
        _visible.value = true
        val pin = responses.receive()
        _visible.value = false
        return pin
    }

    fun submit(pin: String) { responses.trySend(pin) }
    fun cancel() { responses.trySend(null) }
}

/** Renders the PIN dialog when [controller] requests it. */
@Composable
fun SecurityKeyPinPrompt(controller: PinPromptController) {
    val visible by controller.visible.collectAsState()
    val wrongAttempt by controller.wrongAttempt.collectAsState()
    if (visible) {
        SecurityKeyPinDialog(
            wrongAttempt = wrongAttempt,
            onSubmit = { controller.submit(it) },
            onCancel = { controller.cancel() },
        )
    }
}

@Composable
fun SecurityKeyPinDialog(
    wrongAttempt: Boolean,
    onSubmit: (String) -> Unit,
    onCancel: () -> Unit,
) {
    var pin by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Security key PIN") },
        text = {
            Column {
                Text(
                    if (wrongAttempt) "Incorrect PIN. Try again."
                    else "Enter your security key PIN to authorize signing."
                )
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it },
                    singleLine = true,
                    label = { Text("PIN") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.padding(top = 12.dp),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { if (pin.isNotEmpty()) onSubmit(pin) }, enabled = pin.isNotEmpty()) {
                Text("Unlock")
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}
