package com.agepony.app.ui.security

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import com.agepony.app.security.piv.YubiKeyBroker

/**
 * The tap and PIN dialogs for YubiKey decryption. Rendered once at the root of each activity;
 * shows only while [YubiKeyBroker] is waiting on the user.
 */
@Composable
fun YubiKeyPromptHost() {
    val prompt by YubiKeyBroker.prompt.collectAsState()
    when (val p = prompt) {
        is YubiKeyBroker.Prompt.Tap -> AlertDialog(
            onDismissRequest = {},
            title = { Text(stringResource(R.string.security_yubikey_title)) },
            text = {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                    CircularProgressIndicator(Modifier.padding(bottom = 16.dp))
                    Text(p.message)
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { YubiKeyBroker.cancel() }) { Text(stringResource(R.string.action_cancel)) } },
        )
        is YubiKeyBroker.Prompt.Pin -> {
            var pin by remember(p) { mutableStateOf("") }
            AlertDialog(
                onDismissRequest = {},
                title = { Text(stringResource(R.string.security_yubikey_pin_title)) },
                text = {
                    Column {
                        Text(stringResource(R.string.security_yubikey_pin_body))
                        p.message?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp)) }
                        OutlinedTextField(
                            value = pin,
                            onValueChange = { if (it.length <= 8) pin = it },
                            singleLine = true,
                            label = { Text(stringResource(R.string.app_pin)) },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                        )
                    }
                },
                confirmButton = {
                    TextButton(enabled = pin.length >= 6, onClick = { YubiKeyBroker.submitPin(pin) }) { Text(stringResource(R.string.security_continue)) }
                },
                dismissButton = { TextButton(onClick = { YubiKeyBroker.cancel() }) { Text(stringResource(R.string.action_cancel)) } },
            )
        }
        null -> Unit
    }
}
