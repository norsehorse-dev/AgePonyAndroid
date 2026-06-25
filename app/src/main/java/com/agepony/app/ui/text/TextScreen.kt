package com.agepony.app.ui.text

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.agepony.app.ui.files.RecipientPicker
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.NoMatchingVaultIdentityException
import com.agepony.app.vault.Vault
import com.agepony.app.vault.WrongPassphraseException
import com.agepony.app.vault.toAgeIdentity
import com.agepony.core.recipients.AgeRecipient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

//
// Text tab (Phase 2d-2). Android counterpart of iOS's Text mode: in-memory,
// no file picker. Encrypt a text blob to ASCII-armored age output (copy it into
// chat/email/forums); paste an armored block to decrypt. Encrypt reuses the
// Files-tab RecipientPicker; decrypt tries vault identities, then a passphrase.
// Output is always armored (binary would defeat the point of text mode).
//

private enum class TextMode { HOME, ENCRYPT, DECRYPT }

@Composable
fun TextScreen(vault: Vault, modifier: Modifier = Modifier) {
    var mode by rememberSaveable { mutableStateOf(TextMode.HOME) }

    when (mode) {
        TextMode.HOME -> Column(
            modifier.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text("Text", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
            Text(
                "Encrypt or decrypt a block of text — handy for chat, email, or anywhere binary attachments are awkward.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 8.dp, bottom = 28.dp),
            )
            Button(onClick = { mode = TextMode.ENCRYPT }, modifier = Modifier.fillMaxWidth()) { Text("Encrypt text") }
            OutlinedButton(
                onClick = { mode = TextMode.DECRYPT },
                modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
            ) { Text("Decrypt text") }
        }

        TextMode.ENCRYPT -> TextEncrypt(vault = vault, modifier = modifier, onClose = { mode = TextMode.HOME })
        TextMode.DECRYPT -> TextDecrypt(vault = vault, modifier = modifier, onClose = { mode = TextMode.HOME })
    }
}

// MARK: - Encrypt

private enum class EncStage { FORM, PICKING, WORKING, RESULT }

@Composable
private fun TextEncrypt(vault: Vault, modifier: Modifier, onClose: () -> Unit) {
    var stage by remember { mutableStateOf(EncStage.FORM) }
    var input by rememberSaveable { mutableStateOf("") }
    var recipients by remember { mutableStateOf<List<AgeRecipient>>(emptyList()) }
    var passphrase by remember { mutableStateOf<String?>(null) }
    var result by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    if (stage == EncStage.PICKING) {
        RecipientPicker(
            vault = vault,
            modifier = modifier,
            onCancel = { stage = EncStage.FORM },
            onConfirm = { r, p -> recipients = r; passphrase = p; stage = EncStage.FORM },
        )
        return
    }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Encrypt text", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)

        if (stage == EncStage.RESULT && result != null) {
            CopyableResult(label = "Armored output", value = result!!)
            Button(
                onClick = { result = null; input = ""; recipients = emptyList(); passphrase = null; stage = EncStage.FORM },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Encrypt another") }
            OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Done") }
            return@Column
        }

        OutlinedTextField(
            value = input,
            onValueChange = { input = it; error = null },
            label = { Text("Text to encrypt") },
            minLines = 6,
            modifier = Modifier.fillMaxWidth(),
        )

        Text("Recipients", style = MaterialTheme.typography.titleSmall)
        Text(
            recipientSummary(recipients.size, passphrase),
            style = MaterialTheme.typography.bodyMedium,
        )
        TextButton(onClick = { stage = EncStage.PICKING }) { Text("Choose recipients") }

        if (error != null) ErrorLine(error!!)

        val canEncrypt = stage != EncStage.WORKING && input.isNotEmpty() &&
            (recipients.isNotEmpty() || !passphrase.isNullOrEmpty())
        Button(
            onClick = {
                error = null
                stage = EncStage.WORKING
                val bytes = input.toByteArray(Charsets.UTF_8)
                val r = recipients
                val p = passphrase
                scope.launch {
                    try {
                        val out = withContext(Dispatchers.Default) {
                            FileEncryptor.encrypt(bytes, r, p, armor = true)
                        }
                        result = String(out, Charsets.UTF_8)
                        stage = EncStage.RESULT
                    } catch (e: OutOfMemoryError) {
                        error = "Not enough memory to encrypt with a passphrase on this device."
                        stage = EncStage.FORM
                    } catch (e: Exception) {
                        error = e.message ?: "Encrypt failed."
                        stage = EncStage.FORM
                    }
                }
            },
            enabled = canEncrypt,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(if (stage == EncStage.WORKING) "Encrypting…" else "Encrypt") }
        if (stage == EncStage.WORKING) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            }
        }
        TextButton(onClick = onClose) { Text("Cancel") }
    }
}

// MARK: - Decrypt

private enum class DecStage { FORM, NEED_PASSPHRASE, WORKING, RESULT }

@Composable
private fun TextDecrypt(vault: Vault, modifier: Modifier, onClose: () -> Unit) {
    var stage by remember { mutableStateOf(DecStage.FORM) }
    var input by rememberSaveable { mutableStateOf("") }
    var binary by remember { mutableStateOf<ByteArray?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Decrypt text", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)

        if (stage == DecStage.RESULT && result != null) {
            CopyableResult(label = "Decrypted text", value = result!!)
            Button(
                onClick = {
                    result = null; input = ""; binary = null; passphrase = ""; stage = DecStage.FORM
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Decrypt another") }
            OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Done") }
            return@Column
        }

        OutlinedTextField(
            value = input,
            onValueChange = { input = it; error = null },
            label = { Text("Paste armored age text (-----BEGIN AGE ENCRYPTED FILE-----)") },
            minLines = 6,
            enabled = stage != DecStage.NEED_PASSPHRASE,
            modifier = Modifier.fillMaxWidth(),
        )

        if (stage == DecStage.NEED_PASSPHRASE) {
            Text(
                "No matching identity. If this was encrypted with a passphrase, enter it.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it; error = null },
                label = { Text("Passphrase") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        if (error != null) ErrorLine(error!!)

        if (stage == DecStage.WORKING) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            }
        }

        if (stage == DecStage.NEED_PASSPHRASE) {
            Button(
                onClick = {
                    val bin = binary ?: return@Button
                    if (passphrase.isEmpty()) { error = "Enter the passphrase."; return@Button }
                    error = null
                    stage = DecStage.WORKING
                    val p = passphrase
                    scope.launch {
                        try {
                            val plain = withContext(Dispatchers.Default) {
                                FileEncryptor.decryptWithPassphrase(bin, p)
                            }
                            result = String(plain, Charsets.UTF_8)
                            stage = DecStage.RESULT
                        } catch (e: WrongPassphraseException) {
                            error = e.message; stage = DecStage.NEED_PASSPHRASE
                        } catch (e: OutOfMemoryError) {
                            error = "Not enough memory to derive the key — the work factor is very high."
                            stage = DecStage.NEED_PASSPHRASE
                        } catch (e: Exception) {
                            error = e.message ?: "Decrypt failed."; stage = DecStage.NEED_PASSPHRASE
                        }
                    }
                },
                enabled = passphrase.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Decrypt with passphrase") }
        } else {
            Button(
                onClick = {
                    if (input.isBlank()) { error = "Paste some text first."; return@Button }
                    error = null
                    stage = DecStage.WORKING
                    val raw = input.toByteArray(Charsets.UTF_8)
                    scope.launch {
                        try {
                            val bin = withContext(Dispatchers.Default) { FileEncryptor.toBinary(raw) }
                            binary = bin
                            val ids = vault.identities.mapNotNull { runCatching { it.toAgeIdentity() }.getOrNull() }
                            try {
                                val plain = withContext(Dispatchers.Default) {
                                    FileEncryptor.decryptWithIdentities(bin, ids)
                                }
                                result = String(plain, Charsets.UTF_8)
                                stage = DecStage.RESULT
                            } catch (e: NoMatchingVaultIdentityException) {
                                stage = DecStage.NEED_PASSPHRASE
                            }
                        } catch (e: OutOfMemoryError) {
                            error = "Not enough memory to decrypt this text."; stage = DecStage.FORM
                        } catch (e: Exception) {
                            error = e.message ?: "This doesn't look like an armored age block."
                            stage = DecStage.FORM
                        }
                    }
                },
                enabled = stage != DecStage.WORKING && input.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (stage == DecStage.WORKING) "Decrypting…" else "Decrypt") }
        }
        TextButton(onClick = onClose) { Text("Cancel") }
    }
}

// MARK: - Shared

@Composable
private fun CopyableResult(label: String, value: String) {
    val clipboard = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }
    LaunchedEffect(copied) {
        if (copied) { delay(1500); copied = false }
    }
    Text(label, style = MaterialTheme.typography.titleSmall)
    OutlinedTextField(
        value = value,
        onValueChange = {},
        readOnly = true,
        minLines = 6,
        textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        modifier = Modifier.fillMaxWidth(),
    )
    Button(
        onClick = { clipboard.setText(AnnotatedString(value)); copied = true },
        modifier = Modifier.fillMaxWidth(),
    ) { Text(if (copied) "Copied ✓" else "Copy") }
    HorizontalDivider()
}

private fun recipientSummary(count: Int, passphrase: String?): String = when {
    !passphrase.isNullOrEmpty() -> "Passphrase only (scrypt)"
    count == 0 -> "None chosen yet"
    count == 1 -> "1 recipient"
    else -> "$count recipients"
}

@Composable
private fun ErrorLine(message: String) {
    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
}
