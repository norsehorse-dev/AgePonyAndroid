package com.agepony.app.ui.text

import com.agepony.app.ui.UserMessage
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import android.content.ClipboardManager
import com.agepony.app.security.ClipboardGuard
import com.agepony.app.share.ShareOut
import com.agepony.app.share.ShareSniff
import androidx.compose.ui.unit.dp
import com.agepony.app.ui.files.RecipientPicker
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.NoMatchingVaultIdentityException
import com.agepony.app.vault.TextDecryptor
import com.agepony.app.vault.Vault
import com.agepony.app.vault.toAgeIdentity
import com.agepony.core.recipients.AgeRecipient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.foundation.layout.imePadding
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.NavRow
import com.agepony.app.ui.components.ScreenPadding
import com.agepony.app.ui.components.SecondaryAction
import com.agepony.app.ui.components.DoneAction
import com.agepony.app.ui.components.PrimaryAction
import com.agepony.app.ui.components.RowAction
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.files.DecryptedHeadline
import com.agepony.app.ui.files.SignatureVerdictPanel
import com.agepony.app.ui.files.textVerdict
import com.agepony.app.ui.files.textVerdictNote
import com.agepony.app.ui.components.showOwnCopyConfirmation
import com.agepony.app.ui.theme.mono

//
// Text tab (Phase 2d-2). Android counterpart of iOS's Text mode: in-memory,
// no file picker. Encrypt a text blob to ASCII-armored age output (copy it into
// chat/email/forums); paste an armored block to decrypt. Encrypt reuses the
// Files-tab RecipientPicker; decrypt tries vault identities, then a passphrase.
// Output is always armored (binary would defeat the point of text mode).
//
// 5.1.0 (iOS 5.1.1 L-1, L-3): a signature in the text (a header stanza or a signed bundle) is
// checked as the file decrypt checks it and shown under the plaintext; a failed one also changes
// the headline. Decrypt has a Paste button that reads the clipboard only when tapped.
//

private enum class TextMode { HOME, ENCRYPT, DECRYPT }

private const val MAX_SAVED_INPUT = 64 * 1024

@Composable
fun TextScreen(vault: Vault, modifier: Modifier = Modifier) {
    var mode by rememberSaveable { mutableStateOf(TextMode.HOME) }

    when (mode) {
        TextMode.HOME -> AgeScreen(title = stringResource(R.string.text_title), modifier = modifier) { padding ->
            Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())) {
                Text(
                    stringResource(R.string.text_intro),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = ScreenPadding, vertical = 8.dp),
                )
                NavRow(stringResource(R.string.text_encrypt), onClick = { mode = TextMode.ENCRYPT })
                ListDivider(Modifier.padding(start = ScreenPadding))
                NavRow(stringResource(R.string.text_decrypt), onClick = { mode = TextMode.DECRYPT })
            }
        }

        TextMode.ENCRYPT -> TextEncrypt(vault = vault, modifier = modifier, onClose = { mode = TextMode.HOME })
        TextMode.DECRYPT -> TextDecrypt(vault = vault, modifier = modifier, onClose = { mode = TextMode.HOME })
    }
}

// MARK: - Encrypt

private enum class EncStage { FORM, PICKING, WORKING, RESULT }

/**
 * [initialText] pre-fills the input (text shared in from another app). [onReplace], when set,
 * offers to hand the armored result back to the app whose selection started this
 * (ACTION_PROCESS_TEXT), replacing the selected text with ciphertext.
 */
@Composable
internal fun TextEncrypt(
    vault: Vault,
    modifier: Modifier,
    onClose: () -> Unit,
    initialText: String = "",
    onReplace: ((String) -> Unit)? = null,
    replaceUnavailableNote: String? = null,
) {
    var stage by remember { mutableStateOf(EncStage.FORM) }
    // Plaintext stays out of the saved-state Bundle, which the system writes to disk on process
    // death (audit L-23). Losing a draft to a process kill is the accepted cost.
    var input by remember { mutableStateOf(initialText) }
    var recipients by remember { mutableStateOf<List<AgeRecipient>>(emptyList()) }
    var passphrase by remember { mutableStateOf<String?>(null) }
    var result by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    if (stage == EncStage.PICKING) {
        AgeScreen(
            title = stringResource(R.string.files_choose_recipients),
            modifier = modifier,
            onBack = { stage = EncStage.FORM },
        ) { padding ->
            RecipientPicker(
                vault = vault,
                modifier = Modifier.fillMaxSize().padding(padding),
                onCancel = { stage = EncStage.FORM },
                onConfirm = { r, p -> recipients = r; passphrase = p; stage = EncStage.FORM },
            )
        }
        return
    }

    AgeScreen(
        title = stringResource(R.string.text_encrypt),
        modifier = modifier,
        onBack = onClose,
        actions = { if (stage == EncStage.RESULT && result != null) DoneAction(onClose) },
    ) { padding ->
    Column(
        Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (stage == EncStage.RESULT && result != null) {
            CopyableResult(label = stringResource(R.string.text_armored_output), value = result!!, mono = true)
            val ctx = LocalContext.current
            if (onReplace != null) {
                // Copy is the filled button; replacing the selection is the other way out.
                SecondaryAction(
                    stringResource(R.string.text_replace_selection),
                    onClick = { onReplace(result!!) },
                    modifier = Modifier.fillMaxWidth(),
                )
            } else if (replaceUnavailableNote != null) {
                Text(
                    replaceUnavailableNote,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val shareTitle = stringResource(R.string.text_share_encrypted)
            SecondaryAction(
                stringResource(R.string.text_share),
                onClick = { ShareOut.text(ctx, result!!, shareTitle) },
                modifier = Modifier.fillMaxWidth(),
            )
            // Done sits in the app bar; the next text is its own row (5.1.0, U4).
            ListDivider()
            RowAction(
                stringResource(R.string.text_encrypt_another),
                onClick = { result = null; input = ""; recipients = emptyList(); passphrase = null; stage = EncStage.FORM },
            )
            return@Column
        }

        OutlinedTextField(
            value = input,
            onValueChange = { input = it; error = null },
            label = { Text(stringResource(R.string.text_input_label)) },
            minLines = 6,
            modifier = Modifier.fillMaxWidth(),
        )

        SectionHeader(stringResource(R.string.files_section_recipients))
        Text(
            recipientSummary(recipients.size, passphrase),
            style = MaterialTheme.typography.bodyMedium,
        )
        TextButton(onClick = { stage = EncStage.PICKING }) { Text(stringResource(R.string.files_choose_recipients)) }

        if (error != null) ErrorText(error!!)

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
                        error = context.getString(R.string.text_oom_encrypt)
                        stage = EncStage.FORM
                    } catch (e: Exception) {
                        error = UserMessage.text(context, e, R.string.text_encrypt_failed)
                        stage = EncStage.FORM
                    }
                }
            },
            enabled = canEncrypt,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                stringResource(if (stage == EncStage.WORKING) R.string.files_encrypting else R.string.text_encrypt_action),
            )
        }
        if (stage == EncStage.WORKING) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            }
        }
        TextButton(onClick = onClose) { Text(stringResource(R.string.action_cancel)) }
    }
    }
}

// MARK: - Decrypt

private enum class DecStage { FORM, NEED_PASSPHRASE, WORKING, RESULT }

/**
 * [initialText] pre-fills the input with shared text; only its armored block is kept, so a
 * message with a greeting around the ciphertext still decrypts. With [autoStart] the decrypt
 * begins at once.
 */
@Composable
internal fun TextDecrypt(
    vault: Vault,
    modifier: Modifier,
    onClose: () -> Unit,
    initialText: String = "",
    autoStart: Boolean = false,
) {
    var stage by remember { mutableStateOf(DecStage.FORM) }
    var input by if (initialText.length > MAX_SAVED_INPUT) remember { mutableStateOf(ShareSniff.extractArmor(initialText)) }
    else rememberSaveable { mutableStateOf(ShareSniff.extractArmor(initialText)) }
    var confirmShare by remember { mutableStateOf(false) }
    var binary by remember { mutableStateOf<ByteArray?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<String?>(null) }
    // The verdict on the text's signature, when it carried one (L-1).
    var signature by remember { mutableStateOf<TextDecryptor.SignatureCheck?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    fun startDecrypt() = decryptTextInto(
        context, input, vault, scope,
        setStage = { stage = it }, setBinary = { binary = it },
        setResult = { text, check -> result = text; signature = check }, setError = { error = it },
    )
    var autoStarted by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        if (autoStart && !autoStarted && input.isNotBlank()) { autoStarted = true; startDecrypt() }
    }

    if (confirmShare && result != null) {
        AlertDialog(
            onDismissRequest = { confirmShare = false },
            title = { Text(stringResource(R.string.text_share_decrypted_title)) },
            text = {
                Text(stringResource(R.string.text_share_decrypted_body))
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmShare = false
                    ShareOut.text(context, result!!, context.getString(R.string.text_share_decrypted))
                }) { Text(stringResource(R.string.text_share_anyway)) }
            },
            dismissButton = { TextButton(onClick = { confirmShare = false }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }

    AgeScreen(
        title = stringResource(R.string.text_decrypt),
        modifier = modifier,
        onBack = onClose,
        actions = { if (stage == DecStage.RESULT && result != null) DoneAction(onClose) },
    ) { padding ->
    Column(
        Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (stage == DecStage.RESULT && result != null) {
            val check = signature
            // A failed signature never sits under a neutral result (L-3).
            if (check != null && check.failed) DecryptedHeadline(signatureFailed = true)
            CopyableResult(label = stringResource(R.string.text_decrypted), value = result!!, mono = false)
            ListDivider()
            if (check != null) {
                // Shown even when it failed: the plaintext is already on screen (L-1).
                SectionHeader(stringResource(R.string.text_signature))
                SignatureVerdictPanel(textVerdict(context, check))
                textVerdictNote(context, check)?.let { note ->
                    Text(
                        note,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                ListDivider()
            }
            SecondaryAction(
                stringResource(R.string.text_share),
                onClick = { confirmShare = true },
                modifier = Modifier.fillMaxWidth(),
            )
            // Done sits in the app bar; the next text is its own row (5.1.0, U4).
            ListDivider()
            RowAction(
                stringResource(R.string.text_decrypt_another),
                onClick = {
                    result = null; signature = null; input = ""; binary = null; passphrase = ""; stage = DecStage.FORM
                },
            )
            return@Column
        }

        OutlinedTextField(
            value = input,
            onValueChange = { input = it; error = null },
            label = { Text(stringResource(R.string.text_paste_label)) },
            minLines = 6,
            enabled = stage != DecStage.NEED_PASSPHRASE,
            modifier = Modifier.fillMaxWidth(),
        )
        // Reads the clipboard only when tapped, and replaces whatever is in the field. Hidden
        // once the text is decrypted, and while a passphrase is asked for this text.
        if (stage == DecStage.FORM || stage == DecStage.WORKING) {
            SecondaryAction(
                text = stringResource(R.string.text_paste),
                enabled = stage == DecStage.FORM,
                onClick = {
                    val clipboard = context.getSystemService(ClipboardManager::class.java)
                    val clip = runCatching { clipboard?.primaryClip }.getOrNull()
                    val pasted = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
                    if (!pasted.isNullOrEmpty()) {
                        input = ShareSniff.extractArmor(pasted)
                        error = null
                    }
                },
            )
        }

        if (stage == DecStage.NEED_PASSPHRASE) {
            Text(
                stringResource(R.string.text_no_identity),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it; error = null },
                label = { Text(stringResource(R.string.files_passphrase)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
        }

        if (error != null) ErrorText(error!!)

        if (stage == DecStage.WORKING) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            }
        }

        if (stage == DecStage.NEED_PASSPHRASE) {
            Button(
                onClick = {
                    val bin = binary ?: return@Button
                    if (passphrase.isEmpty()) { error = context.getString(R.string.files_enter_passphrase); return@Button }
                    error = null
                    stage = DecStage.WORKING
                    val p = passphrase
                    val known = vault.identities.toList()
                    val signers = vault.signers.toList()
                    scope.launch {
                        try {
                            // Guarded against a work factor that won't fit in memory (L-2), and a
                            // signed bundle inside is checked (L-1).
                            val outcome = withContext(Dispatchers.Default) {
                                TextDecryptor.decrypt(bin, emptyList(), p, known, signers)
                            }
                            result = String(outcome.plaintext, Charsets.UTF_8)
                            signature = outcome.signature
                            stage = DecStage.RESULT
                        } catch (e: OutOfMemoryError) {
                            error = context.getString(R.string.text_oom_derive)
                            stage = DecStage.NEED_PASSPHRASE
                        } catch (e: Exception) {
                            error = UserMessage.text(context, e, R.string.text_decrypt_failed); stage = DecStage.NEED_PASSPHRASE
                        }
                    }
                },
                enabled = passphrase.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.text_decrypt_with_passphrase)) }
        } else {
            Button(
                onClick = { startDecrypt() },
                enabled = stage != DecStage.WORKING && input.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    stringResource(if (stage == DecStage.WORKING) R.string.files_decrypting else R.string.files_decrypt_action),
                )
            }
        }
        TextButton(onClick = onClose) { Text(stringResource(R.string.action_cancel)) }
    }
    }
}

private fun decryptTextInto(
    context: android.content.Context,
    input: String,
    vault: Vault,
    scope: kotlinx.coroutines.CoroutineScope,
    setStage: (DecStage) -> Unit,
    setBinary: (ByteArray) -> Unit,
    setResult: (String, TextDecryptor.SignatureCheck?) -> Unit,
    setError: (String?) -> Unit,
) {
    if (input.isBlank()) { setError(context.getString(R.string.text_paste_first)); return }
    setError(null)
    setStage(DecStage.WORKING)
    val raw = input.toByteArray(Charsets.UTF_8)
    scope.launch {
        try {
            val bin = withContext(Dispatchers.Default) { FileEncryptor.toBinary(raw) }
            setBinary(bin)
            val ids = vault.identities.mapNotNull { runCatching { it.toAgeIdentity() }.getOrNull() }
            val known = vault.identities.toList()
            val signers = vault.signers.toList()
            try {
                // Checks a signature stanza or signed bundle as the file decrypt does (L-1).
                val outcome = withContext(Dispatchers.Default) {
                    TextDecryptor.decrypt(bin, ids, null, known, signers)
                }
                setResult(String(outcome.plaintext, Charsets.UTF_8), outcome.signature)
                setStage(DecStage.RESULT)
            } catch (e: NoMatchingVaultIdentityException) {
                setStage(DecStage.NEED_PASSPHRASE)
            }
        } catch (e: OutOfMemoryError) {
            setError(context.getString(R.string.text_oom_decrypt)); setStage(DecStage.FORM)
        } catch (e: Exception) {
            setError(UserMessage.textUnlessCancelled(context, e, R.string.text_not_armored))
            setStage(DecStage.FORM)
        }
    }
}

// MARK: - Shared

@Composable
private fun CopyableResult(label: String, value: String, mono: Boolean) {
    val context = LocalContext.current
    var copied by remember { mutableStateOf(false) }
    LaunchedEffect(copied) {
        if (copied) { delay(1500); copied = false }
    }
    SectionHeader(label)
    // Plain, non-selectable text rather than a read-only text field: a text field offers the
    // system's long-press Copy, which would skip ClipboardGuard's sensitive flag and timed clear
    // (audit L-23). The Copy button below is the only way out.
    Surface(
        shape = MaterialTheme.shapes.extraSmall,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            value,
            // Monospace for armored ciphertext only; decrypted text is prose.
            style = if (mono) MaterialTheme.typography.mono else MaterialTheme.typography.bodyLarge,
            minLines = 6,
            modifier = Modifier.fillMaxWidth().padding(16.dp),
        )
    }
    // Copying the result is what the screen is for, so it is the filled button.
    PrimaryAction(
        stringResource(if (copied) R.string.action_copied else R.string.action_copy),
        // Android 13+ confirms the copy itself; only older versions get our own "Copied".
        onClick = { ClipboardGuard.copySensitive(context, value); copied = showOwnCopyConfirmation },
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun recipientSummary(count: Int, passphrase: String?): String = when {
    !passphrase.isNullOrEmpty() -> stringResource(R.string.files_passphrase_only_scrypt)
    count == 0 -> stringResource(R.string.files_recipients_none)
    else -> pluralStringResource(R.plurals.transfer_recipients, count, count)
}

