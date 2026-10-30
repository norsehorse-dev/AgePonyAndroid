package com.agepony.app.ui.passphrase

import com.agepony.app.ui.UserMessage
import android.net.Uri
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.agepony.app.security.ClipboardGuard
import com.agepony.app.share.ShareOut
import com.agepony.app.share.ShareSniff
import com.agepony.app.ui.files.DecryptFlow
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.foundation.layout.imePadding
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.PrimaryAction
import com.agepony.app.ui.components.RowAction
import com.agepony.app.ui.components.SecondaryAction
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.showOwnCopyConfirmation
import com.agepony.app.ui.theme.mono
import kotlinx.coroutines.delay

/**
 * Passphrase work without unlocking the vault (issue #13). The app lock guards the vault's keys
 * and notes; a passphrase file needs none of them, so asking for the app PIN first was a second
 * secret for one job. This screen never touches the vault's contents: it encrypts and decrypts
 * text with a passphrase, and decrypts passphrase files (the Files decrypt flow finds no vault
 * identities while locked and goes straight to the passphrase).
 */
@Composable
fun PassphraseOnlyScreen(
    vault: Vault,
    onClose: () -> Unit,
    initialText: String? = null,
    initialFile: Uri? = null,
) {
    var tab by rememberSaveable { mutableStateOf(if (initialFile != null) 1 else 0) }
    // The app bar back arrow and system back return to the unlock screen.
    AgeScreen(title = stringResource(R.string.app_passphrase_only_title), onBack = onClose) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Text(
                stringResource(R.string.app_passphrase_only_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            PrimaryTabRow(selectedTabIndex = tab, containerColor = MaterialTheme.colorScheme.background) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text(stringResource(R.string.app_tab_text)) })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text(stringResource(R.string.files_decrypt)) })
            }
            when (tab) {
                0 -> PassphraseText(vault, initialText.orEmpty())
                else -> DecryptFlow(vault = vault, initialUri = initialFile, showTopBar = false, onClose = onClose)
            }
        }
    }
}

@Composable
private fun PassphraseText(vault: Vault, initialText: String) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var input by remember { mutableStateOf(ShareSniff.extractArmor(initialText)) }
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<String?>(null) }
    var resultIsPlaintext by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val decrypting = ShareSniff.textLooksEncrypted(input)
    var copied by remember { mutableStateOf(false) }
    LaunchedEffect(copied) {
        if (copied) { delay(1500); copied = false }
    }

    Column(
        Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (result != null) {
            SectionHeader(stringResource(if (resultIsPlaintext) R.string.app_passphrase_decrypted_text else R.string.app_passphrase_armored_output))
            // Non-selectable text, so a long-press Copy can't skip ClipboardGuard (audit L-23).
            Surface(
                shape = MaterialTheme.shapes.extraSmall,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    result!!,
                    // Monospace for armored ciphertext only; decrypted text is prose.
                    style = if (resultIsPlaintext) MaterialTheme.typography.bodyLarge else MaterialTheme.typography.mono,
                    minLines = 6,
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                )
            }
            // Android 13+ confirms the copy itself; only older versions get our own "Copied".
            PrimaryAction(
                stringResource(if (copied) R.string.action_copied else R.string.action_copy),
                onClick = { ClipboardGuard.copySensitive(context, result!!); copied = showOwnCopyConfirmation },
                modifier = Modifier.fillMaxWidth(),
            )
            if (!resultIsPlaintext) {
                SecondaryAction(
                    stringResource(R.string.app_share_ellipsis),
                    onClick = { ShareOut.text(context, result!!, context.getString(R.string.app_passphrase_share_chooser)) },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            // The next text is its own row, as on the other done screens (5.1.0, U4).
            ListDivider()
            RowAction(
                stringResource(R.string.app_start_over),
                onClick = { result = null; input = ""; passphrase = ""; confirm = "" },
            )
            return@Column
        }

        OutlinedTextField(
            value = input, onValueChange = { input = it; error = null },
            label = { Text(stringResource(R.string.app_passphrase_input_label)) },
            minLines = 6, modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = passphrase, onValueChange = { passphrase = it; error = null },
            label = { Text(stringResource(R.string.notes_passphrase)) }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        if (!decrypting) {
            OutlinedTextField(
                value = confirm, onValueChange = { confirm = it; error = null },
                label = { Text(stringResource(R.string.notes_confirm_passphrase)) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        error?.let { ErrorText(it) }
        val ready = !busy && input.isNotBlank() && passphrase.isNotEmpty() && (decrypting || passphrase == confirm)
        Button(
            onClick = {
                busy = true
                val text = input
                val pass = passphrase
                scope.launch {
                    try {
                        if (decrypting) {
                            val plain = withContext(Dispatchers.Default) {
                                FileEncryptor.decryptWithPassphrase(FileEncryptor.toBinary(text.toByteArray(Charsets.UTF_8)), pass)
                            }
                            result = String(plain, Charsets.UTF_8); resultIsPlaintext = true
                        } else {
                            val out = withContext(Dispatchers.Default) {
                                FileEncryptor.encrypt(text.toByteArray(Charsets.UTF_8), emptyList(), pass, armor = true, workFactor = vault.scryptWorkFactor)
                            }
                            result = String(out, Charsets.UTF_8); resultIsPlaintext = false
                        }
                    } catch (e: OutOfMemoryError) {
                        error = context.getString(R.string.app_passphrase_oom)
                    } catch (e: Exception) {
                        // Wrong passphrase and scrypt memory each have their own sentence (U5).
                        error = UserMessage.text(
                            context, e,
                            if (decrypting) R.string.app_decrypt_failed else R.string.app_encrypt_failed,
                        )
                    } finally {
                        busy = false
                    }
                }
            },
            enabled = ready,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                stringResource(
                    if (decrypting) R.string.app_passphrase_decrypt_action else R.string.app_passphrase_encrypt_action
                )
            )
        }
        if (busy) CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
        if (!decrypting && confirm.isNotEmpty() && passphrase != confirm) {
            Text(stringResource(R.string.notes_passphrase_mismatch), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
    }
}
