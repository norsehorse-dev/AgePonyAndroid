package com.agepony.app.ui.files

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.NoMatchingVaultIdentityException
import com.agepony.app.vault.Vault
import com.agepony.app.vault.WrongPassphraseException
import com.agepony.app.vault.toAgeIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

//
// Decrypt flow (Phase 2c-3b). Android counterpart of iOS's DecryptFlow:
//   pick .age (SAF) -> normalize armor -> try vault identities -> if none match,
//   ask for a passphrase (scrypt) -> save plaintext (SAF).
// Armor is auto-detected via the BEGIN marker; the header is never parsed
// directly (we just try identities, then passphrase).
//

private enum class DecryptStage { PICK, WORKING, NEED_PASSPHRASE, DONE }

@Composable
fun DecryptFlow(vault: Vault, modifier: Modifier = Modifier, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var stage by remember { mutableStateOf(DecryptStage.PICK) }
    var sourceName by remember { mutableStateOf("file.age") }
    var binary by remember { mutableStateOf<ByteArray?>(null) }
    var triedIdentities by remember { mutableStateOf(false) }
    var passphrase by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var outputBytes by remember { mutableStateOf<ByteArray?>(null) }
    var savedName by remember { mutableStateOf<String?>(null) }

    val createOutput = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        val bytes = outputBytes
        if (uri == null || bytes == null) {
            // User cancelled the save; stay where they were.
            if (stage == DecryptStage.WORKING) {
                stage = if (triedIdentities) DecryptStage.NEED_PASSPHRASE else DecryptStage.PICK
            }
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                        ?: throw IllegalStateException("Couldn't open the destination.")
                }
                savedName = documentName(context, uri)
                stage = DecryptStage.DONE
            } catch (e: Exception) {
                error = e.message ?: "Couldn't save the file."
                stage = DecryptStage.NEED_PASSPHRASE
            }
        }
    }

    val openInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        error = null
        passphrase = ""
        triedIdentities = false
        stage = DecryptStage.WORKING
        scope.launch {
            try {
                val name = withContext(Dispatchers.IO) { documentName(context, uri) }
                val raw = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw IllegalStateException("Couldn't open the file.")
                }
                sourceName = name
                val bin = withContext(Dispatchers.Default) { FileEncryptor.toBinary(raw) }
                binary = bin

                val ids = vault.identities.mapNotNull { runCatching { it.toAgeIdentity() }.getOrNull() }
                if (ids.isEmpty()) {
                    triedIdentities = true
                    stage = DecryptStage.NEED_PASSPHRASE
                    return@launch
                }
                triedIdentities = true
                try {
                    val plain = withContext(Dispatchers.Default) {
                        FileEncryptor.decryptWithIdentities(bin, ids)
                    }
                    outputBytes = plain
                    vault.autoLockSuppressed = true
                    createOutput.launch(FileEncryptor.decryptedName(name))
                } catch (e: NoMatchingVaultIdentityException) {
                    stage = DecryptStage.NEED_PASSPHRASE
                } catch (e: OutOfMemoryError) {
                    error = "Not enough memory to decrypt this file on this device."
                    stage = DecryptStage.NEED_PASSPHRASE
                } catch (e: Exception) {
                    error = e.message ?: "This doesn't look like an age file."
                    stage = DecryptStage.PICK
                }
            } catch (e: Exception) {
                error = e.message ?: "Couldn't read the file."
                stage = DecryptStage.PICK
            }
        }
    }

    fun reset() {
        sourceName = "file.age"; binary = null; triedIdentities = false
        passphrase = ""; error = null; outputBytes = null; savedName = null
        stage = DecryptStage.PICK
    }

    Column(modifier.fillMaxSize()) {
        when (stage) {
            DecryptStage.PICK -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text("Decrypt a file", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    "Pick an age file (.age, binary or armored). AgePony tries your identities first, " +
                        "then offers a passphrase if the file needs one.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (error != null) ErrorLine(error!!)
                Button(
                    onClick = { error = null; vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Pick a file…") }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            DecryptStage.WORKING -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                Text("Decrypting…", modifier = Modifier.padding(top = 16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            DecryptStage.NEED_PASSPHRASE -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text("Passphrase", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    sourceName,
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    "No matching identity in your vault. If this file was encrypted with a passphrase, enter it.",
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
                if (error != null) ErrorLine(error!!)
                Button(
                    onClick = {
                        val bin = binary ?: return@Button
                        if (passphrase.isEmpty()) { error = "Enter the passphrase."; return@Button }
                        error = null
                        stage = DecryptStage.WORKING
                        scope.launch {
                            try {
                                val plain = withContext(Dispatchers.Default) {
                                    FileEncryptor.decryptWithPassphrase(bin, passphrase)
                                }
                                outputBytes = plain
                                vault.autoLockSuppressed = true
                                createOutput.launch(FileEncryptor.decryptedName(sourceName))
                            } catch (e: WrongPassphraseException) {
                                error = e.message
                                stage = DecryptStage.NEED_PASSPHRASE
                            } catch (e: OutOfMemoryError) {
                                error = "Not enough memory to derive the key — the file's work factor is very high."
                                stage = DecryptStage.NEED_PASSPHRASE
                            } catch (e: Exception) {
                                error = e.message ?: "Decrypt failed."
                                stage = DecryptStage.NEED_PASSPHRASE
                            }
                        }
                    },
                    enabled = passphrase.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Decrypt") }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            DecryptStage.DONE -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text("Decrypted ✓", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    savedName ?: FileEncryptor.decryptedName(sourceName),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp, bottom = 24.dp),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Button(onClick = { reset() }, modifier = Modifier.fillMaxWidth()) { Text("Decrypt another") }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Done") }
            }
        }
    }
}

@Composable
private fun ErrorLine(message: String) {
    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
}

private fun documentName(context: Context, uri: Uri): String {
    var name = "file.age"
    context.contentResolver.query(uri, null, null, null, null)?.use { c ->
        val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (c.moveToFirst() && idx >= 0) c.getString(idx)?.let { name = it }
    }
    return name
}
