package com.agepony.app.ui.files

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
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
import com.agepony.app.vault.Vault
import com.agepony.core.recipients.AgeRecipient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

//
// Encrypt flow (Phase 2c-3a). Android counterpart of iOS's EncryptFlow:
//   pick input (SAF) -> configure (recipients + armor) -> encrypt -> save (SAF).
// The whole input is read into memory; suitable for typical files.
//

private enum class EncryptStage { PICK, CONFIGURE, PICKING, WORKING, DONE }

@Composable
fun EncryptFlow(vault: Vault, modifier: Modifier = Modifier, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var stage by remember { mutableStateOf(EncryptStage.PICK) }
    var sourceBytes by remember { mutableStateOf<ByteArray?>(null) }
    var sourceName by remember { mutableStateOf("file") }
    var sourceSize by remember { mutableStateOf(0L) }
    var recipients by remember { mutableStateOf<List<AgeRecipient>>(emptyList()) }
    var passphrase by remember { mutableStateOf<String?>(null) }
    var armor by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var outputBytes by remember { mutableStateOf<ByteArray?>(null) }
    var savedName by remember { mutableStateOf<String?>(null) }

    val openInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        error = null
        scope.launch {
            try {
                val (name, size) = withContext(Dispatchers.IO) { queryNameSize(context, uri) }
                val bytes = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw IllegalStateException("Couldn't open the file.")
                }
                sourceName = name
                sourceSize = if (size > 0) size else bytes.size.toLong()
                sourceBytes = bytes
                stage = EncryptStage.CONFIGURE
            } catch (e: Exception) {
                error = e.message ?: "Couldn't read the file."
            }
        }
    }

    val createOutput = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        val bytes = outputBytes
        if (uri == null || bytes == null) {
            stage = EncryptStage.CONFIGURE
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                        ?: throw IllegalStateException("Couldn't open the destination.")
                }
                savedName = queryNameSize(context, uri).first
                stage = EncryptStage.DONE
            } catch (e: Exception) {
                error = e.message ?: "Couldn't save the file."
                stage = EncryptStage.CONFIGURE
            }
        }
    }

    fun reset() {
        sourceBytes = null; sourceName = "file"; sourceSize = 0L
        recipients = emptyList(); passphrase = null; armor = true
        outputBytes = null; savedName = null; error = null
        stage = EncryptStage.PICK
    }

    Column(modifier.fillMaxSize()) {
        when (stage) {
            EncryptStage.PICK -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text("Encrypt a file", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    "Pick any file. The encrypted result gets a .age extension and can be shared anywhere.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (error != null) ErrorText(error!!)
                Button(onClick = { vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Pick a file…")
                }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            EncryptStage.CONFIGURE -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text("Encrypt a file", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)

                Text("Source", style = MaterialTheme.typography.titleSmall)
                Text(sourceName, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(humanSize(sourceSize), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                TextButton(onClick = { vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) }) { Text("Change file") }

                HorizontalDivider()

                Text("Recipients", style = MaterialTheme.typography.titleSmall)
                Text(
                    recipientSummary(recipients.size, passphrase),
                    style = MaterialTheme.typography.bodyMedium,
                )
                TextButton(onClick = { stage = EncryptStage.PICKING }) { Text("Choose recipients") }

                HorizontalDivider()

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = armor, onCheckedChange = { armor = it })
                    Text("Armor as text", modifier = Modifier.padding(start = 12.dp))
                }
                Text(
                    if (armor) "Output is text between BEGIN/END markers — safe to paste anywhere."
                    else "Output is raw binary — smaller, but won't survive being pasted as text.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                if (error != null) ErrorText(error!!)

                val canEncrypt = sourceBytes != null &&
                    (recipients.isNotEmpty() || !passphrase.isNullOrEmpty())
                Button(
                    onClick = {
                        val bytes = sourceBytes ?: return@Button
                        error = null
                        stage = EncryptStage.WORKING
                        scope.launch {
                            try {
                                val out = withContext(Dispatchers.Default) {
                                    FileEncryptor.encrypt(bytes, recipients, passphrase, armor)
                                }
                                outputBytes = out
                                vault.autoLockSuppressed = true
                                createOutput.launch(FileEncryptor.encryptedName(sourceName))
                                // stage advances to DONE in the createOutput callback
                            } catch (e: OutOfMemoryError) {
                                error = "Not enough memory to encrypt with a passphrase on " +
                                    "this device. Try a smaller file, or encrypt to recipient keys instead."
                                stage = EncryptStage.CONFIGURE
                            } catch (e: Exception) {
                                error = e.message ?: "Encrypt failed."
                                stage = EncryptStage.CONFIGURE
                            }
                        }
                    },
                    enabled = canEncrypt,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Encrypt") }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            EncryptStage.PICKING -> RecipientPicker(
                vault = vault,
                onCancel = { stage = EncryptStage.CONFIGURE },
                onConfirm = { r, p ->
                    recipients = r
                    passphrase = p
                    stage = EncryptStage.CONFIGURE
                },
            )

            EncryptStage.WORKING -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                Text("Encrypting…", modifier = Modifier.padding(top = 16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            EncryptStage.DONE -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text("Encrypted ✓", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    savedName ?: FileEncryptor.encryptedName(sourceName),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp, bottom = 24.dp),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Button(onClick = { reset() }, modifier = Modifier.fillMaxWidth()) { Text("Encrypt another") }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Done") }
            }
        }
    }
}

@Composable
private fun ErrorText(message: String) {
    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
}

private fun recipientSummary(count: Int, passphrase: String?): String = when {
    !passphrase.isNullOrEmpty() -> "Passphrase only (scrypt)"
    count == 0 -> "None chosen yet"
    count == 1 -> "1 recipient"
    else -> "$count recipients"
}

private fun queryNameSize(context: Context, uri: Uri): Pair<String, Long> {
    var name = "file"
    var size = 0L
    context.contentResolver.query(uri, null, null, null, null)?.use { c ->
        val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
        if (c.moveToFirst()) {
            if (nameIdx >= 0) c.getString(nameIdx)?.let { name = it }
            if (sizeIdx >= 0 && !c.isNull(sizeIdx)) size = c.getLong(sizeIdx)
        }
    }
    return name to size
}

private fun humanSize(bytes: Long): String {
    if (bytes <= 0) return "—"
    val units = arrayOf("B", "KB", "MB", "GB")
    var b = bytes.toDouble()
    var i = 0
    while (b >= 1024 && i < units.size - 1) { b /= 1024; i++ }
    return if (i == 0) "${bytes} B" else String.format("%.1f %s", b, units[i])
}
