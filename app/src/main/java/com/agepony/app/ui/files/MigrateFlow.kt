package com.agepony.app.ui.files

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.NoMatchingVaultIdentityException
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.Vault
import com.agepony.app.vault.WrongPassphraseException
import com.agepony.app.vault.toAgeIdentity
import com.agepony.app.vault.toAgeRecipient
import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.AgeRecipient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

//
// Migrate flow: batch "upgrade to quantum-safe". Pick a post-quantum identity as the target,
// select existing .age files and a destination folder, and AgePony decrypts each (with vault
// identities, or an optional shared passphrase) and re-encrypts it to the PQC identity, writing
// the result into the chosen folder. Each file gets a pass/fail line. Files that need a
// different passphrase than the one entered are reported, not silently dropped.
//

private enum class MigrateStage { SETUP, WORKING, DONE }

private class MigrateItem(val name: String, val ok: Boolean, val detail: String)

@Composable
fun MigrateFlow(vault: Vault, modifier: Modifier = Modifier, onClose: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()

    var stage by remember { mutableStateOf(MigrateStage.SETUP) }
    var targetId by remember { mutableStateOf<String?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var sourceUris by remember { mutableStateOf<List<Uri>>(emptyList()) }
    var destTree by remember { mutableStateOf<Uri?>(null) }
    var results by remember { mutableStateOf<List<MigrateItem>>(emptyList()) }
    var progress by remember { mutableStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }

    val pqcIdentities = vault.identities.filter { it.type == StoredIdentityType.MLKEM768X25519 }

    val pickFiles = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris -> if (uris.isNotEmpty()) { sourceUris = uris; error = null } }

    val pickFolder = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri -> if (uri != null) { destTree = uri; error = null } }

    fun reset() {
        stage = MigrateStage.SETUP; targetId = null; passphrase = ""
        sourceUris = emptyList(); destTree = null; results = emptyList(); progress = 0; error = null
    }

    Column(modifier.fillMaxSize()) {
        when (stage) {
            MigrateStage.SETUP -> Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text("Upgrade files to quantum-safe", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    "Re-encrypt existing age files to your quantum-safe identity. AgePony decrypts each " +
                        "with your identities (or the passphrase below) and re-encrypts it to the identity you pick.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                HorizontalDivider()

                Text("Quantum-safe identity", style = MaterialTheme.typography.titleSmall)
                if (pqcIdentities.isEmpty()) {
                    Text(
                        "You have no quantum-safe identity yet. Create one in Identities → Add → Generate → " +
                            "Quantum-safe, then come back.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                } else {
                    pqcIdentities.forEach { id ->
                        Row(
                            modifier = Modifier.fillMaxWidth().clickable { targetId = id.id }.padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = targetId == id.id, onClick = { targetId = id.id })
                            Text(id.name, modifier = Modifier.padding(start = 8.dp))
                        }
                    }
                }

                HorizontalDivider()

                Text("Files", style = MaterialTheme.typography.titleSmall)
                Text(
                    if (sourceUris.isEmpty()) "None chosen" else "${sourceUris.size} file${if (sourceUris.size == 1) "" else "s"} chosen",
                    style = MaterialTheme.typography.bodyMedium,
                )
                TextButton(onClick = { vault.autoLockSuppressed = true; pickFiles.launch(arrayOf("*/*")) }) { Text("Choose files…") }

                Text("Destination folder", style = MaterialTheme.typography.titleSmall)
                Text(
                    if (destTree == null) "None chosen" else "Folder chosen ✓",
                    style = MaterialTheme.typography.bodyMedium,
                )
                TextButton(onClick = { vault.autoLockSuppressed = true; pickFolder.launch(null) }) { Text("Choose folder…") }

                HorizontalDivider()

                Text("Passphrase (optional)", style = MaterialTheme.typography.titleSmall)
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("For any passphrase-encrypted files") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                if (error != null) {
                    Text(error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }

                val canStart = targetId != null && sourceUris.isNotEmpty() && destTree != null
                Button(
                    onClick = {
                        val target = vault.identities.firstOrNull { it.id == targetId } ?: return@Button
                        val tree = destTree ?: return@Button
                        error = null
                        results = emptyList()
                        progress = 0
                        stage = MigrateStage.WORKING
                        vault.autoLockSuppressed = true
                        scope.launch {
                            val prepared = withContext(Dispatchers.Default) {
                                val recipient = target.toAgeRecipient()
                                val ids = vault.identities.mapNotNull { runCatching { it.toAgeIdentity() }.getOrNull() }
                                recipient to ids
                            }
                            val recipient = prepared.first
                            val ids = prepared.second
                            val collected = ArrayList<MigrateItem>()
                            for ((i, uri) in sourceUris.withIndex()) {
                                progress = i + 1
                                val item = withContext(Dispatchers.IO) {
                                    migrateOne(context, uri, ids, recipient, passphrase, tree)
                                }
                                collected.add(item)
                                results = collected.toList()
                            }
                            stage = MigrateStage.DONE
                        }
                    },
                    enabled = canStart,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Upgrade ${if (sourceUris.isEmpty()) "" else "${sourceUris.size} "}file${if (sourceUris.size == 1) "" else "s"}") }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            MigrateStage.WORKING -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                Text(
                    "Upgrading $progress of ${sourceUris.size}…",
                    modifier = Modifier.padding(top = 16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            MigrateStage.DONE -> Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                val okCount = results.count { it.ok }
                Text("Upgrade complete", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    "$okCount of ${results.size} upgraded to quantum-safe.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                HorizontalDivider()
                results.forEach { item ->
                    Column(Modifier.fillMaxWidth()) {
                        Text(
                            (if (item.ok) "✓ " else "⚠ ") + item.name,
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (item.ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            item.detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    HorizontalDivider()
                }
                Button(onClick = { reset() }, modifier = Modifier.fillMaxWidth()) { Text("Upgrade more") }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Done") }
            }
        }
    }
}

/** Decrypt one file (identities, then optional passphrase) and re-encrypt it to [target]. */
private fun migrateOne(
    context: Context,
    uri: Uri,
    ids: List<AgeIdentity>,
    target: AgeRecipient,
    passphrase: String,
    destTree: Uri,
): MigrateItem {
    val name = queryDisplayName(context, uri)
    val raw = try {
        context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: return MigrateItem(name, false, "Couldn't open the file.")
    } catch (e: Exception) {
        return MigrateItem(name, false, "Couldn't read the file.")
    }

    val bin = try {
        FileEncryptor.toBinary(raw)
    } catch (e: Exception) {
        return MigrateItem(name, false, "Not an age file.")
    }

    val plain: ByteArray = try {
        FileEncryptor.decryptWithIdentities(bin, ids)
    } catch (e: NoMatchingVaultIdentityException) {
        if (passphrase.isBlank()) {
            return MigrateItem(name, false, "No matching identity, and no passphrase given.")
        }
        try {
            FileEncryptor.decryptWithPassphrase(bin, passphrase)
        } catch (e2: WrongPassphraseException) {
            return MigrateItem(name, false, "Needs a different passphrase — skipped.")
        } catch (e2: Exception) {
            return MigrateItem(name, false, e2.message ?: "Decrypt failed.")
        }
    } catch (e: Exception) {
        return MigrateItem(name, false, e.message ?: "Decrypt failed.")
    }

    val wasArmored = FileEncryptor.isArmored(raw)
    val out = try {
        FileEncryptor.encrypt(plain, listOf(target), null, wasArmored)
    } catch (e: Exception) {
        return MigrateItem(name, false, "Re-encrypt failed: ${e.message}")
    }

    return try {
        writeToTree(context, destTree, name, out)
        MigrateItem(name, true, "Re-encrypted to your quantum-safe identity.")
    } catch (e: Exception) {
        MigrateItem(name, false, "Couldn't save to the folder: ${e.message}")
    }
}

private fun writeToTree(context: Context, treeUri: Uri, displayName: String, bytes: ByteArray) {
    val parent = DocumentsContract.buildDocumentUriUsingTree(treeUri, DocumentsContract.getTreeDocumentId(treeUri))
    val fileUri = DocumentsContract.createDocument(
        context.contentResolver, parent, "application/octet-stream", displayName
    ) ?: throw IllegalStateException("couldn't create output file")
    context.contentResolver.openOutputStream(fileUri)?.use { it.write(bytes) }
        ?: throw IllegalStateException("couldn't open output stream")
}

private fun queryDisplayName(context: Context, uri: Uri): String {
    var name = "file.age"
    context.contentResolver.query(uri, null, null, null, null)?.use { c ->
        val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (c.moveToFirst() && idx >= 0) c.getString(idx)?.let { name = it }
    }
    return name
}
