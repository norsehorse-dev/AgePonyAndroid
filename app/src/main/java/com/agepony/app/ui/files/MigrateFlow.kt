package com.agepony.app.ui.files

import com.agepony.app.ui.UserMessage
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
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
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.DoneAction
import com.agepony.app.ui.components.OneLineValue
import com.agepony.app.ui.components.RowAction
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.RadioRow
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.theme.AgeStatus

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

    // Back is held while files are being rewritten; the job belongs to this screen.
    if (stage == MigrateStage.WORKING) BackHandler {}

    AgeScreen(
        title = stringResource(R.string.files_migrate),
        modifier = modifier,
        onBack = if (stage == MigrateStage.WORKING) null else onClose,
        actions = { if (stage == MigrateStage.DONE) DoneAction(onClose) },
    ) { padding ->
    Column(Modifier.fillMaxSize().padding(padding)) {
        when (stage) {
            MigrateStage.SETUP -> Column(
                Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    stringResource(R.string.files_migrate_intro),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                ListDivider()

                SectionHeader(stringResource(R.string.files_migrate_section_identity))
                if (pqcIdentities.isEmpty()) {
                    Text(
                        stringResource(R.string.files_migrate_no_identity),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                } else {
                    pqcIdentities.forEach { id ->
                        RadioRow(title = id.name, selected = targetId == id.id, onClick = { targetId = id.id })
                    }
                }

                ListDivider()

                SectionHeader(stringResource(R.string.files_title))
                Text(
                    if (sourceUris.isEmpty()) stringResource(R.string.files_migrate_none_chosen)
                    else pluralStringResource(R.plurals.migrate_files_chosen, sourceUris.size, sourceUris.size),
                    style = MaterialTheme.typography.bodyMedium,
                )
                TextButton(onClick = { vault.autoLockSuppressed = true; pickFiles.launch(arrayOf("*/*")) }) { Text(stringResource(R.string.files_migrate_choose_files)) }

                SectionHeader(stringResource(R.string.files_migrate_section_destination))
                Text(
                    stringResource(
                        if (destTree == null) R.string.files_migrate_none_chosen else R.string.files_migrate_folder_chosen,
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
                TextButton(onClick = { vault.autoLockSuppressed = true; pickFolder.launch(null) }) { Text(stringResource(R.string.files_migrate_choose_folder)) }

                ListDivider()

                SectionHeader(stringResource(R.string.files_migrate_section_passphrase))
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(stringResource(R.string.files_migrate_passphrase_label)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )

                if (error != null) ErrorText(error!!)

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
                ) {
                    Text(
                        if (sourceUris.isEmpty()) stringResource(R.string.files_migrate_upgrade)
                        else pluralStringResource(R.plurals.migrate_upgrade_files, sourceUris.size, sourceUris.size)
                    )
                }
                TextButton(onClick = onClose) { Text(stringResource(R.string.action_cancel)) }
            }

            MigrateStage.WORKING -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                Text(
                    stringResource(R.string.files_migrate_progress, progress, sourceUris.size),
                    modifier = Modifier.padding(top = 16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            MigrateStage.DONE -> Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                val okCount = results.count { it.ok }
                VerdictPanel(
                    title = stringResource(R.string.files_migrate_done),
                    detail = null,
                    color = if (okCount == results.size) AgeStatus.colors.success else AgeStatus.colors.warning,
                    icon = if (okCount == results.size) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                )
                Text(
                    pluralStringResource(R.plurals.files_migrate_result, results.size, okCount, results.size),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                ListDivider()
                results.forEach { item ->
                    Column(Modifier.fillMaxWidth()) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                if (item.ok) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                                contentDescription = null,
                                tint = if (item.ok) AgeStatus.colors.success else AgeStatus.colors.failure,
                                modifier = Modifier.size(16.dp),
                            )
                            OneLineValue(
                                item.name,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(start = 8.dp),
                            )
                        }
                        Text(
                            item.detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    ListDivider()
                }
                // Done sits in the app bar; the next batch is its own row (5.1.0, U4).
                RowAction(stringResource(R.string.files_migrate_more), onClick = { reset() })
            }
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
            ?: return MigrateItem(name, false, context.getString(R.string.files_migrate_open_failed))
    } catch (e: Exception) {
        return MigrateItem(name, false, context.getString(R.string.files_migrate_read_failed))
    }

    val bin = try {
        FileEncryptor.toBinary(raw)
    } catch (e: Exception) {
        return MigrateItem(name, false, context.getString(R.string.files_migrate_not_age))
    }

    val plain: ByteArray = try {
        FileEncryptor.decryptWithIdentities(bin, ids)
    } catch (e: NoMatchingVaultIdentityException) {
        if (passphrase.isBlank()) {
            return MigrateItem(name, false, context.getString(R.string.files_migrate_no_match))
        }
        try {
            FileEncryptor.decryptWithPassphrase(bin, passphrase)
        } catch (e2: WrongPassphraseException) {
            return MigrateItem(name, false, context.getString(R.string.files_migrate_other_passphrase))
        } catch (e2: Exception) {
            return MigrateItem(name, false, UserMessage.text(context, e2, R.string.files_decrypt_failed))
        }
    } catch (e: Exception) {
        return MigrateItem(name, false, UserMessage.text(context, e, R.string.files_decrypt_failed))
    }

    val wasArmored = FileEncryptor.isArmored(raw)
    val out = try {
        FileEncryptor.encrypt(plain, listOf(target), null, wasArmored)
    } catch (e: Exception) {
        return MigrateItem(name, false, UserMessage.text(context, e, R.string.files_migrate_reencrypt_failed))
    }

    return try {
        writeToTree(context, destTree, name, out)
        MigrateItem(name, true, context.getString(R.string.files_migrate_item_done))
    } catch (e: Exception) {
        MigrateItem(name, false, UserMessage.text(context, e, R.string.files_migrate_save_failed))
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
