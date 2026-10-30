package com.agepony.app.ui.sign

import com.agepony.app.ui.components.EmptyState
import com.agepony.app.ui.UserMessage
import android.net.Uri
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.layout.heightIn
import androidx.compose.ui.unit.dp
import com.agepony.app.ui.files.SafIo
import com.agepony.app.vault.AllowedSignerReview
import com.agepony.app.vault.StoredRecipient
import com.agepony.app.vault.StoredRecipientType
import com.agepony.app.vault.StoredSigner
import com.agepony.app.vault.StoredSignerSource
import com.agepony.app.vault.Vault
import com.agepony.app.vault.b64d
import com.agepony.app.vault.b64e
import com.agepony.core.signing.SSHSig
import com.agepony.core.ssh.AllowedSigners
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.semantics.Role
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.OneLineValue
import com.agepony.app.ui.components.QuietAction

//
// Trusted signers: the keys whose signatures verify with a name attached.
// Android counterpart of iOS's SignersView + AddSignerView.
//
// The list round-trips through the OpenSSH allowed_signers format via the
// core's AllowedSigners, so an export drops straight onto a machine's command
// line (`ssh-keygen -Y verify -f allowed_signers ...`) and a file built there
// imports back without loss.
//

@Composable
fun SignersScreen(vault: Vault, modifier: Modifier = Modifier, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var status by remember { mutableStateOf<String?>(null) }
    var showPaste by remember { mutableStateOf(false) }
    var showFromRecipient by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf<StoredSigner?>(null) }
    // Audit L-6: an allowed_signers file is reviewed entry by entry before anything is trusted.
    var review by remember { mutableStateOf<ImportReview?>(null) }

    val importFile = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            try {
                val text = withContext(Dispatchers.IO) {
                    SafIo.openInput(context, uri).use { String(it.readBytes(), Charsets.UTF_8) }
                }
                val entries = AllowedSigners.parse(text)
                if (entries.isEmpty()) {
                    status = context.getString(R.string.sign_signers_none_in_file)
                } else {
                    val known = vault.signers.toList()
                    val rows = entries.map { AllowedSignerReview.of(it, StoredSignerSource.IMPORT_ALLOWED_SIGNERS, known) }
                    review = ImportReview(rows, entryLines(text) - entries.size)
                }
            } catch (e: Exception) {
                status = UserMessage.text(context, e, R.string.sign_signers_import_failed)
            }
        }
    }

    val exportFile = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        val text = AllowedSigners.serialize(vault.signers.map { it.toAllowedSigner() })
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    SafIo.openOutput(context, uri).use { it.write(text.toByteArray(Charsets.UTF_8)) }
                }
                status = context.resources.getQuantityString(
                    R.plurals.signers_exported, vault.signers.size, vault.signers.size,
                )
            } catch (e: Exception) {
                status = UserMessage.text(context, e, R.string.sign_signers_export_failed)
            }
        }
    }

    val pending = review
    if (pending != null) {
        val r = pending
        ImportReviewPane(
            review = r,
            modifier = modifier,
            onImport = { chosen ->
                var added = 0
                var skipped = 0
                chosen.forEach { signer -> if (vault.addSigner(signer)) added++ else skipped++ }
                val left = r.rows.size - chosen.size
                val res = context.resources
                status = listOfNotNull(
                    res.getQuantityString(R.plurals.sign_signers_imported_sentence, added, added),
                    if (skipped > 0) res.getQuantityString(R.plurals.sign_signers_already_present, skipped, skipped) else null,
                    if (left > 0) res.getQuantityString(R.plurals.sign_signers_not_imported, left, left) else null,
                ).joinToString(" ")
                review = null
            },
            onCancel = { review = null; status = context.getString(R.string.sign_signers_nothing_imported) },
        )
        return
    }

    AgeScreen(title = stringResource(R.string.files_signers), modifier = modifier, onBack = onClose) { padding ->
    Column(
        Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            stringResource(R.string.sign_signers_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (status != null) {
            Text(status!!, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        if (vault.signers.isEmpty()) {
            EmptyState(
                title = stringResource(R.string.sign_signers_empty_title),
                body = stringResource(R.string.sign_signers_empty),
            )
        } else {
            vault.signers.forEach { signer ->
                Column(Modifier.fillMaxWidth()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(signer.name, style = MaterialTheme.typography.bodyLarge)
                            OneLineValue("${signer.keyType} · ${signer.fingerprint()}")
                            // Imported restrictions (audit L-6), kept and exported as written.
                            val restrictions = signer.restrictions(LocalContext.current)
                            if (restrictions.isNotEmpty()) {
                                Text(
                                    restrictions.joinToString(" · "),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            signer.agePonyWarning(LocalContext.current)?.let {
                                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                            }
                        }
                        QuietAction(stringResource(R.string.action_delete), onClick = { confirmDelete = signer }, destructive = true)
                    }
                    ListDivider()
                }
            }
        }

        Button(
            onClick = { status = null; showPaste = true },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.sign_signers_paste)) }
        OutlinedButton(
            onClick = {
                status = null
                vault.autoLockSuppressed = true
                importFile.launch(arrayOf("*/*"))
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.sign_signers_import)) }
        OutlinedButton(
            onClick = { status = null; showFromRecipient = true },
            enabled = vault.recipients.any { it.type == StoredRecipientType.SSH_ED25519 || it.type == StoredRecipientType.SSH_RSA },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.sign_signers_promote)) }
        OutlinedButton(
            onClick = {
                status = null
                vault.autoLockSuppressed = true
                exportFile.launch("allowed_signers")
            },
            enabled = vault.signers.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.sign_signers_export)) }
    }
    }

    if (showPaste) {
        PasteSignerDialog(
            onConfirm = { name, line ->
                val entry = AllowedSigners.makeSigner(listOf(name), line)
                val signer = entry?.let { StoredSigner.fromAllowedSigner(it, StoredSignerSource.PASTE_KEY) }
                status = when {
                    signer == null -> context.getString(R.string.sign_signers_not_ssh_line)
                    vault.addSigner(signer) -> context.getString(R.string.sign_signers_added, name)
                    else -> context.getString(R.string.sign_signers_already_listed)
                }
                showPaste = false
            },
            onDismiss = { showPaste = false },
        )
    }

    if (showFromRecipient) {
        FromRecipientDialog(
            recipients = vault.recipients.filter {
                it.type == StoredRecipientType.SSH_ED25519 || it.type == StoredRecipientType.SSH_RSA
            },
            onPick = { recipient ->
                val signer = signerFromRecipient(recipient)
                status = when {
                    signer == null -> context.getString(R.string.sign_signers_recipient_unreadable)
                    vault.addSigner(signer) -> context.getString(R.string.sign_signers_added, recipient.name)
                    else -> context.getString(R.string.sign_signers_already_listed)
                }
                showFromRecipient = false
            },
            onDismiss = { showFromRecipient = false },
        )
    }

    confirmDelete?.let { signer ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text(stringResource(R.string.recipient_delete_title, signer.name)) },
            text = {
                Text(stringResource(R.string.sign_signer_delete_body))
            },
            confirmButton = {
                TextButton(onClick = {
                    vault.deleteSigner(signer.id)
                    confirmDelete = null
                }) { Text(stringResource(R.string.action_delete)) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }
}

/** A parsed allowed_signers file waiting for the user's choice (audit L-6). */
private class ImportReview(val rows: List<AllowedSignerReview>, val unreadable: Int)

/** Non-blank, non-comment lines, counted the way [AllowedSigners.parse] reads them. */
private fun entryLines(text: String): Int =
    text.replace("\r\n", "\n").replace('\r', '\n').split('\n')
        .map { it.trim() }
        .count { it.isNotEmpty() && !it.startsWith("#") }

/**
 * The allowed_signers import preview (audit L-6). Every entry is listed with its principal, key
 * and options in plain words. Entries AgePony can't enforce (cert-authority, unknown or unreadable
 * options) are listed and never imported; expired entries and ones not allowed to sign AgePony
 * files start unticked.
 */
@Composable
private fun ImportReviewPane(
    review: ImportReview,
    modifier: Modifier,
    onImport: (List<StoredSigner>) -> Unit,
    onCancel: () -> Unit,
) {
    val picked = remember(review) {
        mutableStateListOf<Int>().apply { review.rows.forEachIndexed { i, r -> if (r.checkedByDefault) add(i) } }
    }
    val resources = LocalContext.current.resources
    AgeScreen(title = stringResource(R.string.sign_signers_import_title), modifier = modifier, onBack = onCancel) { padding ->
    Column(
        Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            stringResource(R.string.sign_signers_review_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (review.unreadable > 0) {
            Text(
                resources.getQuantityString(R.plurals.signers_unreadable_lines, review.unreadable, review.unreadable),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        review.rows.forEachIndexed { i, row ->
            // The whole row toggles; the Checkbox only draws the state.
            Row(
                verticalAlignment = Alignment.Top,
                modifier = Modifier
                    .fillMaxWidth()
                    .toggleable(
                        value = i in picked && row.importable,
                        enabled = row.importable,
                        role = Role.Checkbox,
                        onValueChange = { if (i in picked) picked.remove(i) else picked.add(i) },
                    )
                    .heightIn(min = 48.dp)
                    .padding(vertical = 8.dp),
            ) {
                Checkbox(
                    checked = i in picked && row.importable,
                    onCheckedChange = null,
                    enabled = row.importable,
                )
                Column(Modifier.weight(1f).padding(start = 12.dp)) {
                    Text(row.entry.principals.joinToString(", "), style = MaterialTheme.typography.bodyLarge)
                    val fingerprint = row.signer?.let { runCatching { it.fingerprint() }.getOrNull() }
                    if (fingerprint != null) {
                        OneLineValue("${row.entry.keyType} · $fingerprint")
                    } else {
                        // "Unreadable key" is prose, so it stays in the UI font.
                        Text(
                            "${row.entry.keyType} · ${stringResource(R.string.sign_signers_unreadable_key)}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    row.restrictions(LocalContext.current).forEach {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (row.alreadyPresent) {
                        Text(
                            stringResource(R.string.sign_signers_review_present),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    row.blocked(LocalContext.current)?.let {
                        Text(stringResource(R.string.sign_signers_review_blocked, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                    row.warning(LocalContext.current)?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            }
            ListDivider()
        }
        val count = picked.count { review.rows.getOrNull(it)?.importable == true }
        Button(
            onClick = {
                onImport(review.rows.filterIndexed { i, r -> i in picked && r.importable }.mapNotNull { it.signer })
            },
            enabled = count > 0,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                if (count > 0) pluralStringResource(R.plurals.sign_signers_import_count, count, count)
                else stringResource(R.string.sign_signers_import_action)
            )
        }
        OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.action_cancel)) }
    }
    }
}

/** SSH recipient → trusted signer, reusing the stored key material. */
private fun signerFromRecipient(recipient: StoredRecipient): StoredSigner? {
    val (keyType, wire) = when (recipient.type) {
        StoredRecipientType.SSH_ED25519 ->
            "ssh-ed25519" to SSHSig.ed25519PublicWire(b64d(recipient.publicKeyB64))
        StoredRecipientType.SSH_RSA -> {
            val parts = String(b64d(recipient.publicKeyB64), Charsets.UTF_8)
                .trim().split(' ').filter { it.isNotEmpty() }
            if (parts.size < 2) return null
            val wire = try {
                b64d(parts[1])
            } catch (e: IllegalArgumentException) {
                return null
            }
            "ssh-rsa" to wire
        }
        else -> return null
    }
    return StoredSigner(
        id = UUID.randomUUID().toString(),
        name = recipient.name,
        keyType = keyType,
        publicKeyWireB64 = b64e(wire),
        comment = recipient.sshComment,
        source = StoredSignerSource.FROM_RECIPIENT,
        createdAt = System.currentTimeMillis(),
    )
}

@Composable
private fun PasteSignerDialog(
    onConfirm: (name: String, line: String) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var line by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.sign_signers_paste_title)) },
        text = {
            Column {
                Text(stringResource(R.string.sign_signers_paste_body))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.sign_signers_name_label)) },
                    modifier = Modifier.padding(top = 12.dp),
                )
                OutlinedTextField(
                    value = line,
                    onValueChange = { line = it },
                    label = { Text(stringResource(R.string.sign_signers_key_line_label)) },
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(name.trim(), line.trim()) },
                enabled = name.trim().isNotEmpty() && line.trim().isNotEmpty(),
            ) { Text(stringResource(R.string.sign_signers_add)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}

@Composable
private fun FromRecipientDialog(
    recipients: List<StoredRecipient>,
    onPick: (StoredRecipient) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.sign_signers_promote_title)) },
        text = {
            Column {
                Text(stringResource(R.string.sign_signers_promote_body))
                recipients.forEach { r ->
                    TextButton(onClick = { onPick(r) }) {
                        Text("${r.name} (${if (r.type == StoredRecipientType.SSH_ED25519) "ssh-ed25519" else "ssh-rsa"})")
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}
