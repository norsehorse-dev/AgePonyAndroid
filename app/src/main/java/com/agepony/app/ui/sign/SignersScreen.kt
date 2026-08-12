package com.agepony.app.ui.sign

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
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.unit.dp
import com.agepony.app.ui.files.SafIo
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
                var added = 0
                var skipped = 0
                entries.forEach { entry ->
                    val signer = StoredSigner.fromAllowedSigner(entry, StoredSignerSource.IMPORT_ALLOWED_SIGNERS)
                    if (signer != null && vault.addSigner(signer)) added++ else skipped++
                }
                status = when {
                    entries.isEmpty() -> "No allowed_signers entries found in that file."
                    skipped == 0 -> "Imported $added signer${if (added == 1) "" else "s"}."
                    else -> "Imported $added, skipped $skipped (already present or unreadable)."
                }
            } catch (e: Exception) {
                status = "Import failed: ${e.message}"
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
                status = "Exported ${vault.signers.size} signer${if (vault.signers.size == 1) "" else "s"}."
            } catch (e: Exception) {
                status = "Export failed: ${e.message}"
            }
        }
    }

    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Trusted signers", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
        Text(
            "Signatures from these keys verify with the name you gave them. " +
                "The list imports from and exports to the OpenSSH allowed_signers format.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (status != null) {
            Text(status!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
        }

        if (vault.signers.isEmpty()) {
            Text(
                "No trusted signers yet. Add one below, or from a valid-but-unknown verify result.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            vault.signers.forEach { signer ->
                Column(Modifier.fillMaxWidth()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(signer.name, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                "${signer.keyType} · ${signer.fingerprint()}",
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                            )
                        }
                        TextButton(onClick = { confirmDelete = signer }) { Text("Delete") }
                    }
                    HorizontalDivider()
                }
            }
        }

        Button(
            onClick = { status = null; showPaste = true },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Paste a public key…") }
        OutlinedButton(
            onClick = {
                status = null
                vault.autoLockSuppressed = true
                importFile.launch(arrayOf("*/*"))
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Import allowed_signers…") }
        OutlinedButton(
            onClick = { status = null; showFromRecipient = true },
            enabled = vault.recipients.any { it.type == StoredRecipientType.SSH_ED25519 || it.type == StoredRecipientType.SSH_RSA },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Promote a saved recipient…") }
        OutlinedButton(
            onClick = {
                status = null
                vault.autoLockSuppressed = true
                exportFile.launch("allowed_signers")
            },
            enabled = vault.signers.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Export allowed_signers…") }
        TextButton(onClick = onClose) { Text("Back") }
    }

    if (showPaste) {
        PasteSignerDialog(
            onConfirm = { name, line ->
                val entry = AllowedSigners.makeSigner(listOf(name), line)
                val signer = entry?.let { StoredSigner.fromAllowedSigner(it, StoredSignerSource.PASTE_KEY) }
                status = when {
                    signer == null -> "That doesn't look like an SSH public key line."
                    vault.addSigner(signer) -> "Added \"$name\"."
                    else -> "That key is already on the list."
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
                    signer == null -> "Couldn't read that recipient's key."
                    vault.addSigner(signer) -> "Added \"${recipient.name}\"."
                    else -> "That key is already on the list."
                }
                showFromRecipient = false
            },
            onDismiss = { showFromRecipient = false },
        )
    }

    confirmDelete?.let { signer ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text("Delete \"${signer.name}\"?") },
            text = {
                Text(
                    "Signatures from this key will verify as valid but unknown instead of " +
                        "carrying this name."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    vault.deleteSigner(signer.id)
                    confirmDelete = null
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel") } },
        )
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
        title = { Text("Paste a public key") },
        text = {
            Column {
                Text("An SSH public key line, like the contents of an id_ed25519.pub.")
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    label = { Text("Name") },
                    modifier = Modifier.padding(top = 12.dp),
                )
                OutlinedTextField(
                    value = line,
                    onValueChange = { line = it },
                    label = { Text("ssh-ed25519 AAAA… or ssh-rsa AAAA…") },
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(name.trim(), line.trim()) },
                enabled = name.trim().isNotEmpty() && line.trim().isNotEmpty(),
            ) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
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
        title = { Text("Promote a saved recipient") },
        text = {
            Column {
                Text("Their key already being saved for encryption doesn't verify signatures; this adds it to the signers list too.")
                recipients.forEach { r ->
                    TextButton(onClick = { onPick(r) }) {
                        Text("${r.name} (${if (r.type == StoredRecipientType.SSH_ED25519) "ssh-ed25519" else "ssh-rsa"})")
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
