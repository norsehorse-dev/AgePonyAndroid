package com.agepony.app.ui.identities

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.ui.components.KeyBlock
import com.agepony.app.ui.scan.QrScanner
import com.agepony.app.vault.RecipientCandidate
import com.agepony.app.vault.RecipientImport
import com.agepony.app.vault.StoredRecipient
import com.agepony.app.vault.StoredRecipientSource
import com.agepony.app.vault.StoredRecipientType
import com.agepony.app.vault.Vault
import com.agepony.app.vault.publicDisplayString
import kotlinx.coroutines.launch
import java.util.UUID

//
// Recipients pane (Phase 2c-2): list / detail / add. Add Recipient supports the
// paste and GitHub paths (QR deferred). Parsed candidates are reviewed (name +
// include) before saving, mirroring iOS's AddRecipientView "Found" section.
//

@Composable
internal fun RecipientList(
    vault: Vault,
    onAdd: () -> Unit,
    onOpen: (String) -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 20.dp, end = 12.dp, top = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Spacer(Modifier.weight(1f))
            TextButton(onClick = onAdd) { Text("Add") }
        }

        if (vault.recipients.isEmpty()) {
            EmptyPane(
                title = "No recipients yet",
                body = "Tap Add to paste a public key or fetch from GitHub.",
            )
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(vault.recipients, key = { it.id }) { recipient ->
                    RecipientRow(recipient = recipient, onClick = { onOpen(recipient.id) })
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun RecipientRow(recipient: StoredRecipient, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(recipient.name, style = MaterialTheme.typography.bodyLarge)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    color = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text(
                        text = sourceLabel(recipient.source),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                }
                Text(
                    text = recipient.publicDisplayString(),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
    }
}

@Composable
internal fun RecipientDetail(
    vault: Vault,
    recipientId: String,
    onBack: () -> Unit,
) {
    val recipient = vault.recipients.firstOrNull { it.id == recipientId }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 8.dp, top = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) { Text("‹ Back") }
        }

        if (recipient == null) {
            Text(
                "Recipient not found.",
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(24.dp),
            )
            return@Column
        }

        Column(
            Modifier.padding(horizontal = 20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                recipient.name,
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.primary,
            )
            Text(
                "${typeLabel(recipient.type)}  •  ${sourceLabel(recipient.source)}" +
                    (recipient.sourceMetadata?.let { "  •  $it" } ?: ""),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (!recipient.sshComment.isNullOrBlank()) {
                Text(
                    recipient.sshComment!!,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            KeyBlock(label = "Public key", value = recipient.publicDisplayString())

            TextButton(onClick = {
                vault.deleteRecipient(recipientId)
                onBack()
            }) {
                Text("Delete recipient", color = MaterialTheme.colorScheme.error)
            }
            Text(
                "Recipients are public keys — you can always add this one again later.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 24.dp),
            )
        }
    }
}

// MARK: - Add recipient

private enum class AddRecipientSource(val label: String) { PASTE("Paste"), GITHUB("GitHub"), SCAN("Scan") }

private class EditableCandidate(val candidate: RecipientCandidate) {
    val key: String = UUID.randomUUID().toString()
    var name by mutableStateOf(candidate.defaultName)
    var include by mutableStateOf(true)
}

@Composable
internal fun AddRecipientFlow(
    vault: Vault,
    onDone: () -> Unit,
    onCancel: () -> Unit,
) {
    var source by rememberSaveable { mutableStateOf(AddRecipientSource.PASTE) }
    var pasteText by rememberSaveable { mutableStateOf("") }
    var githubUser by rememberSaveable { mutableStateOf("") }
    var inputError by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    val candidates = remember { mutableStateListOf<EditableCandidate>() }
    val scope = rememberCoroutineScope()
    var showScanner by remember { mutableStateOf(false) }

    if (showScanner) {
        QrScanner(
            onResult = { value ->
                try {
                    val parsed = RecipientImport.parsePastedText(value)
                        .copy(source = StoredRecipientSource.QR_SCAN)
                    candidates.add(EditableCandidate(parsed))
                    inputError = null
                } catch (e: Exception) {
                    inputError = e.message
                }
                showScanner = false
            },
            onCancel = { showScanner = false },
        )
        return
    }


    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            "Add recipient",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.primary,
        )

        TabRow(selectedTabIndex = source.ordinal) {
            AddRecipientSource.entries.forEach { s ->
                Tab(
                    selected = source == s,
                    onClick = { source = s; inputError = null },
                    text = { Text(s.label) },
                )
            }
        }

        when (source) {
            AddRecipientSource.PASTE -> {
                OutlinedTextField(
                    value = pasteText,
                    onValueChange = { pasteText = it; inputError = null },
                    label = { Text("age1… or ssh-ed25519 / ssh-rsa AAAA…") },
                    minLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = {
                        try {
                            val c = RecipientImport.parsePastedText(pasteText)
                            candidates.add(EditableCandidate(c))
                            pasteText = ""
                            inputError = null
                        } catch (e: Exception) {
                            inputError = e.message
                        }
                    },
                    enabled = pasteText.isNotBlank(),
                ) { Text("Parse") }
            }

            AddRecipientSource.GITHUB -> {
                OutlinedTextField(
                    value = githubUser,
                    onValueChange = { githubUser = it; inputError = null },
                    label = { Text("GitHub username") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = {
                        if (loading) return@Button
                        loading = true
                        inputError = null
                        scope.launch {
                            try {
                                val found = RecipientImport.fetchFromGitHub(githubUser)
                                found.forEach { candidates.add(EditableCandidate(it)) }
                            } catch (e: Exception) {
                                inputError = e.message
                            } finally {
                                loading = false
                            }
                        }
                    },
                    enabled = githubUser.isNotBlank() && !loading,
                ) {
                    if (loading) CircularProgressIndicator(modifier = Modifier.height(18.dp)) else Text("Fetch")
                }
                Text(
                    "Fetches github.com/<username>.keys. Only ed25519 and RSA keys are read.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            AddRecipientSource.SCAN -> {
                Text(
                    "Scan a QR code that encodes an age recipient (age1…) or an OpenSSH public key.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(onClick = { inputError = null; showScanner = true }) { Text("Open camera") }
            }
        }

        if (inputError != null) {
            Text(inputError!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }

        if (candidates.isNotEmpty()) {
            HorizontalDivider()
            Text(
                "Found ${candidates.size} recipient${if (candidates.size == 1) "" else "s"}",
                style = MaterialTheme.typography.titleSmall,
            )
            candidates.forEach { ec ->
                CandidateRow(
                    ec = ec,
                    onDiscard = { candidates.removeAll { it.key == ec.key } },
                )
                HorizontalDivider()
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            val savable = candidates.count { it.include }
            Button(
                onClick = {
                    candidates.filter { it.include }.forEach { ec ->
                        val c = ec.candidate
                        vault.addRecipient(
                            StoredRecipient(
                                id = UUID.randomUUID().toString(),
                                name = ec.name.trim().ifBlank { c.defaultName },
                                type = c.type,
                                publicKeyB64 = c.publicKeyB64,
                                sshComment = c.sshComment,
                                source = c.source,
                                sourceMetadata = c.sourceMetadata,
                                createdAt = System.currentTimeMillis(),
                            )
                        )
                    }
                    onDone()
                },
                enabled = savable > 0,
                modifier = Modifier.weight(1f),
            ) { Text(if (savable > 0) "Save $savable" else "Save") }
            OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) { Text("Cancel") }
        }
    }
}

@Composable
private fun CandidateRow(ec: EditableCandidate, onDiscard: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Switch(checked = ec.include, onCheckedChange = { ec.include = it })
        Column(Modifier.weight(1f).padding(start = 12.dp)) {
            Text(
                typeLabel(ec.candidate.type),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = ec.name,
                onValueChange = { ec.name = it },
                label = { Text("Name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            if (!ec.candidate.sshComment.isNullOrBlank()) {
                Text(
                    ec.candidate.sshComment!!,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        TextButton(onClick = onDiscard) { Text("Discard") }
    }
}

// MARK: - Labels

private fun typeLabel(t: StoredRecipientType): String = when (t) {
    StoredRecipientType.X25519 -> "age X25519"
    StoredRecipientType.SSH_ED25519 -> "SSH Ed25519"
    StoredRecipientType.SSH_RSA -> "SSH RSA"
}

private fun sourceLabel(s: StoredRecipientSource): String = when (s) {
    StoredRecipientSource.PASTE_AGE -> "PASTE"
    StoredRecipientSource.PASTE_SSH -> "PASTE"
    StoredRecipientSource.QR_SCAN -> "QR"
    StoredRecipientSource.GITHUB -> "GITHUB"
    StoredRecipientSource.DERIVED_FROM_IDENTITY -> "SELF"
}
