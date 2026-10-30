package com.agepony.app.ui.identities

import com.agepony.app.vault.DefaultKeyNames
import com.agepony.app.ui.UserMessage
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.foundation.layout.heightIn
import com.agepony.app.ui.components.ChoiceField
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.ui.components.KeyAvatar
import com.agepony.app.ui.components.KeyBlock
import com.agepony.app.ui.components.PostQuantumBadge
import com.agepony.app.ui.scan.QrScanner
import com.agepony.app.vault.RecipientCandidate
import com.agepony.app.vault.RecipientImport
import com.agepony.app.vault.StoredRecipient
import com.agepony.app.vault.StoredRecipientSource
import com.agepony.app.vault.StoredRecipientType
import com.agepony.app.vault.Vault
import com.agepony.app.vault.isPostQuantum
import com.agepony.app.vault.publicDisplayString
import kotlinx.coroutines.launch
import java.util.UUID
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import com.agepony.app.R
import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.ui.platform.LocalContext
import com.agepony.core.recipients.MIN_RSA_RECIPIENT_BITS
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.EmptyState
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.QuietAction
import com.agepony.app.ui.components.OneLineValue
import com.agepony.app.ui.components.ValueRow
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.pluralResource

//
// Recipients pane (Phase 2c-2): list / detail / add. Add Recipient supports the
// paste and GitHub paths (QR deferred). Parsed candidates are reviewed (name +
// include) before saving, mirroring iOS's AddRecipientView "Found" section.
//
// The candidate's name field starts *empty* and the key summary is rendered above it.
// It used to be pre-filled with the truncated key, which testers read as a read-only
// display of the parsed key rather than an editable field, so recipients ended up
// saved under names like "age1pqdu27d…d8swW".
//

@Composable
internal fun RecipientList(
    vault: Vault,
    onOpen: (String) -> Unit,
    onAdd: () -> Unit,
) {
    // Add and Recently deleted live in the Identities app bar; the empty state offers Add too.
    if (vault.recipients.isEmpty()) {
        EmptyState(
            title = stringResource(R.string.identities_recipients_empty_title),
            body = stringResource(R.string.identities_recipients_empty_body),
            actionLabel = stringResource(R.string.action_add_recipient),
            onAction = onAdd,
        )
    } else {
        LazyColumn(Modifier.fillMaxSize()) {
            items(vault.recipients, key = { it.id }) { recipient ->
                RecipientRow(recipient = recipient, onClick = { onOpen(recipient.id) })
                ListDivider()
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
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KeyAvatar(seed = recipient.publicKeyB64, name = recipient.name)
        val tooSmall = remember(recipient.type, recipient.publicKeyB64) {
            RecipientImport.isRsaBelowMinimum(recipient.type, recipient.publicKeyB64)
        }
        Column(Modifier.weight(1f)) {
            Text(recipient.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (recipient.type.isPostQuantum) {
                    PostQuantumBadge(modifier = Modifier.padding(end = 8.dp))
                }
                // Where the key came from, as a plain word (no pill).
                Text(
                    text = stringResource(sourceLabel(recipient.source)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                // The key on one line, cut in the middle so both ends stay readable (5.1.0, U4).
                OneLineValue(
                    recipient.publicDisplayString(),
                    modifier = Modifier.padding(start = 8.dp).weight(1f, fill = false),
                )
            }
            // Audit L-4: encrypting to an ssh-rsa key under 2048 bits now fails, so say so here
            // rather than only when a file is encrypted.
            if (tooSmall) {
                Text(
                    rsaTooSmallText(LocalContext.current, null),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
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
    modifier: Modifier = Modifier,
) {
    val recipient = vault.recipients.firstOrNull { it.id == recipientId }
    var confirmDelete by remember { mutableStateOf(false) }
    // Rename starts from the app bar, as on iOS (5.1.0, U4); the field opens in the content.
    val renaming = remember(recipientId) { mutableStateOf(false) }
    val draftName = remember(recipientId) { mutableStateOf(recipient?.name.orEmpty()) }

    if (confirmDelete && recipient != null) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.recipient_delete_title, recipient.name)) },
            text = { Text(stringResource(R.string.recipient_delete_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    vault.deleteRecipient(recipientId)
                    onBack()
                }) { Text(stringResource(R.string.action_delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }

    AgeScreen(
        title = stringResource(R.string.recipient_title),
        modifier = modifier,
        onBack = onBack,
        actions = {
            if (recipient != null && !renaming.value) {
                TextButton(onClick = {
                    draftName.value = recipient.name
                    renaming.value = true
                }) { Text(stringResource(R.string.identities_rename)) }
            }
        },
    ) { padding ->
    Column(Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState())) {
        if (recipient == null) {
            Text(
                stringResource(R.string.identities_recipient_not_found),
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(24.dp),
            )
            return@Column
        }

        Column(
            Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (renaming.value) {
                OutlinedTextField(
                    value = draftName.value,
                    onValueChange = { draftName.value = it },
                    label = { Text(stringResource(R.string.identities_name_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = { renaming.value = false }) { Text(stringResource(R.string.action_cancel)) }
                    Button(
                        onClick = {
                            vault.renameRecipient(recipientId, draftName.value)
                            renaming.value = false
                        },
                        enabled = draftName.value.isNotBlank(),
                    ) { Text(stringResource(R.string.identities_save)) }
                }
            }
            // Name, type, source and origin as rows of a details list (5.1.0, U4).
            Column {
                if (!renaming.value) {
                    ValueRow(stringResource(R.string.identities_row_name), recipient.name)
                    ListDivider()
                }
                ValueRow(stringResource(R.string.identities_row_type), stringResource(typeLabel(recipient.type)))
                if (recipient.type.isPostQuantum) {
                    PostQuantumBadge(modifier = Modifier.padding(bottom = 8.dp))
                }
                ListDivider()
                ValueRow(stringResource(R.string.identities_row_source), stringResource(sourceLabel(recipient.source)))
                recipient.sourceMetadata?.let { meta ->
                    ListDivider()
                    ValueRow(stringResource(R.string.identities_row_origin), meta)
                }
                if (!recipient.sshComment.isNullOrBlank()) {
                    ListDivider()
                    ValueRow(stringResource(R.string.identities_row_comment), recipient.sshComment!!)
                }
            }
            if (RecipientImport.isRsaBelowMinimum(recipient.type, recipient.publicKeyB64)) {
                Text(
                    rsaTooSmallText(
                        LocalContext.current,
                        RecipientImport.rsaBits(recipient.type, recipient.publicKeyB64),
                        withAdvice = true,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            ListDivider(Modifier.padding(vertical = 8.dp))

            KeyBlock(label = stringResource(R.string.identities_public_key), value = recipient.publicDisplayString())

            QuietAction(text = stringResource(R.string.identities_recipient_delete_button), onClick = { confirmDelete = true }, destructive = true)
            Text(
                stringResource(R.string.identities_recipient_delete_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 24.dp),
            )
        }
    }
    }
}

// MARK: - Add recipient

private enum class AddRecipientSource(@param:StringRes val label: Int) {
    PASTE(R.string.identities_add_source_paste),
    GITHUB(R.string.identities_add_source_github),
    SCAN(R.string.identities_add_source_scan),
}

private class EditableCandidate(val candidate: RecipientCandidate) {
    val key: String = UUID.randomUUID().toString()
    var name by mutableStateOf("")
    /** An ssh-rsa key too small to encrypt to starts unselected (audit L-4). */
    val tooSmall: Boolean = RecipientImport.isRsaBelowMinimum(candidate.type, candidate.publicKeyB64)
    var include by mutableStateOf(!tooSmall)
}

@Composable
internal fun AddRecipientFlow(
    vault: Vault,
    onDone: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var source by rememberSaveable { mutableStateOf(AddRecipientSource.PASTE) }
    var pasteText by rememberSaveable { mutableStateOf("") }
    var githubUser by rememberSaveable { mutableStateOf("") }
    var inputError by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    val candidates = remember { mutableStateListOf<EditableCandidate>() }
    val scope = rememberCoroutineScope()
    var showScanner by remember { mutableStateOf(false) }
    val context = LocalContext.current

    // A blank name still saves (it falls back to the key summary), but it is nearly always an
    // oversight rather than a choice, so confirm instead of silently storing a key as a name.
    var confirmUnnamed by remember { mutableStateOf(false) }

    if (showScanner) {
        QrScanner(
            onResult = { value ->
                try {
                    val parsed = RecipientImport.parsePastedText(value, DefaultKeyNames.from(context))
                        .copy(source = StoredRecipientSource.QR_SCAN)
                    candidates.add(EditableCandidate(parsed))
                    inputError = null
                } catch (e: Exception) {
                    inputError = UserMessage.text(context, e, R.string.files_picker_parse_failed)
                }
                showScanner = false
            },
            onCancel = { showScanner = false },
            modifier = modifier,
        )
        return
    }

    val commit: () -> Unit = {
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
    }

    if (confirmUnnamed) {
        AlertDialog(
            onDismissRequest = { confirmUnnamed = false },
            title = { Text(stringResource(R.string.identities_unnamed_title)) },
            text = {
                Text(stringResource(R.string.identities_unnamed_body))
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmUnnamed = false
                    commit()
                }) { Text(stringResource(R.string.identities_unnamed_save)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmUnnamed = false }) { Text(stringResource(R.string.identities_unnamed_go_back)) }
            },
        )
    }

    AgeScreen(title = stringResource(R.string.action_add_recipient), modifier = modifier, onBack = onCancel) { padding ->
    Column(
        Modifier
            .fillMaxSize()
            .padding(padding)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // A menu labelled Source, as on iOS (5.1.0, U4).
        ChoiceField(
            label = stringResource(R.string.identities_row_source),
            selected = source,
            options = AddRecipientSource.entries.toList(),
            optionLabel = { stringResource(it.label) },
            onSelect = { source = it; inputError = null },
            modifier = Modifier.fillMaxWidth(),
        )

        when (source) {
            AddRecipientSource.PASTE -> {
                OutlinedTextField(
                    value = pasteText,
                    onValueChange = { pasteText = it; inputError = null },
                    label = { Text(stringResource(R.string.identities_paste_label)) },
                    minLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(
                    onClick = {
                        try {
                            val c = RecipientImport.parsePastedText(pasteText, DefaultKeyNames.from(context))
                            candidates.add(EditableCandidate(c))
                            pasteText = ""
                            inputError = null
                        } catch (e: Exception) {
                            inputError = UserMessage.text(context, e, R.string.files_picker_parse_failed)
                        }
                    },
                    enabled = pasteText.isNotBlank(),
                ) { Text(stringResource(R.string.identities_parse)) }
            }

            AddRecipientSource.GITHUB -> {
                OutlinedTextField(
                    value = githubUser,
                    onValueChange = { githubUser = it; inputError = null },
                    label = { Text(stringResource(R.string.identities_github_username)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                // Outlined: Save below is the screen's one filled button.
                OutlinedButton(
                    onClick = {
                        if (loading) return@OutlinedButton
                        loading = true
                        inputError = null
                        scope.launch {
                            try {
                                val found = RecipientImport.fetchFromGitHub(
                                    githubUser,
                                    vault.proxyConfig,
                                    DefaultKeyNames.from(context),
                                )
                                found.forEach { candidates.add(EditableCandidate(it)) }
                            } catch (e: Exception) {
                                // An account with no usable keys says so ("found none", U5).
                                inputError = UserMessage.text(context, e, R.string.identities_github_fetch_failed)
                            } finally {
                                loading = false
                            }
                        }
                    },
                    enabled = githubUser.isNotBlank() && !loading,
                ) {
                    if (loading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    } else {
                        Text(stringResource(R.string.identities_fetch))
                    }
                }
                Text(
                    stringResource(R.string.identities_github_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            AddRecipientSource.SCAN -> {
                Text(
                    stringResource(R.string.identities_scan_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedButton(onClick = { inputError = null; showScanner = true }) { Text(stringResource(R.string.identities_open_camera)) }
            }
        }

        if (inputError != null) ErrorText(inputError!!)

        if (candidates.isNotEmpty()) {
            ListDivider()
            SectionHeader(pluralResource(R.plurals.recipients_found, candidates.size, candidates.size))
            candidates.forEach { ec ->
                CandidateRow(
                    ec = ec,
                    onDiscard = { candidates.removeAll { it.key == ec.key } },
                )
                ListDivider()
            }
        }

        // Stacked, full width, so long translated labels never squeeze (5.1.0, U4).
        Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            val savable = candidates.count { it.include }
            Button(
                onClick = {
                    if (candidates.any { it.include && it.name.isBlank() }) {
                        confirmUnnamed = true
                    } else {
                        commit()
                    }
                },
                enabled = savable > 0,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (savable > 0) pluralResource(R.plurals.identities_save_count, savable, savable)
                    else stringResource(R.string.identities_save)
                )
            }
            QuietAction(stringResource(R.string.action_cancel), onClick = onCancel)
        }
    }
    }
}

@Composable
private fun CandidateRow(ec: EditableCandidate, onDiscard: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        // Which key this is, first — then an empty field to name it. The order matters:
        // a name field pre-filled with the key reads as a label, not as an input.
        // The whole row toggles "include"; the Switch only draws it. Discard stays its own button.
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .toggleable(
                    value = ec.include,
                    role = Role.Switch,
                    onValueChange = { ec.include = it },
                )
                .heightIn(min = 48.dp),
        ) {
            Switch(checked = ec.include, onCheckedChange = null)
            Column(Modifier.weight(1f).padding(start = 12.dp)) {
                Text(
                    stringResource(typeLabel(ec.candidate.type)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OneLineValue(candidateKeySummary(ec.candidate), color = MaterialTheme.colorScheme.onSurface)
                if (!ec.candidate.sshComment.isNullOrBlank()) {
                    // The comment is a label someone typed, not key material, so the UI font.
                    Text(
                        ec.candidate.sshComment!!,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (ec.tooSmall) {
                    Text(
                        rsaTooSmallText(
                            LocalContext.current,
                            RecipientImport.rsaBits(ec.candidate.type, ec.candidate.publicKeyB64),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            TextButton(onClick = onDiscard) { Text(stringResource(R.string.identities_discard)) }
        }
        OutlinedTextField(
            value = ec.name,
            onValueChange = { ec.name = it },
            label = { Text(stringResource(R.string.identities_name_label)) },
            placeholder = { Text(stringResource(R.string.identities_name_placeholder)) },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp),
        )
    }
}

/**
 * One-line, middle-elided rendering of a parsed key: enough to compare against what the
 * sender published, short enough to sit above the name field. Falls back to the candidate's
 * default name if the key somehow will not re-render.
 */
private fun candidateKeySummary(candidate: RecipientCandidate): String {
    val full = runCatching { candidate.publicDisplayString() }.getOrNull()
        ?: return candidate.defaultName
    return when (candidate.type) {
        StoredRecipientType.X25519, StoredRecipientType.MLKEM768X25519, StoredRecipientType.YUBIKEY_P256,
        StoredRecipientType.TAG, StoredRecipientType.TAG_PQ ->
            if (full.length <= 24) full else "${full.take(14)}…${full.takeLast(5)}"

        StoredRecipientType.SSH_ED25519, StoredRecipientType.SSH_RSA -> {
            // "ssh-ed25519 AAAAC3… comment" — keep the algorithm, elide the blob, drop the comment
            // (it already has its own line).
            val parts = full.trim().split(Regex("\\s+"))
            val algo = parts.firstOrNull().orEmpty()
            val blob = parts.getOrNull(1).orEmpty()
            if (blob.length <= 18) "$algo $blob".trim()
            else "$algo ${blob.take(10)}…${blob.takeLast(6)}"
        }
    }
}

// MARK: - Labels

@StringRes
private fun typeLabel(t: StoredRecipientType): Int = when (t) {
    StoredRecipientType.X25519 -> R.string.identities_type_x25519
    StoredRecipientType.MLKEM768X25519 -> R.string.identities_type_mlkem
    StoredRecipientType.SSH_ED25519 -> R.string.identities_type_ssh_ed25519
    StoredRecipientType.SSH_RSA -> R.string.identities_type_ssh_rsa
    StoredRecipientType.YUBIKEY_P256 -> R.string.identities_rtype_yubikey
    StoredRecipientType.TAG -> R.string.identities_rtype_tag
    StoredRecipientType.TAG_PQ -> R.string.identities_rtype_tag_pq
}

/** Where a recipient came from, as a row label (sentence start). */
@StringRes
private fun sourceLabel(s: StoredRecipientSource): Int = when (s) {
    StoredRecipientSource.PASTE_AGE -> R.string.identities_source_pasted
    StoredRecipientSource.PASTE_SSH -> R.string.identities_source_pasted
    StoredRecipientSource.QR_SCAN -> R.string.identities_source_scanned
    StoredRecipientSource.GITHUB -> R.string.identities_source_github
    StoredRecipientSource.DERIVED_FROM_IDENTITY -> R.string.identities_source_identity
}


/** "Too small to encrypt to" text for an ssh-rsa key under the minimum (audit L-4). */
internal fun rsaTooSmallText(context: Context, bits: Int?, withAdvice: Boolean = false): String = when {
    bits != null && withAdvice ->
        context.getString(R.string.identities_rsa_too_small_bits_advice, bits, MIN_RSA_RECIPIENT_BITS)
    bits != null -> context.getString(R.string.identities_rsa_too_small_bits, bits, MIN_RSA_RECIPIENT_BITS)
    withAdvice -> context.getString(R.string.identities_rsa_too_small_advice, MIN_RSA_RECIPIENT_BITS)
    else -> context.getString(R.string.identities_rsa_too_small, MIN_RSA_RECIPIENT_BITS)
}
