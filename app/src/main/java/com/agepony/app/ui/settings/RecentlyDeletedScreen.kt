// RecentlyDeletedScreen.kt
// AgePony Android 4.2.0
//
// The recycle bin. Lists soft-deleted identities and recipients so an
// accidental delete can be undone. Deleting an identity destroys a private
// key, so this window matters: restore brings it back intact, or you can
// remove it for good. Entries age out after Vault.TRASH_RETENTION_DAYS.
// Reached from Settings.

package com.agepony.app.ui.settings

import com.agepony.app.ui.components.EmptyState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.R
import com.agepony.app.ui.components.KeyAvatar
import com.agepony.app.vault.Vault
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.QuietAction
import com.agepony.app.ui.components.SectionHeader

@Composable
fun RecentlyDeletedScreen(vault: Vault, onBack: () -> Unit, modifier: Modifier = Modifier) {
    var confirmEmpty by remember { mutableStateOf(false) }
    // Per-item permanent-delete confirmation: (kind, id, name).
    var confirmPurge by remember { mutableStateOf<Triple<String, String, String>?>(null) }

    val ids = vault.trashedIdentities
    val recips = vault.trashedRecipients
    val isEmpty = ids.isEmpty() && recips.isEmpty()

    AgeScreen(title = stringResource(R.string.settings_recently_deleted), modifier = modifier, onBack = onBack) { padding ->
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Text(
            stringResource(R.string.settings_trash_intro, DAYS),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 16.dp),
        )

        if (isEmpty) {
            EmptyState(
                title = stringResource(R.string.settings_trash_empty_state_title),
                body = stringResource(R.string.settings_trash_empty),
            )
            return@Column
        }

        if (ids.isNotEmpty()) {
            SectionHeader(stringResource(R.string.settings_trash_identities), Modifier.padding(bottom = 4.dp))
            ids.forEach { t ->
                TrashRow(
                    seed = t.identity.publicKeyB64,
                    name = t.identity.name,
                    deletedAt = t.deletedAt,
                    onRestore = { vault.restoreIdentity(t.identity.id) },
                    onPurge = { confirmPurge = Triple("identity", t.identity.id, t.identity.name) },
                )
                ListDivider()
            }
        }

        if (recips.isNotEmpty()) {
            SectionHeader(stringResource(R.string.settings_trash_recipients), Modifier.padding(top = 8.dp, bottom = 4.dp))
            recips.forEach { t ->
                TrashRow(
                    seed = t.recipient.publicKeyB64,
                    name = t.recipient.name,
                    deletedAt = t.deletedAt,
                    onRestore = { vault.restoreRecipient(t.recipient.id) },
                    onPurge = { confirmPurge = Triple("recipient", t.recipient.id, t.recipient.name) },
                )
                ListDivider()
            }
        }

        QuietAction(
            text = stringResource(R.string.settings_trash_empty_bin),
            onClick = { confirmEmpty = true },
            destructive = true,
            modifier = Modifier.padding(top = 16.dp, bottom = 24.dp),
        )
    }
    }

    if (confirmEmpty) {
        AlertDialog(
            onDismissRequest = { confirmEmpty = false },
            title = { Text(stringResource(R.string.settings_trash_empty_title)) },
            text = { Text(stringResource(R.string.settings_trash_empty_body)) },
            confirmButton = {
                TextButton(onClick = { confirmEmpty = false; vault.emptyTrash() }) {
                    Text(stringResource(R.string.settings_trash_empty_confirm), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { confirmEmpty = false }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }

    confirmPurge?.let { (kind, id, name) ->
        AlertDialog(
            onDismissRequest = { confirmPurge = null },
            title = { Text(stringResource(R.string.settings_trash_purge_title, name)) },
            text = {
                Text(
                    stringResource(
                        if (kind == "identity") R.string.settings_trash_purge_identity_body
                        else R.string.settings_trash_purge_recipient_body
                    )
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmPurge = null
                    if (kind == "identity") vault.purgeIdentity(id) else vault.purgeRecipient(id)
                }) { Text(stringResource(R.string.action_delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmPurge = null }) { Text(stringResource(R.string.action_cancel)) } },
        )
    }
}

@Composable
private fun TrashRow(
    seed: String,
    name: String,
    deletedAt: Long,
    onRestore: () -> Unit,
    onPurge: () -> Unit,
) {
    // The actions sit under the name, so a long translated name or label never squeezes the
    // row (5.1.0, U4). Both stay visible, as on iOS.
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 12.dp, bottom = 4.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KeyAvatar(seed = seed, name = name)
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                relativeAge(deletedAt),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                QuietAction(text = stringResource(R.string.settings_trash_restore), onClick = onRestore)
                QuietAction(text = stringResource(R.string.action_delete), onClick = onPurge, destructive = true)
            }
        }
    }
}

private const val DAYS = 30

/** "Deleted 3 hours ago": the whole line, so translations can order it freely. */
@Composable
private fun relativeAge(deletedAt: Long): String {
    val ms = System.currentTimeMillis() - deletedAt
    val minutes = (ms / 60000L).toInt()
    val hours = minutes / 60
    val days = hours / 24
    return when {
        minutes < 1 -> stringResource(R.string.settings_trash_deleted_just_now)
        minutes < 60 -> pluralStringResource(R.plurals.settings_trash_deleted_minutes, minutes, minutes)
        hours < 24 -> pluralStringResource(R.plurals.settings_trash_deleted_hours, hours, hours)
        else -> pluralStringResource(R.plurals.settings_trash_deleted_days, days, days)
    }
}
