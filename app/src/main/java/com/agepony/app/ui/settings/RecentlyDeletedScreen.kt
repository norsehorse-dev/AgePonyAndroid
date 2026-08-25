// RecentlyDeletedScreen.kt
// AgePony Android 4.2.0
//
// The recycle bin. Lists soft-deleted identities and recipients so an
// accidental delete can be undone. Deleting an identity destroys a private
// key, so this window matters: restore brings it back intact, or you can
// remove it for good. Entries age out after Vault.TRASH_RETENTION_DAYS.
// Reached from Settings.

package com.agepony.app.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.ui.components.KeyAvatar
import com.agepony.app.vault.Vault

@Composable
fun RecentlyDeletedScreen(vault: Vault, onBack: () -> Unit, modifier: Modifier = Modifier) {
    var confirmEmpty by remember { mutableStateOf(false) }
    // Per-item permanent-delete confirmation: (kind, id, name).
    var confirmPurge by remember { mutableStateOf<Triple<String, String, String>?>(null) }

    val ids = vault.trashedIdentities
    val recips = vault.trashedRecipients
    val isEmpty = ids.isEmpty() && recips.isEmpty()

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp),
    ) {
        TextButton(onClick = onBack, modifier = Modifier.padding(top = 8.dp)) { Text("‹ Back") }
        Text("Recently deleted", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(bottom = 4.dp))
        Text(
            "Deleted identities and recipients wait here for $DAYS days before they are removed for good. Restoring an identity brings its private key back intact.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 16.dp),
        )

        if (isEmpty) {
            Text(
                "Nothing here. Deleted items will show up on this screen.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 24.dp),
            )
            return@Column
        }

        if (ids.isNotEmpty()) {
            Text("Identities", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 8.dp, bottom = 4.dp))
            ids.forEach { t ->
                TrashRow(
                    seed = t.identity.publicKeyB64,
                    name = t.identity.name,
                    deletedAt = t.deletedAt,
                    onRestore = { vault.restoreIdentity(t.identity.id) },
                    onPurge = { confirmPurge = Triple("identity", t.identity.id, t.identity.name) },
                )
                HorizontalDivider()
            }
        }

        if (recips.isNotEmpty()) {
            Text("Recipients", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 16.dp, bottom = 4.dp))
            recips.forEach { t ->
                TrashRow(
                    seed = t.recipient.publicKeyB64,
                    name = t.recipient.name,
                    deletedAt = t.deletedAt,
                    onRestore = { vault.restoreRecipient(t.recipient.id) },
                    onPurge = { confirmPurge = Triple("recipient", t.recipient.id, t.recipient.name) },
                )
                HorizontalDivider()
            }
        }

        TextButton(onClick = { confirmEmpty = true }, modifier = Modifier.padding(top = 16.dp, bottom = 24.dp)) {
            Text("Empty recycle bin", color = MaterialTheme.colorScheme.error)
        }
    }

    if (confirmEmpty) {
        AlertDialog(
            onDismissRequest = { confirmEmpty = false },
            title = { Text("Empty recycle bin?") },
            text = { Text("This permanently removes everything here. Any deleted identity's private key is gone for good. This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = { confirmEmpty = false; vault.emptyTrash() }) {
                    Text("Empty", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { confirmEmpty = false }) { Text("Cancel") } },
        )
    }

    confirmPurge?.let { (kind, id, name) ->
        AlertDialog(
            onDismissRequest = { confirmPurge = null },
            title = { Text("Delete \"$name\" for good?") },
            text = {
                Text(
                    if (kind == "identity")
                        "This removes the identity and its private key permanently. Files encrypted to it can never be opened again. This cannot be undone."
                    else
                        "This removes the recipient permanently. This cannot be undone."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmPurge = null
                    if (kind == "identity") vault.purgeIdentity(id) else vault.purgeRecipient(id)
                }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmPurge = null }) { Text("Cancel") } },
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
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KeyAvatar(seed = seed, name = name)
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                "deleted ${relativeAge(deletedAt)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontFamily = FontFamily.Default,
            )
        }
        TextButton(onClick = onRestore) { Text("Restore") }
        TextButton(onClick = onPurge) { Text("Delete", color = MaterialTheme.colorScheme.error) }
    }
}

private const val DAYS = 30

private fun relativeAge(deletedAt: Long): String {
    val ms = System.currentTimeMillis() - deletedAt
    val minutes = ms / 60000L
    val hours = minutes / 60L
    val days = hours / 24L
    return when {
        minutes < 1 -> "just now"
        minutes < 60 -> "$minutes min ago"
        hours < 24 -> if (hours == 1L) "1 hour ago" else "$hours hours ago"
        days == 1L -> "1 day ago"
        else -> "$days days ago"
    }
}
