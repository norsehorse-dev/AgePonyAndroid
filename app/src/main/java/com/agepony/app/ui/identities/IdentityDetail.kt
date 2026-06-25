package com.agepony.app.ui.identities

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
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
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.agepony.app.security.BiometricGate
import com.agepony.app.security.BiometricGateException
import com.agepony.app.ui.components.KeyBlock
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.Vault
import com.agepony.app.vault.privateDisplayString
import com.agepony.app.vault.publicDisplayString
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

//
// Detail screen for a single identity (Android counterpart of iOS's
// IdentityDetailView): public key block, a biometric-gated private-key reveal,
// set-as-active, rename, and delete. Reveal re-prompts biometric even though
// the vault is unlocked, matching the iOS defense-in-depth behavior.
//
@Composable
fun IdentityDetail(
    vault: Vault,
    identityId: String,
    modifier: Modifier = Modifier,
    onBack: () -> Unit,
) {
    val identity = vault.identities.firstOrNull { it.id == identityId }

    val activity = LocalContext.current as FragmentActivity
    val scope = rememberCoroutineScope()

    var revealed by remember(identityId) { mutableStateOf(false) }
    var activeId by remember { mutableStateOf(vault.activeIdentityId) }
    var renaming by remember { mutableStateOf(false) }
    var renameDraft by remember { mutableStateOf("") }
    var confirmingDelete by remember { mutableStateOf(false) }
    var revealError by remember { mutableStateOf<String?>(null) }

    Column(modifier = modifier.verticalScroll(rememberScrollState())) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 8.dp, end = 12.dp, top = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) { Text("‹ Back") }
        }

        if (identity == null) {
            Text(
                text = "Identity not found.",
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(24.dp),
            )
            return@Column
        }

        Column(
            modifier = Modifier.padding(horizontal = 20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = identity.name,
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = {
                    renameDraft = identity.name
                    renaming = true
                }) { Text("Rename") }
            }

            Text(
                text = "${typeLabel(identity.type)}  •  created ${
                    DateFormat.getDateInstance().format(Date(identity.createdAt))
                }",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            KeyBlock(label = "Public", value = identity.publicDisplayString())
            Text(
                text = "Safe to share. Anyone with this can encrypt to you.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (revealed) {
                KeyBlock(
                    label = "Private",
                    value = identity.privateDisplayString(),
                    isSensitive = true,
                )
            } else {
                OutlinedButton(
                    onClick = {
                        scope.launch {
                            try {
                                BiometricGate.confirm(
                                    activity,
                                    title = "Reveal private key",
                                    subtitle = "Confirm it's you",
                                )
                                revealed = true
                            } catch (e: BiometricGateException) {
                                if (e.code != androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED &&
                                    e.code != androidx.biometric.BiometricPrompt.ERROR_NEGATIVE_BUTTON
                                ) {
                                    revealError = e.message
                                }
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Reveal private key")
                }
                Text(
                    text = "Revealing the private key requires your biometric or device credential.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            if (activeId != identity.id) {
                TextButton(onClick = {
                    vault.activeIdentityId = identity.id
                    activeId = identity.id
                }) { Text("Set as active identity") }
            } else {
                Text(
                    text = "This is your active identity (default encrypt-to-self recipient).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            TextButton(onClick = { confirmingDelete = true }) {
                Text("Delete identity", color = MaterialTheme.colorScheme.error)
            }
            Text(
                text = "Files encrypted to this identity will no longer be decryptable on this device.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 24.dp),
            )
        }
    }

    if (renaming) {
        AlertDialog(
            onDismissRequest = { renaming = false },
            title = { Text("Rename identity") },
            text = {
                OutlinedTextField(
                    value = renameDraft,
                    onValueChange = { renameDraft = it },
                    singleLine = true,
                    label = { Text("Name") },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val trimmed = renameDraft.trim()
                    if (trimmed.isNotEmpty()) vault.renameIdentity(identityId, trimmed)
                    renaming = false
                }) { Text("Save") }
            },
            dismissButton = {
                TextButton(onClick = { renaming = false }) { Text("Cancel") }
            },
        )
    }

    if (confirmingDelete) {
        AlertDialog(
            onDismissRequest = { confirmingDelete = false },
            title = { Text("Delete \"${identity?.name ?: "this identity"}\"?") },
            text = {
                Text("Files encrypted to this identity will no longer be decryptable on this device.")
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmingDelete = false
                    vault.deleteIdentity(identityId)
                    onBack()
                }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { confirmingDelete = false }) { Text("Cancel") }
            },
        )
    }

    if (revealError != null) {
        AlertDialog(
            onDismissRequest = { revealError = null },
            title = { Text("Couldn't reveal private key") },
            text = { Text(revealError ?: "") },
            confirmButton = {
                TextButton(onClick = { revealError = null }) { Text("OK") }
            },
        )
    }
}

private fun typeLabel(t: StoredIdentityType): String = when (t) {
    StoredIdentityType.X25519 -> "age X25519"
    StoredIdentityType.SSH_ED25519 -> "SSH Ed25519"
    StoredIdentityType.SSH_RSA -> "SSH RSA"
}
