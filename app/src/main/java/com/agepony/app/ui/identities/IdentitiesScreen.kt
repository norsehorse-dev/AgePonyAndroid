package com.agepony.app.ui.identities

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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
import com.agepony.app.vault.IdentityImport
import com.agepony.app.vault.IdentityImportException
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.Vault
import com.agepony.app.vault.b64e
import com.agepony.app.vault.publicDisplayString
import com.agepony.core.recipients.X25519Identity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

//
// Identities tab (Phase 2c-2). A two-tab segmented control switches between the
// user's own identities and saved recipients (the Android counterpart of iOS's
// IdentitiesView segmented Picker). Each pane has its own list / add / detail
// sub-navigation, held as plain state (no nav library).
//

private enum class IdSegment(val label: String) {
    IDENTITIES("My Identities"),
    RECIPIENTS("Recipients"),
}

private enum class PaneMode { LIST, ADD, DETAIL }

@Composable
fun IdentitiesScreen(vault: Vault, modifier: Modifier = Modifier) {
    var segment by rememberSaveable { mutableStateOf(IdSegment.IDENTITIES) }
    var mode by rememberSaveable { mutableStateOf(PaneMode.LIST) }
    var detailId by rememberSaveable { mutableStateOf<String?>(null) }

    fun toList() {
        mode = PaneMode.LIST
        detailId = null
    }

    Column(modifier) {
        if (mode == PaneMode.LIST) {
            TabRow(selectedTabIndex = segment.ordinal) {
                IdSegment.entries.forEach { s ->
                    Tab(
                        selected = segment == s,
                        onClick = { if (s != segment) { segment = s; toList() } },
                        text = { Text(s.label) },
                    )
                }
            }
        }

        when (segment) {
            IdSegment.IDENTITIES -> when (mode) {
                PaneMode.LIST -> IdentityList(
                    vault = vault,
                    onAdd = { mode = PaneMode.ADD },
                    onOpen = { detailId = it; mode = PaneMode.DETAIL },
                )

                PaneMode.ADD -> AddIdentityFlow(
                    vault = vault,
                    onDone = { toList() },
                    onCancel = { toList() },
                )

                PaneMode.DETAIL -> IdentityDetail(
                    vault = vault,
                    identityId = detailId.orEmpty(),
                    onBack = { toList() },
                )
            }

            IdSegment.RECIPIENTS -> when (mode) {
                PaneMode.LIST -> RecipientList(
                    vault = vault,
                    onAdd = { mode = PaneMode.ADD },
                    onOpen = { detailId = it; mode = PaneMode.DETAIL },
                )

                PaneMode.ADD -> AddRecipientFlow(
                    vault = vault,
                    onDone = { toList() },
                    onCancel = { toList() },
                )

                PaneMode.DETAIL -> RecipientDetail(
                    vault = vault,
                    recipientId = detailId.orEmpty(),
                    onBack = { toList() },
                )
            }
        }
    }
}

// MARK: - Identity list

@Composable
private fun IdentityList(
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

        if (vault.identities.isEmpty()) {
            EmptyPane(
                title = "No identities yet",
                body = "Tap Add to generate or import an age identity.",
            )
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(vault.identities, key = { it.id }) { identity ->
                    IdentityRow(
                        identity = identity,
                        isActive = identity.id == vault.activeIdentityId,
                        onClick = { onOpen(identity.id) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun IdentityRow(identity: StoredIdentity, isActive: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(identity.name, style = MaterialTheme.typography.bodyLarge)
                if (isActive) {
                    Surface(
                        color = MaterialTheme.colorScheme.primary,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.padding(start = 8.dp),
                    ) {
                        Text(
                            "ACTIVE",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onPrimary,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        )
                    }
                }
            }
            Text(
                text = identity.publicDisplayString(),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

// MARK: - Add identity (choice -> generate | import)

private enum class AddIdentityStage { CHOICE, GENERATE, IMPORT }

@Composable
private fun AddIdentityFlow(
    vault: Vault,
    onDone: () -> Unit,
    onCancel: () -> Unit,
) {
    var stage by rememberSaveable { mutableStateOf(AddIdentityStage.CHOICE) }

    when (stage) {
        AddIdentityStage.CHOICE -> Column(
            Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                "Add identity",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.primary,
            )
            Text(
                "Generate a fresh age identity, or import an existing age or OpenSSH key.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = { stage = AddIdentityStage.GENERATE },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Generate new identity") }
            OutlinedButton(
                onClick = { stage = AddIdentityStage.IMPORT },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Import existing identity") }
            TextButton(onClick = onCancel) { Text("Cancel") }
        }

        AddIdentityStage.GENERATE -> GenerateIdentity(vault, onDone = onDone, onCancel = onCancel)
        AddIdentityStage.IMPORT -> ImportIdentity(vault, onDone = onDone, onCancel = onCancel)
    }
}

@Composable
private fun GenerateIdentity(vault: Vault, onDone: () -> Unit, onCancel: () -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            "Generate identity",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(
            "Creates a fresh age X25519 keypair, stored in your vault.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text("Name") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = {
                    if (busy) return@Button
                    busy = true
                    scope.launch {
                        val stored = withContext(Dispatchers.Default) {
                            val identity = X25519Identity.generate()
                            StoredIdentity(
                                id = UUID.randomUUID().toString(),
                                name = name.trim().ifBlank { "age identity" },
                                type = StoredIdentityType.X25519,
                                publicKeyB64 = b64e(identity.publicKey),
                                privateKeyB64 = b64e(identity.privateKey),
                                createdAt = System.currentTimeMillis(),
                            )
                        }
                        vault.addIdentity(stored)
                        busy = false
                        onDone()
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(if (busy) "Generating…" else "Generate") }
            OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) { Text("Cancel") }
        }
    }
}

@Composable
private fun ImportIdentity(vault: Vault, onDone: () -> Unit, onCancel: () -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    var keyText by rememberSaveable { mutableStateOf("") }
    var passphrase by rememberSaveable { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            "Import identity",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(
            "Paste an AGE-SECRET-KEY-1… string, or a full OpenSSH private key " +
                "(-----BEGIN OPENSSH PRIVATE KEY-----). Ed25519 and age keys are supported.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text("Name") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = keyText,
            onValueChange = { keyText = it; error = null },
            label = { Text("Key") },
            minLines = 4,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = passphrase,
            onValueChange = { passphrase = it; error = null },
            label = { Text("Passphrase (only if the OpenSSH key is encrypted)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        if (error != null) {
            Text(error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = {
                    if (busy) return@Button
                    val txt = keyText.trim()
                    if (txt.isEmpty()) { error = "Paste a key first."; return@Button }
                    busy = true
                    error = null
                    scope.launch {
                        try {
                            val stored = withContext(Dispatchers.Default) {
                                if (txt.startsWith("AGE-SECRET-KEY-1", ignoreCase = true)) {
                                    IdentityImport.fromAgeSecretKey(txt, name)
                                } else {
                                    IdentityImport.fromOpenSSHPem(txt, passphrase, name)
                                }
                            }
                            vault.addIdentity(stored)
                            busy = false
                            onDone()
                        } catch (e: IdentityImportException) {
                            busy = false
                            error = e.message
                        } catch (e: Exception) {
                            busy = false
                            error = e.message ?: "Import failed."
                        }
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(if (busy) "Importing…" else "Import") }
            OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) { Text("Cancel") }
        }
    }
}

// MARK: - Shared

@Composable
internal fun EmptyPane(title: String, body: String) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            Text(
                body,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
