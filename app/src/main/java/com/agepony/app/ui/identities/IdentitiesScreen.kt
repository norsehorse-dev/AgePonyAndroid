package com.agepony.app.ui.identities

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import com.agepony.app.ui.settings.RecentlyDeletedScreen
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.agepony.app.security.SecurityKeyService
import com.agepony.app.security.keystore.HardwareKeyService
import com.agepony.app.security.keystore.HardwareTagKeyService
import com.agepony.app.security.piv.YubiKeyBroker
import com.agepony.core.recipients.YubiKeyStub
import com.agepony.app.ui.components.KeyAvatar
import com.agepony.app.ui.components.PostQuantumBadge
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import com.agepony.app.vault.IdentityImport
import com.agepony.app.vault.IdentityImportException
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.Vault
import com.agepony.app.vault.b64e
import com.agepony.app.vault.isPostQuantum
import com.agepony.app.vault.publicDisplayString
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.SSHEd25519Identity
import com.agepony.core.recipients.X25519Identity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import androidx.compose.foundation.layout.imePadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.EmptyState
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.SwitchRow
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.theme.AgeStatus
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import androidx.annotation.StringRes

//
// Identities tab (Phase 2c-2). A two-tab segmented control switches between the
// user's own identities and saved recipients (the Android counterpart of iOS's
// IdentitiesView segmented Picker). Each pane has its own list / add / detail
// sub-navigation, held as plain state (no nav library).
//

private enum class IdSegment(@StringRes val label: Int) {
    IDENTITIES(R.string.identities_tab_mine),
    RECIPIENTS(R.string.identities_tab_recipients),
}

private enum class PaneMode { LIST, ADD, DETAIL }

@Composable
fun IdentitiesScreen(vault: Vault, modifier: Modifier = Modifier) {
    var segment by rememberSaveable { mutableStateOf(IdSegment.IDENTITIES) }
    var mode by rememberSaveable { mutableStateOf(PaneMode.LIST) }
    var detailId by rememberSaveable { mutableStateOf<String?>(null) }
    var showTrash by rememberSaveable { mutableStateOf(false) }

    fun toList() {
        mode = PaneMode.LIST
        detailId = null
    }

    if (showTrash) {
        RecentlyDeletedScreen(vault = vault, onBack = { showTrash = false }, modifier = modifier)
        return
    }

    when (mode) {
        PaneMode.LIST -> AgeScreen(
            title = stringResource(R.string.identities_title),
            modifier = modifier,
            actions = {
                IconButton(onClick = { mode = PaneMode.ADD }) {
                    Icon(
                        Icons.Filled.Add,
                        contentDescription = stringResource(
                            if (segment == IdSegment.IDENTITIES) R.string.action_add_identity else R.string.action_add_recipient
                        ),
                    )
                }
                var menuOpen by remember { mutableStateOf(false) }
                Box {
                    IconButton(onClick = { menuOpen = true }) {
                        Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.action_more_options))
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.identities_recently_deleted)) },
                            onClick = { menuOpen = false; showTrash = true },
                        )
                    }
                }
            },
        ) { padding ->
            Column(Modifier.fillMaxSize().padding(padding)) {
                PrimaryTabRow(
                    selectedTabIndex = segment.ordinal,
                    containerColor = MaterialTheme.colorScheme.background,
                ) {
                    IdSegment.entries.forEach { s ->
                        Tab(
                            selected = segment == s,
                            onClick = { if (s != segment) { segment = s; toList() } },
                            text = { Text(stringResource(s.label)) },
                        )
                    }
                }
                when (segment) {
                    IdSegment.IDENTITIES -> IdentityList(
                        vault = vault,
                        onOpen = { detailId = it; mode = PaneMode.DETAIL },
                    )
                    IdSegment.RECIPIENTS -> RecipientList(
                        vault = vault,
                        onOpen = { detailId = it; mode = PaneMode.DETAIL },
                    )
                }
            }
        }

        PaneMode.ADD -> when (segment) {
            IdSegment.IDENTITIES -> AddIdentityFlow(
                vault = vault,
                modifier = modifier,
                onDone = { toList() },
                onCancel = { toList() },
            )
            IdSegment.RECIPIENTS -> AddRecipientFlow(
                vault = vault,
                onDone = { toList() },
                onCancel = { toList() },
                modifier = modifier,
            )
        }

        PaneMode.DETAIL -> when (segment) {
            IdSegment.IDENTITIES -> IdentityDetail(
                vault = vault,
                identityId = detailId.orEmpty(),
                modifier = modifier,
                onBack = { toList() },
            )
            IdSegment.RECIPIENTS -> RecipientDetail(
                vault = vault,
                recipientId = detailId.orEmpty(),
                onBack = { toList() },
                modifier = modifier,
            )
        }
    }
}

// MARK: - Identity list

@Composable
private fun IdentityList(
    vault: Vault,
    onOpen: (String) -> Unit,
) {
    // Add and Recently deleted live in the app bar.
    if (vault.identities.isEmpty()) {
        EmptyState(
            title = stringResource(R.string.identities_empty_title),
            body = stringResource(R.string.identities_empty_body),
        )
    } else {
        LazyColumn(Modifier.fillMaxSize()) {
            items(vault.identities, key = { it.id }) { identity ->
                IdentityRow(
                    identity = identity,
                    isActive = identity.id == vault.activeIdentityId,
                    onClick = { onOpen(identity.id) },
                )
                ListDivider()
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
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KeyAvatar(seed = identity.publicKeyB64, name = identity.name)
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(identity.name, style = MaterialTheme.typography.bodyLarge)
                if (identity.type.isPostQuantum) {
                    PostQuantumBadge(modifier = Modifier.padding(start = 8.dp))
                }
                if (isActive) {
                    Text(
                        stringResource(R.string.identities_active),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 8.dp),
                    )
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
    modifier: Modifier,
    onDone: () -> Unit,
    onCancel: () -> Unit,
) {
    var stage by rememberSaveable { mutableStateOf(AddIdentityStage.CHOICE) }
    var keyType by rememberSaveable { mutableStateOf<GenKeyType?>(null) }

    // One app bar for the whole flow; its back arrow (and system back) steps up one level:
    // key form -> type chooser -> add choice -> identity list.
    fun back() {
        when {
            stage == AddIdentityStage.CHOICE -> onCancel()
            stage == AddIdentityStage.GENERATE && keyType != null -> keyType = null
            else -> stage = AddIdentityStage.CHOICE
        }
    }
    val title = when (stage) {
        AddIdentityStage.CHOICE -> stringResource(R.string.action_add_identity)
        AddIdentityStage.IMPORT -> stringResource(R.string.identities_import_title)
        AddIdentityStage.GENERATE -> stringResource(keyType?.title ?: R.string.identities_generate_title)
    }

    AgeScreen(title = title, modifier = modifier, onBack = { back() }) { padding ->
    Box(Modifier.fillMaxSize().padding(padding)) {
    when (stage) {
        AddIdentityStage.CHOICE -> Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                stringResource(R.string.identities_add_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = { stage = AddIdentityStage.GENERATE },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.identities_generate_new)) }
            OutlinedButton(
                onClick = { stage = AddIdentityStage.IMPORT },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.identities_import_existing)) }
            TextButton(onClick = onCancel) { Text(stringResource(R.string.action_cancel)) }
        }

        AddIdentityStage.GENERATE -> GenerateIdentity(
            vault,
            keyType = keyType,
            onPick = { keyType = it },
            onDone = onDone,
            onCancel = onCancel,
        )
        AddIdentityStage.IMPORT -> ImportIdentity(vault, onDone = onDone, onCancel = onCancel)
    }
    }
    }
}

/** Kinds of key the Generate step can create; [title] is the app bar title for its form. */
private enum class GenKeyType(@StringRes val title: Int) {
    X25519(R.string.identities_gen_title_x25519),
    QUANTUM_SAFE(R.string.identities_gen_title_quantum_safe),
    HARDWARE_DECRYPT(R.string.identities_gen_title_hardware_decrypt),
    SSH_ED25519(R.string.identities_gen_title_ssh),
    HARDWARE(R.string.identities_gen_title_hardware),
    SECURITY(R.string.identities_gen_title_security),
}

@Composable
private fun GenerateIdentity(
    vault: Vault,
    keyType: GenKeyType?,
    onPick: (GenKeyType) -> Unit,
    onDone: () -> Unit,
    onCancel: () -> Unit,
) {
    when (keyType) {
        // Each key form's back step (to this chooser) is the app bar back arrow.
        null -> GenerateTypeChooser(onPick = onPick, onCancel = onCancel)
        GenKeyType.X25519 -> GenerateX25519(vault, onDone)
        GenKeyType.QUANTUM_SAFE -> GenerateHybrid(vault, onDone)
        GenKeyType.HARDWARE_DECRYPT -> GenerateHardwareDecryptKey(vault, onDone)
        GenKeyType.SSH_ED25519 -> GenerateEd25519(vault, onDone)
        GenKeyType.HARDWARE -> GenerateHardwareKey(vault, onDone)
        GenKeyType.SECURITY -> GenerateSecurityKey(vault, onDone)
    }
}

@Composable
private fun GenerateTypeChooser(onPick: (GenKeyType) -> Unit, onCancel: () -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            stringResource(R.string.identities_gen_chooser_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(onClick = { onPick(GenKeyType.X25519) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.identities_gen_option_x25519))
        }
        OutlinedButton(onClick = { onPick(GenKeyType.QUANTUM_SAFE) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.identities_gen_option_quantum_safe))
        }
        if (HardwareTagKeyService.isSupported) {
            OutlinedButton(onClick = { onPick(GenKeyType.HARDWARE_DECRYPT) }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.identities_gen_option_hardware_decrypt))
            }
        }
        OutlinedButton(onClick = { onPick(GenKeyType.SSH_ED25519) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.identities_gen_option_ssh))
        }
        OutlinedButton(onClick = { onPick(GenKeyType.HARDWARE) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.identities_gen_option_hardware))
        }
        OutlinedButton(onClick = { onPick(GenKeyType.SECURITY) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.identities_gen_option_security))
        }
        TextButton(onClick = onCancel) { Text(stringResource(R.string.action_cancel)) }
    }
}

@Composable
private fun GenerateX25519(vault: Vault, onDone: () -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    val defaultName = stringResource(R.string.identities_default_name_x25519)
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.identities_gen_x25519_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.identities_name_label)) },
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
                                name = name.trim().ifBlank { defaultName },
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
            ) { Text(stringResource(if (busy) R.string.identities_generating else R.string.identities_generate)) }
        }
    }
}

@Composable
private fun GenerateHybrid(vault: Vault, onDone: () -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    val defaultName = stringResource(R.string.identities_default_name_quantum_safe)
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.identities_gen_hybrid_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.identities_name_label)) },
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
                            val identity = HybridIdentity.generate()
                            StoredIdentity(
                                id = UUID.randomUUID().toString(),
                                name = name.trim().ifBlank { defaultName },
                                type = StoredIdentityType.MLKEM768X25519,
                                publicKeyB64 = b64e(identity.publicKey),
                                privateKeyB64 = b64e(identity.seed),
                                createdAt = System.currentTimeMillis(),
                            )
                        }
                        vault.addIdentity(stored)
                        busy = false
                        onDone()
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(if (busy) R.string.identities_generating else R.string.identities_generate)) }
        }
    }
}

@Composable
private fun GenerateEd25519(vault: Vault, onDone: () -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    val defaultName = stringResource(R.string.identities_default_name_ssh)
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.identities_gen_ssh_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.identities_name_label)) },
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
                            val identity = SSHEd25519Identity.generate()
                            StoredIdentity(
                                id = UUID.randomUUID().toString(),
                                name = name.trim().ifBlank { defaultName },
                                type = StoredIdentityType.SSH_ED25519,
                                publicKeyB64 = b64e(identity.edPublicKey),
                                privateKeyB64 = b64e(identity.edSeed),
                                createdAt = System.currentTimeMillis(),
                            )
                        }
                        vault.addIdentity(stored)
                        busy = false
                        onDone()
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(if (busy) R.string.identities_generating else R.string.identities_generate)) }
        }
    }
}

@Composable
private fun GenerateHardwareKey(vault: Vault, onDone: () -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    val defaultName = stringResource(R.string.identities_default_name_hardware)
    val createFailed = stringResource(R.string.identities_error_hardware_create)
    var requireAuth by rememberSaveable { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Column(
        Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.identities_gen_hardware_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.identities_name_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        SwitchRow(
            title = stringResource(R.string.identities_require_unlock_sign),
            checked = requireAuth,
            onCheckedChange = { requireAuth = it },
        )
        if (error != null) ErrorText(error!!)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = {
                    if (busy) return@Button
                    busy = true; error = null
                    scope.launch {
                        try {
                            val stored = withContext(Dispatchers.IO) {
                                val alias = HardwareKeyService.newAlias()
                                val generated = HardwareKeyService.generate(alias, requireAuth)
                                HardwareKeyService.toStoredIdentity(name.trim().ifBlank { defaultName }, generated)
                            }
                            vault.addIdentity(stored)
                            busy = false
                            onDone()
                        } catch (e: Exception) {
                            error = e.message ?: createFailed
                            busy = false
                        }
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(if (busy) R.string.identities_creating else R.string.identities_create)) }
        }
    }
}

/**
 * A decryption key whose private half never leaves this device's secure hardware, published as
 * an age v1.3 tag recipient (age1tag1 / age1tagpq1) that stock age can encrypt to. It cannot be
 * exported, moved or backed up, so the screen says so plainly before creating one.
 */
@Composable
private fun GenerateHardwareDecryptKey(vault: Vault, onDone: () -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    var postQuantum by rememberSaveable { mutableStateOf(true) }
    var requireAuth by rememberSaveable { mutableStateOf(false) }
    val defaultName = stringResource(R.string.identities_default_name_hardware_decrypt)
    val createFailed = stringResource(R.string.identities_error_hardware_create)
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Column(
        Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.identities_gen_hardware_decrypt_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        VerdictPanel(
            title = stringResource(R.string.identity_no_backup_title),
            detail = stringResource(R.string.identities_no_backup_detail),
            color = AgeStatus.colors.warning,
            icon = Icons.Filled.Warning,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.identities_name_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        SwitchRow(
            title = stringResource(R.string.identities_hardware_decrypt_pq_switch),
            checked = postQuantum,
            onCheckedChange = { postQuantum = it },
        )
        Text(
            if (postQuantum) stringResource(R.string.identities_hardware_decrypt_pq_detail)
            else stringResource(R.string.identities_hardware_decrypt_classic_detail),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        SwitchRow(
            title = stringResource(R.string.identities_require_unlock_decrypt),
            checked = requireAuth,
            onCheckedChange = { requireAuth = it },
        )
        if (requireAuth) {
            Text(
                stringResource(R.string.identities_screen_lock_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        if (error != null) ErrorText(error!!)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = {
                    if (busy) return@Button
                    busy = true; error = null
                    scope.launch {
                        try {
                            val label = name.trim().ifBlank { defaultName }
                            // Not cancellable: leaving the screen mid-way must not strand a
                            // Keystore key with no vault record pointing at it.
                            withContext(NonCancellable) {
                                val alias = HardwareTagKeyService.newAlias()
                                val stored = try {
                                    withContext(Dispatchers.IO) {
                                        val generated = HardwareTagKeyService.generate(alias, requireAuth)
                                        if (postQuantum) HardwareTagKeyService.toStoredHybrid(label, generated)
                                        else HardwareTagKeyService.toStoredClassic(label, generated)
                                    }
                                } catch (e: Exception) {
                                    runCatching { HardwareTagKeyService.delete(alias) }
                                    throw e
                                }
                                vault.addIdentity(stored)
                            }
                            busy = false
                            onDone()
                        } catch (e: Exception) {
                            error = e.message ?: createFailed
                            busy = false
                        }
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(if (busy) R.string.identities_creating else R.string.identities_create)) }
        }
    }
}

@Composable
private fun GenerateSecurityKey(vault: Vault, onDone: () -> Unit) {
    val activity = LocalContext.current as? FragmentActivity
    var name by rememberSaveable { mutableStateOf("") }
    var useP256 by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") } // not saveable (audit L-23)
    var needsPin by remember { mutableStateOf(false) }
    val context = LocalContext.current

    Column(
        Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.identities_gen_security_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.identities_name_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        SwitchRow(
            title = stringResource(R.string.identities_security_p256_switch),
            checked = useP256,
            onCheckedChange = { useP256 = it },
        )
        if (needsPin) {
            OutlinedTextField(
                value = pin,
                onValueChange = { pin = it },
                label = { Text(stringResource(R.string.identities_security_pin_label)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Text(
            stringResource(R.string.identities_security_tap_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (error != null) ErrorText(error!!)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = {
                    val act = activity ?: run { error = context.getString(R.string.identities_error_nfc_screen); return@Button }
                    if (busy) return@Button
                    busy = true; error = null
                    scope.launch {
                        try {
                            val stored = withContext(Dispatchers.IO) {
                                val service = SecurityKeyService(act)
                                val algo = if (useP256) SecurityKeyService.Algorithm.ECDSA_P256
                                else SecurityKeyService.Algorithm.ED25519
                                service.enroll(name.trim().ifBlank { context.getString(R.string.identities_default_name_security) }, algo, pin = pin.ifBlank { null })
                            }
                            vault.addIdentity(stored)
                            busy = false
                            onDone()
                        } catch (e: SecurityKeyService.PinRequiredException) {
                            needsPin = true
                            error = context.getString(R.string.identities_error_pin_required)
                            busy = false
                        } catch (e: SecurityKeyService.WrongPinException) {
                            error = context.getString(R.string.identities_error_pin_wrong)
                            busy = false
                        } catch (e: Exception) {
                            error = e.message ?: context.getString(R.string.identities_error_enroll_failed)
                            busy = false
                        }
                    }
                },
                enabled = activity != null,
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(if (busy) R.string.identities_enroll_busy else R.string.identities_enroll)) }
        }
    }
}

@Composable
private fun ImportIdentity(vault: Vault, onDone: () -> Unit, onCancel: () -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    // The pasted private key and its passphrase stay out of the saved-state Bundle (audit L-23).
    var keyText by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    Column(
        Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            stringResource(R.string.identities_import_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.identities_name_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = keyText,
            onValueChange = { keyText = it; error = null },
            label = { Text(stringResource(R.string.identities_import_key_label)) },
            minLines = 4,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = passphrase,
            onValueChange = { passphrase = it; error = null },
            label = { Text(stringResource(R.string.identities_import_passphrase_label)) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        if (error != null) ErrorText(error!!)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = {
                    if (busy) return@Button
                    val txt = keyText.trim()
                    if (txt.isEmpty()) { error = context.getString(R.string.identities_error_paste_key); return@Button }
                    busy = true
                    error = null
                    scope.launch {
                        try {
                            val stored = withContext(Dispatchers.IO) {
                                // Covers both AGE-SECRET-KEY-1… and AGE-SECRET-KEY-PQ-1…;
                                // fromAgeSecretKey routes on the -PQ- marker.
                                if (YubiKeyStub.isStub(txt)) {
                                    val stub = YubiKeyStub.parse(txt)
                                    val pub = YubiKeyBroker.readPublicKey(stub)
                                    StoredIdentity(
                                        id = java.util.UUID.randomUUID().toString(),
                                        name = name.trim().ifBlank { context.getString(R.string.identities_default_name_yubikey, stub.serial.toString()) },
                                        type = StoredIdentityType.YUBIKEY_PIV,
                                        publicKeyB64 = b64e(pub),
                                        privateKeyB64 = b64e(stub.toBytes()),
                                        createdAt = System.currentTimeMillis(),
                                    )
                                } else if (txt.startsWith("AGE-SECRET-KEY-", ignoreCase = true)) {
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
                            error = e.message ?: context.getString(R.string.identities_error_import_failed)
                        }
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(if (busy) R.string.identities_importing else R.string.identities_import)) }
            OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.action_cancel)) }
        }
    }
}

