package com.agepony.app.ui.identities

import com.agepony.app.vault.LockMode
import com.agepony.app.ui.security.rememberSensitiveConfirm
import android.view.WindowManager

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.agepony.app.security.BiometricGate
import com.agepony.app.ui.portability.PaperBackupScreen
import com.agepony.app.vault.KeyPortability
import com.agepony.app.vault.isDeviceBound
import com.agepony.app.ui.components.KeyBlock
import com.agepony.app.ui.components.QrImage
import com.agepony.app.ui.components.PostQuantumBadge
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.Vault
import com.agepony.app.vault.isPostQuantum
import com.agepony.app.vault.isPrivateKeyExportable
import com.agepony.app.vault.privateDisplayString
import com.agepony.app.vault.publicDisplayString
import java.text.DateFormat
import java.util.Date
import androidx.compose.foundation.layout.fillMaxSize
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.QuietAction
import com.agepony.app.ui.components.ValueRow
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import androidx.annotation.StringRes

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
    var paperBackup by remember(identityId) { mutableStateOf(false) }
    if (paperBackup && identity != null) {
        PaperBackupScreen(vault = vault, identity = identity, onBack = { paperBackup = false }, modifier = modifier)
        return
    }

    val activity = LocalContext.current as FragmentActivity

    var revealed by remember(identityId) { mutableStateOf(false) }
    var activeId by remember { mutableStateOf(vault.activeIdentityId) }
    var renaming by remember { mutableStateOf(false) }
    var renameDraft by remember { mutableStateOf("") }
    var confirmingDelete by remember { mutableStateOf(false) }
    // Reveal is a defense-in-depth re-auth, the same owner check as sending keys or printing a
    // backup (5.1.0): the biometric or device credential, or the app password where the vault's
    // lock calls for it (a password-only vault, or Biometrics only after a biometric was added
    // or removed, or while none can run). Refused on a phone with a screen lock where no check
    // can run; straight through only with no screen lock and no app password.
    val confirmOwner = rememberSensitiveConfirm(vault)
    val isPin = vault.unlockSecretKind == "pin"

    AgeScreen(
        title = stringResource(R.string.identity_title),
        modifier = modifier,
        onBack = onBack,
        // Rename is an app bar action, as on iOS, not a button squeezed beside the name (5.1.0, U4).
        actions = {
            if (identity != null) {
                TextButton(onClick = {
                    renameDraft = identity.name
                    renaming = true
                }) { Text(stringResource(R.string.identities_rename)) }
            }
        },
    ) { padding ->
    Column(modifier = Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())) {
        if (identity == null) {
            Text(
                text = stringResource(R.string.identities_not_found),
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(24.dp),
            )
            return@Column
        }

        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            // Name, type and date as rows of a details list (5.1.0, U4).
            Column {
                ValueRow(stringResource(R.string.identities_row_name), identity.name)
                ListDivider()
                ValueRow(stringResource(R.string.identities_row_type), stringResource(typeLabel(identity.type)))
                if (identity.type.isPostQuantum) {
                    PostQuantumBadge(modifier = Modifier.padding(bottom = 8.dp))
                }
                ListDivider()
                ValueRow(
                    stringResource(R.string.identities_row_created),
                    DateFormat.getDateInstance().format(Date(identity.createdAt)),
                )
                ListDivider()
            }

            KeyBlock(label = stringResource(R.string.identities_key_public), value = identity.publicDisplayString())
            Text(
                text = stringResource(R.string.identities_public_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            var showQr by remember(identityId) { mutableStateOf(false) }
            TextButton(onClick = { showQr = !showQr }) {
                Text(stringResource(if (showQr) R.string.identities_hide_qr else R.string.identities_show_qr))
            }
            if (showQr) {
                QrImage(
                    content = identity.publicDisplayString(),
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .padding(top = 4.dp, bottom = 4.dp),
                )
            }

            val exportable = identity.isPrivateKeyExportable()
            // A revealed private key forces FLAG_SECURE even when screenshots are allowed. On
            // dispose only clear it when the activity-wide setting allows screenshots, so leaving
            // this screen never lifts the default protection (audit M-5).
            DisposableEffect(revealed) {
                val forced = revealed
                if (forced) activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                onDispose {
                    if (forced && vault.allowScreenshots) {
                        activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    }
                }
            }
            if (revealed && exportable) {
                KeyBlock(
                    label = stringResource(R.string.identities_key_private),
                    value = identity.privateDisplayString(LocalContext.current),
                    isSensitive = true,
                    copyable = true,
                )
            } else if (revealed) {
                // A key that never leaves its hardware has a sentence here, not key material,
                // so it is set in the UI font (5.1.0, U4).
                Column {
                    Text(
                        stringResource(R.string.identities_key_private),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 4.dp),
                    )
                    Text(
                        identity.privateDisplayString(LocalContext.current),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            } else {
                OutlinedButton(
                    onClick = {
                        confirmOwner(activity.getString(R.string.identities_reveal_private)) { revealed = true }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.identities_reveal_private))
                }
                Text(
                    text = stringResource(revealHint(vault, activity, isPin)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            if (KeyPortability.isPaperBackable(identity)) {
                OutlinedButton(onClick = { paperBackup = true }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                    Text(stringResource(R.string.identities_paper_backup_button))
                }
            }
            if (identity.type.isDeviceBound) {
                Text(
                    stringResource(R.string.identities_device_bound_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            ListDivider(modifier = Modifier.padding(vertical = 8.dp))

            if (activeId != identity.id) {
                TextButton(onClick = {
                    vault.activeIdentityId = identity.id
                    activeId = identity.id
                }) { Text(stringResource(R.string.identities_set_active)) }
            } else {
                Text(
                    text = stringResource(R.string.identities_is_active_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            QuietAction(text = stringResource(R.string.identities_delete_button), onClick = { confirmingDelete = true }, destructive = true)
            Text(
                text = stringResource(R.string.identities_delete_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 24.dp),
            )
        }
    }
    }

    if (renaming) {
        AlertDialog(
            onDismissRequest = { renaming = false },
            title = { Text(stringResource(R.string.identities_rename_title)) },
            text = {
                OutlinedTextField(
                    value = renameDraft,
                    onValueChange = { renameDraft = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.identities_name_label)) },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val trimmed = renameDraft.trim()
                    if (trimmed.isNotEmpty()) vault.renameIdentity(identityId, trimmed)
                    renaming = false
                }) { Text(stringResource(R.string.identities_save)) }
            },
            dismissButton = {
                TextButton(onClick = { renaming = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }

    if (confirmingDelete) {
        AlertDialog(
            onDismissRequest = { confirmingDelete = false },
            title = {
                Text(
                    if (identity != null) stringResource(R.string.identities_delete_title, identity.name)
                    else stringResource(R.string.identities_delete_title_unnamed)
                )
            },
            text = {
                Text(stringResource(R.string.identities_delete_warning))
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmingDelete = false
                    vault.deleteIdentity(identityId)
                    onBack()
                }) { Text(stringResource(R.string.action_delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { confirmingDelete = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }
}

@StringRes
private fun typeLabel(t: StoredIdentityType): Int = when (t) {
    StoredIdentityType.X25519 -> R.string.identities_type_x25519
    StoredIdentityType.MLKEM768X25519 -> R.string.identities_type_mlkem
    StoredIdentityType.SSH_ED25519 -> R.string.identities_type_ssh_ed25519
    StoredIdentityType.SSH_RSA -> R.string.identities_type_ssh_rsa
    StoredIdentityType.HARDWARE_KEY -> R.string.identities_type_hardware_key
    StoredIdentityType.SK_ED25519 -> R.string.identities_type_sk_ed25519
    StoredIdentityType.SK_ECDSA_P256 -> R.string.identities_type_sk_p256
    StoredIdentityType.HARDWARE_TAG -> R.string.identities_type_hardware_tag
    StoredIdentityType.HARDWARE_TAG_PQ -> R.string.identities_type_hardware_tag_pq
    StoredIdentityType.YUBIKEY_PIV -> R.string.identities_type_yubikey
}

/**
 * What the reveal button will ask for, following the same order as the owner check
 * ([com.agepony.app.security.OwnerCheckPolicy.route]). In Biometrics only mode the hint names
 * the biometric, never the device credential (5.1.0, iOS E6).
 */
@StringRes
private fun revealHint(vault: Vault, activity: FragmentActivity, isPin: Boolean): Int {
    val hasPassword = vault.passwordKeyBlobExists()
    val passwordHint = if (isPin) R.string.identities_reveal_needs_pin else R.string.identities_reveal_needs_password
    return when {
        hasPassword && vault.passwordIsOnlyUnlock() -> passwordHint
        vault.lockMode == LockMode.BIOMETRIC_ONLY && !vault.duressBlobExists() ->
            if (isPin) R.string.identities_reveal_needs_biometric_only_pin
            else R.string.identities_reveal_needs_biometric_only_password
        BiometricGate.canAuthenticateDefault(activity) -> R.string.identities_reveal_needs_biometric
        hasPassword -> passwordHint
        BiometricGate.isDeviceSecure(activity) -> R.string.identities_reveal_needs_screen_lock
        else -> R.string.identities_reveal_no_lock
    }
}
