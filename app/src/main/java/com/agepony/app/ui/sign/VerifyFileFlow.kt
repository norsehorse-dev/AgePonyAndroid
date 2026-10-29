package com.agepony.app.ui.sign

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.signing.FileVerifier
import com.agepony.app.ui.files.SafIo
import com.agepony.app.ui.files.SourceRef
import com.agepony.app.vault.StoredSigner
import com.agepony.app.vault.StoredSignerSource
import com.agepony.app.vault.Vault
import com.agepony.app.vault.b64e
import com.agepony.core.signing.SSHSig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import androidx.activity.compose.BackHandler
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.StatusText
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.theme.AgeStatus
import com.agepony.app.ui.theme.mono
import androidx.compose.ui.res.stringResource
import com.agepony.app.R

//
// Detached verification: pick the file, pick its .sig, get a verdict. Android
// counterpart of iOS's VerifyFileView, badge included.
//
// The file is streamed through the hash, so size doesn't matter. A valid
// signature from a key that is in neither your identities nor your signers
// list offers "add this signer", which is how a first key exchange becomes a
// named, trusted one (StoredSignerSource.FROM_VERIFICATION).
//

private enum class VerifyStage { PICK, WORKING, RESULT }

@Composable
fun VerifyFileFlow(vault: Vault, modifier: Modifier = Modifier, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var stage by remember { mutableStateOf(VerifyStage.PICK) }
    var error by remember { mutableStateOf<String?>(null) }
    var file by remember { mutableStateOf<SourceRef?>(null) }
    var result by remember { mutableStateOf<FileVerifier.Result?>(null) }
    var showAddSigner by remember { mutableStateOf(false) }
    var addedName by remember { mutableStateOf<String?>(null) }

    val openSig = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        val src = file
        if (uri == null || src == null) return@rememberLauncherForActivityResult
        error = null
        stage = VerifyStage.WORKING
        val identities = vault.identities.toList()
        val signers = vault.signers.toList()
        scope.launch {
            try {
                result = withContext(Dispatchers.IO) {
                    val sigBytes = SafIo.openInput(context, uri).use { it.readBytes() }
                    FileVerifier().verifyHashed(sigBytes, identities, signers) { alg ->
                        SafIo.openInput(context, src.uri).use { SSHSig.hashStream(it, alg) }
                    }
                }
                stage = VerifyStage.RESULT
            } catch (e: Exception) {
                error = e.message ?: context.getString(R.string.sign_verify_not_ssh_signature)
                stage = VerifyStage.PICK
            }
        }
    }

    val openFile = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        error = null
        scope.launch {
            file = withContext(Dispatchers.IO) { SafIo.sourceRef(context, uri) }
            vault.autoLockSuppressed = true
            openSig.launch(arrayOf("*/*"))
        }
    }

    if (stage == VerifyStage.WORKING) BackHandler {}

    AgeScreen(
        title = stringResource(R.string.files_verify),
        modifier = modifier,
        onBack = if (stage == VerifyStage.WORKING) null else onClose,
    ) { padding ->
    when (stage) {
        VerifyStage.PICK -> Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                stringResource(R.string.sign_verify_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (error != null) ErrorText(error!!)
            Button(
                onClick = {
                    error = null
                    vault.autoLockSuppressed = true
                    openFile.launch(arrayOf("*/*"))
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.sign_verify_pick_file)) }
            TextButton(onClick = onClose) { Text(stringResource(R.string.action_cancel)) }
        }

        VerifyStage.WORKING -> Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            Text(
                stringResource(R.string.sign_verify_working),
                modifier = Modifier.padding(top = 16.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        VerifyStage.RESULT -> {
            val r = result
            if (r == null) {
                stage = VerifyStage.PICK
            } else {
                Column(
                    Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .verticalScroll(rememberScrollState())
                        .padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        file?.name ?: "",
                        style = MaterialTheme.typography.mono,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    when (r.trust) {
                        FileVerifier.Trust.TRUSTED -> VerdictPanel(
                            title = r.signerName?.let { stringResource(R.string.sign_verify_signed_by, it) }
                                ?: stringResource(R.string.sign_verify_signed_by_known_key),
                            detail = null,
                            color = AgeStatus.colors.success,
                            icon = Icons.Filled.CheckCircle,
                        )
                        // The key is on the trusted-signers list, but that entry's imported
                        // options (expiry, namespaces, touch, ...) reject this signature.
                        FileVerifier.Trust.VALID_UNKNOWN -> if (r.untrustedSignerName != null) {
                            VerdictPanel(
                                title = stringResource(R.string.sign_verify_untrusted_title),
                                detail = stringResource(
                                    R.string.sign_verify_untrusted_detail,
                                    r.untrustedSignerName ?: "",
                                    r.untrustedReason ?: stringResource(R.string.sign_verify_untrusted_default_reason),
                                ),
                                color = AgeStatus.colors.warning,
                                icon = Icons.Filled.Warning,
                            )
                        } else {
                            VerdictPanel(
                                title = stringResource(R.string.sign_verify_unknown_title),
                                detail = stringResource(R.string.sign_verify_unknown_detail),
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                icon = Icons.Filled.Info,
                            )
                        }
                        FileVerifier.Trust.INVALID -> VerdictPanel(
                            title = stringResource(R.string.sign_verify_invalid_title),
                            detail = r.reason ?: stringResource(R.string.sign_verify_failed),
                            color = AgeStatus.colors.failure,
                            icon = Icons.Filled.Warning,
                        )
                    }

                    Text(
                        r.keyType,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    r.signerPublicWire?.let { wire ->
                        Text(
                            StoredSigner.sshFingerprint(wire),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }

                    if (addedName != null) {
                        StatusText(
                            text = stringResource(R.string.sign_verify_added_signer, addedName ?: ""),
                            color = AgeStatus.colors.success,
                            icon = Icons.Filled.CheckCircle,
                        )
                    } else if (r.trust == FileVerifier.Trust.VALID_UNKNOWN && r.signerPublicWire != null &&
                        r.untrustedSignerName == null
                    ) {
                        OutlinedButton(
                            onClick = { showAddSigner = true },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(stringResource(R.string.sign_verify_add_signer)) }
                    }

                    Button(
                        onClick = {
                            result = null
                            file = null
                            error = null
                            addedName = null
                            stage = VerifyStage.PICK
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(stringResource(R.string.sign_verify_another)) }
                    OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.app_done)) }
                }

                if (showAddSigner && r.signerPublicWire != null) {
                    AddSignerNameDialog(
                        fingerprint = StoredSigner.sshFingerprint(r.signerPublicWire),
                        onConfirm = { name ->
                            val added = vault.addSigner(
                                StoredSigner(
                                    id = UUID.randomUUID().toString(),
                                    name = name,
                                    keyType = r.keyType,
                                    publicKeyWireB64 = b64e(r.signerPublicWire),
                                    comment = null,
                                    source = StoredSignerSource.FROM_VERIFICATION,
                                    createdAt = System.currentTimeMillis(),
                                )
                            )
                            addedName = if (added) name else null
                            showAddSigner = false
                        },
                        onDismiss = { showAddSigner = false },
                    )
                }
            }
        }
    }
    }
}

@Composable
private fun AddSignerNameDialog(
    fingerprint: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.sign_verify_add_signer_title)) },
        text = {
            Column {
                Text(stringResource(R.string.sign_verify_add_signer_body))
                Text(
                    fingerprint,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.sign_signers_name_label)) },
                    modifier = Modifier.padding(top = 12.dp),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(name.trim()) },
                enabled = name.trim().isNotEmpty(),
            ) { Text(stringResource(R.string.sign_signers_add)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}
