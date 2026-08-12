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
                error = e.message ?: "That doesn't look like an SSH signature."
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

    when (stage) {
        VerifyStage.PICK -> Column(
            modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Verify a file", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
            Text(
                "Pick the file first, then its signature (the .sig that came with it). " +
                    "The file is only read, never changed.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (error != null) {
                Text(error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            Button(
                onClick = {
                    error = null
                    vault.autoLockSuppressed = true
                    openFile.launch(arrayOf("*/*"))
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Pick the file…") }
            TextButton(onClick = onClose) { Text("Cancel") }
        }

        VerifyStage.WORKING -> Column(
            modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            Text(
                "Checking the signature…",
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
                    modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        file?.name ?: "",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.primary,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    HorizontalDivider()

                    when (r.trust) {
                        FileVerifier.Trust.TRUSTED -> {
                            Text(
                                "Signed by ${r.signerName ?: "a known key"} ✓",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                        FileVerifier.Trust.VALID_UNKNOWN -> {
                            Text(
                                "Valid signature — signer not in your vault",
                                style = MaterialTheme.typography.titleMedium,
                            )
                            Text(
                                "The math checks out, but this key isn't one of yours and isn't " +
                                    "on your trusted signers list. If you know whose it is, add it " +
                                    "so future signatures carry their name.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        FileVerifier.Trust.INVALID -> {
                            Text(
                                "⚠ Signature invalid",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.error,
                            )
                            Text(
                                r.reason ?: "Verification failed.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
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
                        Text(
                            "Added to trusted signers as \"$addedName\".",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    } else if (r.trust == FileVerifier.Trust.VALID_UNKNOWN && r.signerPublicWire != null) {
                        OutlinedButton(
                            onClick = { showAddSigner = true },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Add this signer…") }
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
                    ) { Text("Verify another") }
                    OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Done") }
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

@Composable
private fun AddSignerNameDialog(
    fingerprint: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add trusted signer") },
        text = {
            Column {
                Text("Name the person or system this key belongs to.")
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
                    label = { Text("Name") },
                    modifier = Modifier.padding(top = 12.dp),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(name.trim()) },
                enabled = name.trim().isNotEmpty(),
            ) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
