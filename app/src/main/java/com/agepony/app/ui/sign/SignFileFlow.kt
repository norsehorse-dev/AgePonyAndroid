package com.agepony.app.ui.sign

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.agepony.app.security.SecurityKeyService
import com.agepony.app.signing.FileSigner
import com.agepony.app.ui.files.SafIo
import com.agepony.app.ui.files.SourceRef
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.Vault
import com.agepony.core.signing.SSHSig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

//
// Detached signing: pick a key, pick a file, save `<name>.sig` next to wherever
// the user chooses. Android counterpart of iOS's SignFileView.
//
// The signature is over the file's bytes exactly as they are — no bundling, no
// encryption — so the pair travels anywhere, and `ssh-keygen -Y verify` on any
// machine can check it. Software keys stream the digest, so file size doesn't
// matter; hardware and NFC keys read the file whole (see FileSigner.signStream).
//

private enum class SignStage { CONFIGURE, WORKING, DONE }

@Composable
fun SignFileFlow(vault: Vault, modifier: Modifier = Modifier, onClose: () -> Unit) {
    val context = LocalContext.current
    val activity = context as FragmentActivity
    val scope = rememberCoroutineScope()
    var skPin by remember { mutableStateOf("") }
    var needsPin by remember { mutableStateOf(false) }

    var stage by remember { mutableStateOf(SignStage.CONFIGURE) }
    var error by remember { mutableStateOf<String?>(null) }
    var selectedId by remember { mutableStateOf<String?>(null) }
    var source by remember { mutableStateOf<SourceRef?>(null) }
    var doneSigName by remember { mutableStateOf("") }

    val signingIdentities = vault.identities.filter { it.type in FileSigner.SIGNING_TYPES }
    val selected = signingIdentities.firstOrNull { it.id == selectedId }

    val createOutput = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(SafIo.MIME_OCTET)
    ) { uri: Uri? ->
        val identity = selected
        val src = source
        if (uri == null || identity == null || src == null) return@rememberLauncherForActivityResult
        error = null
        stage = SignStage.WORKING
        scope.launch {
            try {
                val armored = FileSigner(activity)
                    .signStream(identity, pin = skPin.ifBlank { null }) { SafIo.openInput(context, src.uri) }
                withContext(Dispatchers.IO) {
                    SafIo.openOutput(context, uri).use { out ->
                        out.write(armored.toByteArray(Charsets.US_ASCII))
                        out.flush()
                    }
                }
                doneSigName = FileSigner(activity).signedName(src.name)
                stage = SignStage.DONE
            } catch (e: SecurityKeyService.PinRequiredException) {
                needsPin = true
                error = "This security key needs a PIN. Enter it below and sign again."
                stage = SignStage.CONFIGURE
            } catch (e: SecurityKeyService.WrongPinException) {
                error = "Incorrect PIN. Try again."
                stage = SignStage.CONFIGURE
            } catch (e: Exception) {
                error = e.message ?: "Signing failed."
                stage = SignStage.CONFIGURE
            }
        }
    }

    val openInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        error = null
        scope.launch {
            val ref = withContext(Dispatchers.IO) { SafIo.sourceRef(context, uri) }
            source = ref
            vault.autoLockSuppressed = true
            createOutput.launch("${ref.name}.sig")
        }
    }

    when (stage) {
        SignStage.CONFIGURE -> Column(
            modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Sign a file", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
            Text(
                "Produces a detached signature saved as its own small file next to the original. " +
                    "Send both; the file itself is not changed or encrypted.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (signingIdentities.isEmpty()) {
                Text(
                    "No signing keys in your vault yet. Add an SSH key, a hardware key, or a " +
                        "security key under Identities first.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            } else {
                Text("Sign with", style = MaterialTheme.typography.titleSmall)
                signingIdentities.forEach { identity ->
                    SigningKeyRow(
                        identity = identity,
                        selected = identity.id == selectedId,
                        onSelect = { selectedId = identity.id },
                    )
                    HorizontalDivider()
                }
            }

            if (needsPin) {
                OutlinedTextField(
                    value = skPin,
                    onValueChange = { skPin = it },
                    singleLine = true,
                    label = { Text("Security key PIN") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            if (error != null) {
                Text(error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }

            Button(
                onClick = {
                    error = null
                    vault.autoLockSuppressed = true
                    openInput.launch(arrayOf("*/*"))
                },
                enabled = selected != null,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Pick a file to sign…") }
            TextButton(onClick = onClose) { Text("Cancel") }
        }

        SignStage.WORKING -> Column(
            modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            Text(
                when (selected?.type) {
                    StoredIdentityType.SK_ED25519, StoredIdentityType.SK_ECDSA_P256 ->
                        "Hold your security key against the back of the phone…"
                    StoredIdentityType.HARDWARE_KEY -> "Signing in the device's secure hardware…"
                    else -> "Signing…"
                },
                modifier = Modifier.padding(top = 16.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SignStage.DONE -> Column(
            modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Signed ✓", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
            Text(
                doneSigName,
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                "Send the signature file along with the original. Signatures are scoped to " +
                    "AgePony's namespace; to check one on the command line:",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "ssh-keygen -Y verify -n ${SSHSig.NAMESPACE_AGEPONY} \\\n" +
                    "  -f allowed_signers -I signer-name \\\n" +
                    "  -s $doneSigName < original-file",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = {
                    source = null
                    doneSigName = ""
                    error = null
                    stage = SignStage.CONFIGURE
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Sign another") }
            OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Done") }
        }
    }
}

@Composable
private fun SigningKeyRow(identity: StoredIdentity, selected: Boolean, onSelect: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .selectable(selected = selected, onClick = onSelect)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onSelect)
        Column(Modifier.padding(start = 4.dp)) {
            Text(identity.name, style = MaterialTheme.typography.bodyLarge)
            Text(
                signingTypeLabel(identity.type),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private fun signingTypeLabel(type: StoredIdentityType): String = when (type) {
    StoredIdentityType.SSH_ED25519 -> "SSH Ed25519 · in-app key"
    StoredIdentityType.SSH_RSA -> "SSH RSA · in-app key"
    StoredIdentityType.HARDWARE_KEY -> "Hardware key · signs in the device keystore"
    StoredIdentityType.SK_ED25519 -> "Security key · Ed25519 over NFC"
    StoredIdentityType.SK_ECDSA_P256 -> "Security key · ECDSA P-256 over NFC"
    else -> ""
}
