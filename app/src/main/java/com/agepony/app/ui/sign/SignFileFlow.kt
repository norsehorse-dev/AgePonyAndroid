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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.annotation.StringRes
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
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
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.Vault
import com.agepony.core.signing.SSHSig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.imePadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.RadioRow
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.theme.AgeStatus
import com.agepony.app.ui.theme.mono

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
                error = context.getString(R.string.sign_sk_pin_needed)
                stage = SignStage.CONFIGURE
            } catch (e: SecurityKeyService.WrongPinException) {
                error = context.getString(R.string.sign_sk_pin_wrong)
                stage = SignStage.CONFIGURE
            } catch (e: Exception) {
                error = e.message ?: context.getString(R.string.sign_failed)
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

    // A security key or hardware prompt is in flight while WORKING; back waits for it.
    if (stage == SignStage.WORKING) BackHandler {}

    AgeScreen(
        title = stringResource(R.string.files_sign),
        modifier = modifier,
        onBack = if (stage == SignStage.WORKING) null else onClose,
    ) { padding ->
    when (stage) {
        SignStage.CONFIGURE -> Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                stringResource(R.string.sign_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (signingIdentities.isEmpty()) {
                Text(
                    stringResource(R.string.sign_no_keys),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            } else {
                SectionHeader(stringResource(R.string.sign_with))
                signingIdentities.forEach { identity ->
                    RadioRow(
                        title = identity.name,
                        subtitle = signingTypeLabelRes(identity.type)?.let { stringResource(it) },
                        selected = identity.id == selectedId,
                        onClick = { selectedId = identity.id },
                    )
                    ListDivider()
                }
            }

            if (needsPin) {
                OutlinedTextField(
                    value = skPin,
                    onValueChange = { skPin = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.sign_sk_pin_label)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            if (error != null) ErrorText(error!!)

            Button(
                onClick = {
                    error = null
                    vault.autoLockSuppressed = true
                    openInput.launch(arrayOf("*/*"))
                },
                enabled = selected != null,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.sign_pick_file)) }
            TextButton(onClick = onClose) { Text(stringResource(R.string.action_cancel)) }
        }

        SignStage.WORKING -> Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            Text(
                when (selected?.type) {
                    StoredIdentityType.SK_ED25519, StoredIdentityType.SK_ECDSA_P256 ->
                        stringResource(R.string.sign_working_security_key)
                    StoredIdentityType.HARDWARE_KEY -> stringResource(R.string.sign_working_hardware)
                    else -> stringResource(R.string.sign_working)
                },
                modifier = Modifier.padding(top = 16.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SignStage.DONE -> Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            VerdictPanel(
                title = stringResource(R.string.sign_done_title),
                detail = null,
                color = AgeStatus.colors.success,
                icon = Icons.Filled.CheckCircle,
            )
            Text(
                doneSigName,
                style = MaterialTheme.typography.mono,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                stringResource(R.string.sign_done_body),
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
            ) { Text(stringResource(R.string.sign_another)) }
            OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.app_done)) }
        }
    }
    }
}

@StringRes
private fun signingTypeLabelRes(type: StoredIdentityType): Int? = when (type) {
    StoredIdentityType.SSH_ED25519 -> R.string.sign_type_ssh_ed25519
    StoredIdentityType.SSH_RSA -> R.string.sign_type_ssh_rsa
    StoredIdentityType.HARDWARE_KEY -> R.string.sign_type_hardware
    StoredIdentityType.SK_ED25519 -> R.string.sign_type_sk_ed25519
    StoredIdentityType.SK_ECDSA_P256 -> R.string.sign_type_sk_p256
    else -> null
}
