package com.agepony.app.ui.files

import com.agepony.app.ui.UserMessage
import android.content.Context
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.agepony.app.R
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.Vault
import com.agepony.app.vault.toAgeIdentity
import com.agepony.core.Age
import com.agepony.core.Armor
import com.agepony.core.Stanza
import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.TagIdentity
import com.agepony.core.signing.SignatureStanza
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.InputStream
import androidx.activity.compose.BackHandler
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.DoneAction
import com.agepony.app.ui.components.OneLineValue
import com.agepony.app.ui.components.RowAction
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.PostQuantumBadge
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.theme.AgeStatus

//
// Header inspector: what is this .age file encrypted to?
//
// Reads the header and stops. The header is small and bounded, so this costs a few hundred bytes
// of reading no matter how large the file is, and it never decrypts anything: the stanza list is
// public information, which is exactly why it is safe to show and useful to look at.
//
// Deliberately read-only. It answers "can I open this, and what is it locked to", which is the
// question people actually have when a file will not decrypt.
//

private enum class InspectStage { PICK, WORKING, RESULT }

/** One recipient stanza, described in words rather than base64. */
private class StanzaInfo(
    val title: String,
    /** Prose about the stanza, or the label for [tag] when there is one. */
    val detail: String,
    val postQuantum: Boolean,
    /** Key material shown after [detail] in monospace; the prose stays in the UI font (5.1.0, U4). */
    val tag: String? = null,
)

private class InspectResult(
    val name: String,
    val size: Long,
    val armored: Boolean,
    val headerBytes: Int,
    val stanzas: List<StanzaInfo>,
    val opensWithVault: Boolean,
    val passphraseOnly: Boolean,
)

@Composable
fun InspectFlow(vault: Vault, modifier: Modifier = Modifier, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var stage by remember { mutableStateOf(InspectStage.PICK) }
    var error by remember { mutableStateOf<String?>(null) }
    var result by remember { mutableStateOf<InspectResult?>(null) }

    val openInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        error = null
        stage = InspectStage.WORKING
        val identities = vault.identities.mapNotNull { runCatching { it.toAgeIdentity() }.getOrNull() }
        scope.launch {
            try {
                result = withContext(Dispatchers.IO) { inspect(context, uri, identities) }
                stage = InspectStage.RESULT
            } catch (e: Exception) {
                error = UserMessage.text(context, e, R.string.files_not_age_file)
                stage = InspectStage.PICK
            }
        }
    }

    // Back is held while the header is read; the scope belongs to this screen.
    if (stage == InspectStage.WORKING) BackHandler {}

    AgeScreen(
        title = stringResource(R.string.files_inspect),
        modifier = modifier,
        onBack = if (stage == InspectStage.WORKING) null else onClose,
        actions = { if (stage == InspectStage.RESULT) DoneAction(onClose) },
    ) { padding ->
    Column(Modifier.fillMaxSize().padding(padding)) {
        when (stage) {
            InspectStage.PICK -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    stringResource(R.string.files_inspect_intro),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (error != null) ErrorText(error!!)
                Button(
                    onClick = { error = null; vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.files_pick_file)) }
                TextButton(onClick = onClose) { Text(stringResource(R.string.action_cancel)) }
            }

            InspectStage.WORKING -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                Text(
                    stringResource(R.string.files_reading_header),
                    modifier = Modifier.padding(top = 16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            InspectStage.RESULT -> {
                val r = result
                if (r == null) {
                    stage = InspectStage.PICK
                } else {
                    Column(
                        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        OneLineValue(r.name, color = MaterialTheme.colorScheme.onSurface)
                        Text(
                            when {
                                // 0 means the provider reported no size, so leave the size out.
                                r.size <= 0 && r.armored ->
                                    stringResource(R.string.files_inspect_summary_armored_no_size, r.headerBytes)
                                r.size <= 0 ->
                                    stringResource(R.string.files_inspect_summary_binary_no_size, r.headerBytes)
                                r.armored ->
                                    stringResource(R.string.files_inspect_summary_armored, SafIo.humanSize(LocalContext.current, r.size), r.headerBytes)
                                else ->
                                    stringResource(R.string.files_inspect_summary_binary, SafIo.humanSize(LocalContext.current, r.size), r.headerBytes)
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )

                        when {
                            r.opensWithVault -> VerdictPanel(
                                title = stringResource(R.string.files_inspect_can_decrypt),
                                detail = null,
                                color = AgeStatus.colors.success,
                                icon = Icons.Filled.CheckCircle,
                            )
                            r.passphraseOnly -> VerdictPanel(
                                title = stringResource(R.string.files_inspect_needs_passphrase),
                                detail = null,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                icon = Icons.Filled.Lock,
                            )
                            else -> VerdictPanel(
                                title = stringResource(R.string.files_inspect_cannot_open),
                                detail = null,
                                color = AgeStatus.colors.warning,
                                icon = Icons.Filled.Warning,
                            )
                        }

                        SectionHeader(
                            pluralStringResource(R.plurals.files_inspect_encrypted_to, r.stanzas.size, r.stanzas.size),
                        )
                        r.stanzas.forEachIndexed { index, s ->
                            Column(Modifier.fillMaxWidth()) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        stringResource(R.string.files_inspect_stanza_row, index + 1, s.title),
                                        style = MaterialTheme.typography.bodyLarge,
                                        modifier = Modifier.weight(1f, fill = false),
                                    )
                                    if (s.postQuantum) {
                                        PostQuantumBadge(Modifier.padding(start = 8.dp))
                                    }
                                }
                                if (s.tag != null) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            s.detail,
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.padding(end = 8.dp),
                                        )
                                        OneLineValue(s.tag)
                                    }
                                } else {
                                    Text(
                                        s.detail,
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                            ListDivider()
                        }

                        Text(
                            stringResource(R.string.files_inspect_footer),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )

                        // Done is in the app bar; the next file is its own row (5.1.0, U4).
                        ListDivider()
                        RowAction(
                            stringResource(R.string.files_inspect_another),
                            onClick = { result = null; error = null; stage = InspectStage.PICK },
                        )
                    }
                }
            }
        }
    }
    }
}

// ---- Work ----

private fun inspect(context: Context, uri: Uri, identities: List<AgeIdentity>): InspectResult {
    val ref = SafIo.sourceRef(context, uri)
    val (armored, rawInput) = FileEncryptor.sniffArmored(SafIo.openInput(context, uri))
    val parsed = rawInput.use { stream ->
        val binary: InputStream = if (armored) Armor.decodingSource(stream) else stream
        Age.parseHeaderStream(binary)
    }

    val stanzas = parsed.stanzas.map { describe(context, it) }
    // An identity that can unwrap any stanza can open the file. scrypt is excluded because it
    // needs the passphrase, which we are deliberately not asking for here.
    // Hardware tag identities are matched on their tag alone, so inspecting never asks the
    // secure hardware (or the user) for anything.
    val opens = identities.any { id ->
        parsed.stanzas.any { stanza ->
            if (id is TagIdentity) id.matches(stanza)
            else runCatching { id.unwrap(stanza) }.getOrNull() != null
        }
    }
    val passphraseOnly = parsed.stanzas.size == 1 && parsed.stanzas.first().type == "scrypt"

    return InspectResult(
        name = ref.name,
        size = ref.size,
        armored = armored,
        headerBytes = parsed.payloadStart,
        stanzas = stanzas,
        opensWithVault = opens,
        passphraseOnly = passphraseOnly,
    )
}

/** Turn a stanza into something a person can act on. */
private fun describe(context: Context, stanza: Stanza): StanzaInfo = when (stanza.type) {
    "scrypt" -> {
        val factor = stanza.args.getOrNull(1)?.toIntOrNull()
        StanzaInfo(
            title = context.getString(R.string.files_inspect_scrypt),
            detail = if (factor != null) {
                context.getString(
                    R.string.files_inspect_scrypt_detail,
                    factor,
                    FileEncryptor.scryptMemoryBytes(factor) shr 20,
                )
            } else {
                context.getString(R.string.files_inspect_scrypt_unreadable)
            },
            postQuantum = false,
        )
    }
    "X25519" -> StanzaInfo(
        title = context.getString(R.string.files_inspect_x25519),
        detail = context.getString(R.string.files_inspect_ephemeral_share),
        postQuantum = false,
        tag = shortArg(context, stanza.args.getOrNull(0)),
    )
    "mlkem768x25519" -> StanzaInfo(
        title = context.getString(R.string.files_inspect_mlkem),
        detail = context.getString(R.string.files_inspect_encapsulation),
        postQuantum = true,
        tag = shortArg(context, stanza.args.getOrNull(0)),
    )
    "ssh-ed25519" -> StanzaInfo(
        title = context.getString(R.string.files_inspect_ssh_ed25519),
        detail = context.getString(R.string.files_inspect_key_tag),
        postQuantum = false,
        tag = shortArg(context, stanza.args.getOrNull(0)),
    )
    "ssh-rsa" -> StanzaInfo(
        title = context.getString(R.string.files_inspect_ssh_rsa),
        detail = context.getString(R.string.files_inspect_key_tag),
        postQuantum = false,
        tag = shortArg(context, stanza.args.getOrNull(0)),
    )
    "p256tag" -> StanzaInfo(
        title = context.getString(R.string.files_inspect_p256tag),
        detail = context.getString(R.string.files_inspect_key_tag),
        postQuantum = false,
        tag = shortArg(context, stanza.args.getOrNull(0)),
    )
    "mlkem768p256tag" -> StanzaInfo(
        title = context.getString(R.string.files_inspect_mlkem_p256tag),
        detail = context.getString(R.string.files_inspect_key_tag),
        postQuantum = true,
        tag = shortArg(context, stanza.args.getOrNull(0)),
    )
    SignatureStanza.TYPE -> StanzaInfo(
        title = context.getString(R.string.files_inspect_signature),
        detail = context.getString(R.string.files_inspect_signature_detail),
        postQuantum = false,
    )
    "piv-p256" -> StanzaInfo(
        title = context.getString(R.string.files_inspect_piv),
        detail = context.getString(R.string.files_inspect_key_tag),
        postQuantum = false,
        tag = shortArg(context, stanza.args.getOrNull(0)),
    )
    else -> StanzaInfo(
        title = context.getString(R.string.files_inspect_unknown, stanza.type),
        detail = context.resources.getQuantityString(
            R.plurals.files_inspect_unknown_detail,
            stanza.args.size,
            stanza.args.size,
        ),
        postQuantum = false,
    )
}

private fun shortArg(context: Context, arg: String?): String {
    if (arg.isNullOrEmpty()) return context.getString(R.string.files_inspect_arg_none)
    return if (arg.length <= 20) arg else arg.take(10) + "…" + arg.takeLast(6)
}
