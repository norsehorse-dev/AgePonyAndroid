package com.agepony.app.ui.files

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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.Vault
import com.agepony.app.vault.toAgeIdentity
import com.agepony.core.Age
import com.agepony.core.Armor
import com.agepony.core.Stanza
import com.agepony.core.recipients.AgeIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.InputStream

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
    val detail: String,
    val postQuantum: Boolean,
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
                error = e.message ?: "That doesn't look like an age file."
                stage = InspectStage.PICK
            }
        }
    }

    Column(modifier.fillMaxSize()) {
        when (stage) {
            InspectStage.PICK -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text("Inspect a file", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    "Shows what an age file is encrypted to, without decrypting it. Only the header " +
                        "is read, so this is instant even for very large files, and it reveals nothing " +
                        "that is not already public in the file.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (error != null) {
                    Text(error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Button(
                    onClick = { error = null; vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Pick a file…") }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            InspectStage.WORKING -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                Text(
                    "Reading the header…",
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
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Text(
                            r.name,
                            style = MaterialTheme.typography.titleLarge,
                            color = MaterialTheme.colorScheme.primary,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            "${SafIo.humanSize(r.size)}  •  ${if (r.armored) "armored text" else "binary"}" +
                                "  •  ${r.headerBytes} byte header",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )

                        HorizontalDivider()

                        Text(
                            when {
                                r.opensWithVault -> "You can decrypt this ✓"
                                r.passphraseOnly -> "Needs the passphrase it was encrypted with"
                                else -> "⚠ No identity in your vault can open this"
                            },
                            style = MaterialTheme.typography.bodyLarge,
                            color = if (r.opensWithVault) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                        )

                        HorizontalDivider()

                        Text(
                            if (r.stanzas.size == 1) "Encrypted to 1 recipient"
                            else "Encrypted to ${r.stanzas.size} recipients",
                            style = MaterialTheme.typography.titleSmall,
                        )
                        r.stanzas.forEachIndexed { index, s ->
                            Column(Modifier.fillMaxWidth()) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        "${index + 1}. ${s.title}",
                                        style = MaterialTheme.typography.bodyMedium,
                                        modifier = Modifier.weight(1f, fill = false),
                                    )
                                    if (s.postQuantum) {
                                        Text(
                                            "  quantum-safe",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.primary,
                                        )
                                    }
                                }
                                Text(
                                    s.detail,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    fontFamily = FontFamily.Monospace,
                                )
                            }
                            HorizontalDivider()
                        }

                        Text(
                            "Recipient stanzas are not secret: anyone holding the file can read them. " +
                                "They say which keys can open it, not what is inside.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )

                        Button(
                            onClick = { result = null; error = null; stage = InspectStage.PICK },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Inspect another") }
                        OutlinedButton(
                            onClick = onClose,
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        ) { Text("Done") }
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

    val stanzas = parsed.stanzas.map { describe(it) }
    // An identity that can unwrap any stanza can open the file. scrypt is excluded because it
    // needs the passphrase, which we are deliberately not asking for here.
    val opens = identities.any { id -> parsed.stanzas.any { runCatching { id.unwrap(it) }.getOrNull() != null } }
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
private fun describe(stanza: Stanza): StanzaInfo = when (stanza.type) {
    "scrypt" -> {
        val factor = stanza.args.getOrNull(1)?.toIntOrNull()
        StanzaInfo(
            title = "Passphrase (scrypt)",
            detail = if (factor != null) {
                "Work factor 2^$factor, about ${FileEncryptor.scryptMemoryBytes(factor) shr 20} MB " +
                    "of memory to derive the key"
            } else {
                "Work factor not readable"
            },
            postQuantum = false,
        )
    }
    "X25519" -> StanzaInfo(
        title = "age recipient (X25519)",
        detail = "ephemeral share " + shortArg(stanza.args.getOrNull(0)),
        postQuantum = false,
    )
    "mlkem768x25519" -> StanzaInfo(
        title = "Post-quantum age recipient (ML-KEM-768 with X25519)",
        detail = "encapsulation " + shortArg(stanza.args.getOrNull(0)),
        postQuantum = true,
    )
    "ssh-ed25519" -> StanzaInfo(
        title = "SSH Ed25519 recipient",
        detail = "key tag " + shortArg(stanza.args.getOrNull(0)),
        postQuantum = false,
    )
    "ssh-rsa" -> StanzaInfo(
        title = "SSH RSA recipient",
        detail = "key tag " + shortArg(stanza.args.getOrNull(0)),
        postQuantum = false,
    )
    else -> StanzaInfo(
        title = "Unrecognised stanza: ${stanza.type}",
        detail = "Written by a newer or different age implementation. " +
            stanza.args.size.toString() + " argument(s)",
        postQuantum = false,
    )
}

private fun shortArg(arg: String?): String {
    if (arg.isNullOrEmpty()) return "(none)"
    return if (arg.length <= 20) arg else arg.take(10) + "…" + arg.takeLast(6)
}
