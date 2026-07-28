package com.agepony.app.ui.files

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
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
import com.agepony.app.vault.ScryptMemoryException
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.Vault
import com.agepony.app.vault.b64d
import com.agepony.core.archive.SignedBundle
import com.agepony.core.archive.TarArchive
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedOutputStream
import java.io.InputStream

//
// Encrypt flow. Android counterpart of iOS's EncryptFlow:
//   pick inputs (SAF) -> choose one archive or one file each -> configure -> pick destination
//   -> stream -> done.
//
// Nothing is held in memory. The destination is chosen *before* the work starts, because
// streaming needs somewhere to write as it goes; the old order (encrypt into a ByteArray, then
// ask where to save) is what made a 130 MB file impossible on a phone.
//
// Encrypt-and-sign: SSHSIG signs a hash, so a signed file is read twice, once to hash and once
// to encrypt, rather than being held. The signature and payload travel in a SignedBundle
// (sign-then-encrypt), so the signer stays hidden inside the ciphertext and the output is one file.
//

private enum class EncryptStage { PICK, MODE, CONFIGURE, PICKING, WORKING, DONE }

/** What a batch of files should turn into. Asked whenever more than one file is picked. */
private enum class OutputMode { BUNDLE, SEPARATE }

/** One line of the per-file results list. */
private class EncryptResult(val name: String, val ok: Boolean, val detail: String)

/** An in-app SSH ed25519 key, unpacked once so the work loop does not touch the vault. */
private class SignerKey(val seed: ByteArray, val publicKey: ByteArray)

@Composable
fun EncryptFlow(vault: Vault, modifier: Modifier = Modifier, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var stage by remember { mutableStateOf(EncryptStage.PICK) }
    var sources by remember { mutableStateOf<List<SourceRef>>(emptyList()) }
    var mode by remember { mutableStateOf(OutputMode.BUNDLE) }
    var recipients by remember { mutableStateOf<List<AgeRecipient>>(emptyList()) }
    var passphrase by remember { mutableStateOf<String?>(null) }
    var signerId by remember { mutableStateOf<String?>(null) }
    var armor by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }

    var phase by remember { mutableStateOf("Encrypting") }
    var bytesDone by remember { mutableStateOf(0L) }
    var bytesTotal by remember { mutableStateOf(0L) }
    var fileIndex by remember { mutableStateOf(0) }
    var results by remember { mutableStateOf<List<EncryptResult>>(emptyList()) }
    var savedName by remember { mutableStateOf<String?>(null) }

    val totalSize = sources.sumOf { it.size }
    val separate = sources.size > 1 && mode == OutputMode.SEPARATE

    fun signerKey(): SignerKey? {
        val id = signerId ?: return null
        val identity = vault.identities.firstOrNull { it.id == id } ?: return null
        return SignerKey(b64d(identity.privateKeyB64), b64d(identity.publicKeyB64))
    }

    val openInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris: List<Uri> ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        error = null
        scope.launch {
            try {
                val refs = withContext(Dispatchers.IO) { uris.map { SafIo.sourceRef(context, it) } }
                sources = refs
                stage = if (refs.size > 1) EncryptStage.MODE else EncryptStage.CONFIGURE
            } catch (e: Exception) {
                error = e.message ?: "Couldn't read the files."
            }
        }
    }

    // Single output: one file in, or several bundled into one archive.
    val createOutput = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(SafIo.MIME_OCTET)
    ) { uri: Uri? ->
        if (uri == null) {
            stage = EncryptStage.CONFIGURE
            return@rememberLauncherForActivityResult
        }
        val picked = sources
        val bundle = picked.size > 1
        val signer = signerKey()
        val recips = recipients
        val pass = passphrase
        val useArmor = armor
        val workFactor = vault.scryptWorkFactor
        error = null
        phase = if (signer != null) "Signing" else "Encrypting"
        bytesDone = 0L
        bytesTotal = if (signer != null) totalSize * 2 else totalSize
        fileIndex = 1
        stage = EncryptStage.WORKING
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    encryptToDocument(
                        context = context,
                        sources = picked,
                        dest = uri,
                        bundle = bundle,
                        recipients = recips,
                        passphrase = pass,
                        signer = signer,
                        armor = useArmor,
                        workFactor = workFactor,
                        onPhase = { phase = it },
                        onBytes = { delta -> bytesDone += delta },
                    )
                }
                savedName = withContext(Dispatchers.IO) { SafIo.queryNameSize(context, uri).first }
                stage = EncryptStage.DONE
            } catch (e: ScryptMemoryException) {
                error = e.message
                stage = EncryptStage.CONFIGURE
            } catch (e: OutOfMemoryError) {
                error = outOfMemoryMessage(!pass.isNullOrEmpty())
                stage = EncryptStage.CONFIGURE
            } catch (e: Exception) {
                error = e.message ?: "Encrypt failed."
                stage = EncryptStage.CONFIGURE
            }
        }
    }

    // One encrypted file per input, written into a folder the user grants.
    val pickFolder = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { tree: Uri? ->
        if (tree == null) {
            stage = EncryptStage.CONFIGURE
            return@rememberLauncherForActivityResult
        }
        val picked = sources
        val signer = signerKey()
        val recips = recipients
        val pass = passphrase
        val useArmor = armor
        val workFactor = vault.scryptWorkFactor
        error = null
        phase = if (signer != null) "Signing" else "Encrypting"
        bytesDone = 0L
        bytesTotal = if (signer != null) totalSize * 2 else totalSize
        fileIndex = 1
        results = emptyList()
        stage = EncryptStage.WORKING
        scope.launch {
            try {
                val collected = ArrayList<EncryptResult>()
                withContext(Dispatchers.IO) {
                    encryptToFolder(
                        context = context,
                        sources = picked,
                        tree = tree,
                        recipients = recips,
                        passphrase = pass,
                        signer = signer,
                        armor = useArmor,
                        workFactor = workFactor,
                        onPhase = { phase = it },
                        onFile = { index -> fileIndex = index },
                        onBytes = { delta -> bytesDone += delta },
                        onResult = { item ->
                            collected.add(item)
                            results = collected.toList()
                        },
                    )
                }
                stage = EncryptStage.DONE
            } catch (e: ScryptMemoryException) {
                error = e.message
                stage = EncryptStage.CONFIGURE
            } catch (e: OutOfMemoryError) {
                error = outOfMemoryMessage(!pass.isNullOrEmpty())
                stage = EncryptStage.CONFIGURE
            } catch (e: Exception) {
                error = e.message ?: "Encrypt failed."
                stage = EncryptStage.CONFIGURE
            }
        }
    }

    fun reset() {
        sources = emptyList(); mode = OutputMode.BUNDLE
        recipients = emptyList(); passphrase = null; signerId = null; armor = true
        error = null; results = emptyList(); savedName = null
        bytesDone = 0L; bytesTotal = 0L; fileIndex = 0
        stage = EncryptStage.PICK
    }

    Column(modifier.fillMaxSize()) {
        when (stage) {
            EncryptStage.PICK -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text("Encrypt a file", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    "Pick one or more files. With several, you choose whether they become one " +
                        "encrypted archive or one encrypted file each. Files are streamed, so size " +
                        "is not a limit.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (error != null) ErrorText(error!!)
                Button(
                    onClick = { vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Pick files…") }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            EncryptStage.MODE -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text("${sources.size} files", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    "How should they come out?",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                ModeRow(
                    selected = mode == OutputMode.BUNDLE,
                    title = "One encrypted archive",
                    detail = "All ${sources.size} files go into a single .tar.age. Decrypting gives " +
                        "back the archive, and any tar tool opens it.",
                    onClick = { mode = OutputMode.BUNDLE },
                )
                ModeRow(
                    selected = mode == OutputMode.SEPARATE,
                    title = "One encrypted file each",
                    detail = "${sources.size} separate .age files written into a folder you pick. " +
                        "Share or decrypt them independently.",
                    onClick = { mode = OutputMode.SEPARATE },
                )

                Button(onClick = { stage = EncryptStage.CONFIGURE }, modifier = Modifier.fillMaxWidth()) {
                    Text("Continue")
                }
                TextButton(onClick = { stage = EncryptStage.PICK }) { Text("Back") }
            }

            EncryptStage.CONFIGURE -> Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text("Encrypt a file", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)

                Text("Source", style = MaterialTheme.typography.titleSmall)
                Text(
                    when {
                        sources.size > 1 && separate -> "${sources.size} files → ${sources.size} .age files"
                        sources.size > 1 -> "${sources.size} files → one archive"
                        else -> sources.firstOrNull()?.name ?: "file"
                    },
                    style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
                Text(
                    SafIo.humanSize(totalSize),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) }) {
                        Text("Change files")
                    }
                    if (sources.size > 1) {
                        TextButton(onClick = { stage = EncryptStage.MODE }) { Text("Change output") }
                    }
                }

                HorizontalDivider()

                Text("Recipients", style = MaterialTheme.typography.titleSmall)
                Text(recipientSummary(recipients.size, passphrase), style = MaterialTheme.typography.bodyMedium)
                TextButton(onClick = { stage = EncryptStage.PICKING }) { Text("Choose recipients") }

                HorizontalDivider()

                // Optional signing — SSH Ed25519 identities sign in-process.
                val signingIdentities = vault.identities.filter { it.type == StoredIdentityType.SSH_ED25519 }
                if (signingIdentities.isNotEmpty()) {
                    Text("Sign (optional)", style = MaterialTheme.typography.titleSmall)
                    SignerRow(selected = signerId == null, label = "Don't sign", onClick = { signerId = null })
                    signingIdentities.forEach { id ->
                        SignerRow(selected = signerId == id.id, label = id.name, onClick = { signerId = id.id })
                    }
                    Text(
                        "Signs the file with your SSH Ed25519 key, then encrypts. The recipient can verify " +
                            "it came from you; the signer stays hidden inside the ciphertext. Signed files " +
                            "are read twice, so this takes a little longer.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    HorizontalDivider()
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = armor, onCheckedChange = { armor = it })
                    Text("Armor as text", modifier = Modifier.padding(start = 12.dp))
                }
                Text(
                    if (armor) "Output is text between BEGIN/END markers — safe to paste anywhere, and about a third larger."
                    else "Output is raw binary — smaller, but won't survive being pasted as text.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                if (error != null) ErrorText(error!!)

                val canEncrypt = sources.isNotEmpty() &&
                    (recipients.isNotEmpty() || !passphrase.isNullOrEmpty())
                Button(
                    onClick = {
                        vault.autoLockSuppressed = true
                        error = null
                        if (separate) {
                            pickFolder.launch(null)
                        } else {
                            val base = if (sources.size > 1) "bundle.tar" else (sources.firstOrNull()?.name ?: "file")
                            createOutput.launch(FileEncryptor.encryptedName(base))
                        }
                    },
                    enabled = canEncrypt,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        when {
                            separate -> "Choose folder & encrypt"
                            signerId != null -> "Sign & encrypt"
                            else -> "Choose destination & encrypt"
                        }
                    )
                }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            EncryptStage.PICKING -> RecipientPicker(
                vault = vault,
                onCancel = { stage = EncryptStage.CONFIGURE },
                onConfirm = { r, p ->
                    recipients = r
                    passphrase = p
                    stage = EncryptStage.CONFIGURE
                },
            )

            EncryptStage.WORKING -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                if (bytesTotal > 0) {
                    LinearProgressIndicator(
                        progress = { (bytesDone.toFloat() / bytesTotal.toFloat()).coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth(),
                        color = MaterialTheme.colorScheme.primary,
                    )
                } else {
                    CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                }
                Text(
                    if (sources.size > 1 && separate) "$phase ${fileIndex} of ${sources.size}…" else "$phase…",
                    modifier = Modifier.padding(top = 16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (bytesTotal > 0) {
                    Text(
                        "${SafIo.humanSize(bytesDone)} of ${SafIo.humanSize(bytesTotal)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            EncryptStage.DONE -> Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                if (results.isEmpty()) {
                    Text("Encrypted ✓", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                    Text(
                        savedName ?: "done",
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                } else {
                    val okCount = results.count { it.ok }
                    Text("Encrypted ✓", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                    Text(
                        "$okCount of ${results.size} files encrypted.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    HorizontalDivider()
                    results.forEach { item ->
                        Column(Modifier.fillMaxWidth()) {
                            Text(
                                (if (item.ok) "✓ " else "⚠ ") + item.name,
                                style = MaterialTheme.typography.bodyMedium,
                                color = if (item.ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                                fontFamily = FontFamily.Monospace,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                item.detail,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        HorizontalDivider()
                    }
                }
                Button(onClick = { reset() }, modifier = Modifier.fillMaxWidth()) { Text("Encrypt more") }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Done") }
            }
        }
    }
}

// ---- Work ----

/**
 * Everything that ends up as a single output document: one file, or several bundled into one
 * archive. Input streams and the output stream are the only buffers involved.
 */
private fun encryptToDocument(
    context: Context,
    sources: List<SourceRef>,
    dest: Uri,
    bundle: Boolean,
    recipients: List<AgeRecipient>,
    passphrase: String?,
    signer: SignerKey?,
    armor: Boolean,
    workFactor: Int,
    onPhase: (String) -> Unit,
    onBytes: (Long) -> Unit,
) {
    // A tar header carries each entry's size ahead of its bytes, and a signature covers a payload
    // of declared length, so those paths need exact sizes; a plain single-file encrypt does not.
    if (sources.isEmpty()) throw IllegalStateException("No files chosen.")
    val needSizes = bundle || signer != null
    val prepared = sources.map { SafIo.prepare(context, it, needSizes) }
    try {
        val entries = if (bundle) {
            val used = HashSet<String>()
            prepared.map { p ->
                TarArchive.StreamEntry(SafIo.uniqueName(p.name, used), p.size) {
                    CountingInputStream(p.open(), onBytes)
                }
            }
        } else {
            emptyList()
        }

        val payloadName = if (bundle) "bundle.tar" else prepared.first().name
        val payloadSize = if (bundle) TarArchive.sizeOf(entries) else prepared.first().size
        fun openPayload(counting: Boolean): InputStream = when {
            bundle -> TarArchive.source(entries)
            counting -> CountingInputStream(prepared.first().open(), onBytes)
            else -> prepared.first().open()
        }

        val plaintext: InputStream = if (signer == null) {
            openPayload(counting = true)
        } else {
            onPhase("Signing")
            val hash = openPayload(counting = true).use { SSHSig.hashStream(it) }
            val signature = SSHSigner.signEd25519Hashed(
                signer.seed, signer.publicKey, hash, SSHSig.NAMESPACE_AGEPONY,
            )
            SignedBundle.bundleSource(payloadName, payloadSize, openPayload(counting = true), signature)
        }

        onPhase("Encrypting")
        plaintext.use { input ->
            BufferedOutputStream(SafIo.openOutput(context, dest)).use { out ->
                FileEncryptor.encryptStream(input, recipients, passphrase, armor, out, workFactor)
                out.flush()
            }
        }
    } finally {
        prepared.forEach { it.cleanup() }
    }
}

/** One encrypted file per input, written into [tree]. One failure does not stop the batch. */
private fun encryptToFolder(
    context: Context,
    sources: List<SourceRef>,
    tree: Uri,
    recipients: List<AgeRecipient>,
    passphrase: String?,
    signer: SignerKey?,
    armor: Boolean,
    workFactor: Int,
    onPhase: (String) -> Unit,
    onFile: (Int) -> Unit,
    onBytes: (Long) -> Unit,
    onResult: (EncryptResult) -> Unit,
) {
    val used = HashSet<String>()
    sources.forEachIndexed { index, ref ->
        onFile(index + 1)
        val outName = SafIo.uniqueName(FileEncryptor.encryptedName(ref.name), used)
        try {
            val destination = SafIo.createInTree(context, tree, outName)
            encryptToDocument(
                context = context,
                sources = listOf(ref),
                dest = destination,
                bundle = false,
                recipients = recipients,
                passphrase = passphrase,
                signer = signer,
                armor = armor,
                workFactor = workFactor,
                onPhase = onPhase,
                onBytes = onBytes,
            )
            onResult(EncryptResult(outName, true, if (signer != null) "Signed and encrypted." else "Encrypted."))
        } catch (e: ScryptMemoryException) {
            throw e // the same for every file in the batch; report it once, not N times
        } catch (e: OutOfMemoryError) {
            throw e // a memory failure is not per-file; let the caller report it once
        } catch (e: Exception) {
            onResult(EncryptResult(ref.name, false, e.message ?: "Encrypt failed."))
        }
    }
}

/**
 * Say which allocation actually failed. Passphrase mode allocates 128 * 2^18 * 8 bytes (256 MiB)
 * inside scrypt no matter how small the file is, so "try a smaller file" is the wrong advice —
 * that was the bug in the 3.0.2 message.
 */
private fun outOfMemoryMessage(usingPassphrase: Boolean): String =
    if (usingPassphrase) {
        "Not enough memory for the passphrase key derivation on this device. scrypt needs about " +
            "256 MB while it runs, whatever the file size, so a smaller file will not help. " +
            "Encrypting to a recipient key instead needs almost none."
    } else {
        "Not enough memory to finish this encrypt. Files are streamed, so this is unusual — " +
            "closing other apps and trying again should clear it."
    }

// ---- Small pieces ----

@Composable
private fun ModeRow(selected: Boolean, title: String, detail: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Column(Modifier.padding(start = 8.dp, top = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SignerRow(selected: Boolean, label: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(label, modifier = Modifier.padding(start = 8.dp), style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ErrorText(message: String) {
    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
}

private fun recipientSummary(count: Int, passphrase: String?): String = when {
    !passphrase.isNullOrEmpty() -> "Passphrase only (scrypt)"
    count == 0 -> "None chosen yet"
    count == 1 -> "1 recipient"
    else -> "$count recipients"
}
