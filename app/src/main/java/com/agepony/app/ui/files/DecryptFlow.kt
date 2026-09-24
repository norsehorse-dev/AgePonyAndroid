package com.agepony.app.ui.files

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import com.agepony.app.ui.util.rememberHaptics
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.signing.FileVerifier
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredSigner
import com.agepony.app.vault.Vault
import com.agepony.app.vault.WrongPassphraseException
import com.agepony.app.vault.toAgeIdentity
import com.agepony.core.Age
import com.agepony.core.archive.SignedBundle
import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.ScryptIdentity
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SignatureStanza
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedOutputStream
import java.io.InputStream

//
// Decrypt flow. Android counterpart of iOS's DecryptFlow:
//   pick .age (SAF) -> work out how it is locked -> pick destination -> stream -> done.
//
// The file is never held in memory. Which key opens it is decided from the header alone, which
// is small and bounded, so a wrong passphrase costs a few hundred bytes of reading rather than a
// whole decrypt. Only once a key is known does the flow ask where to save, because streaming
// needs somewhere to write as it goes.
//
// Armor is auto-detected from the first bytes. After decryption the plaintext is probed for an
// AgePony signed bundle (encrypt-and-sign): the wrapper is stripped as it streams and the
// embedded SSHSIG is checked against the vault. The signature sits after the payload in the
// bundle, so a bad signature is reported once the file is already written; the verdict says so
// plainly rather than pretending the file was verified before saving. A signature-stanza file is
// decrypted in memory, so its signature is checked before anything is written (audit L-9).
//
// A decrypt that fails after the destination document exists deletes it, so no partial or
// truncated plaintext is left behind (audit L-18). A bundle whose signature failed is not
// offered for extraction.
//

private enum class DecryptStage { PICK, PROBING, NEED_PASSPHRASE, WORKING, DONE }

@Composable
fun DecryptFlow(
    vault: Vault,
    modifier: Modifier = Modifier,
    initialUri: Uri? = null,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var stage by remember { mutableStateOf(DecryptStage.PICK) }
    var source by remember { mutableStateOf<SourceRef?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var usePassphrase by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var savedName by remember { mutableStateOf<String?>(null) }
    var originalName by remember { mutableStateOf<String?>(null) }
    var verdict by remember { mutableStateOf<String?>(null) }
    var bytesDone by remember { mutableStateOf(0L) }
    var isBundle by remember { mutableStateOf(false) }
    var savedDest by remember { mutableStateOf<Uri?>(null) }
    var extracting by remember { mutableStateOf(false) }
    var extractResult by remember { mutableStateOf<String?>(null) }
    var signatureFailed by remember { mutableStateOf(false) }
    var nameCovered by remember { mutableStateOf(true) }
    var signatureNote by remember { mutableStateOf<String?>(null) }

    val sourceName = source?.name ?: "file.age"

    val createOutput = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(SafIo.MIME_OCTET)
    ) { dest: Uri? ->
        val ref = source
        if (dest == null || ref == null) {
            stage = if (usePassphrase) DecryptStage.NEED_PASSPHRASE else DecryptStage.PICK
            return@rememberLauncherForActivityResult
        }
        val pass = if (usePassphrase) passphrase else null
        val identities = vault.identities.mapNotNull { runCatching { it.toAgeIdentity() }.getOrNull() }
        val known = vault.identities.toList()
        val signers = vault.signers.toList()
        error = null
        bytesDone = 0L
        stage = DecryptStage.WORKING
        scope.launch {
            try {
                val outcome = withContext(Dispatchers.IO) {
                    decryptToDocument(
                        context = context,
                        source = ref,
                        dest = dest,
                        identities = identities,
                        passphrase = pass,
                        known = known,
                        signers = signers,
                        onBytes = { delta -> bytesDone += delta },
                    )
                }
                originalName = outcome.originalName
                verdict = outcome.verdict
                signatureFailed = outcome.signatureFailed
                nameCovered = outcome.nameCovered
                signatureNote = outcome.note
                savedName = withContext(Dispatchers.IO) { SafIo.queryNameSize(context, dest).first }
                savedDest = dest
                isBundle = withContext(Dispatchers.IO) { peekIsBundle(context, dest) }
                stage = DecryptStage.DONE
            } catch (e: WrongPassphraseException) {
                error = e.message
                stage = DecryptStage.NEED_PASSPHRASE
            } catch (e: OutOfMemoryError) {
                error = decryptOutOfMemoryMessage(pass != null)
                stage = if (usePassphrase) DecryptStage.NEED_PASSPHRASE else DecryptStage.PICK
            } catch (e: Exception) {
                error = e.message ?: "Decrypt failed."
                stage = if (usePassphrase) DecryptStage.NEED_PASSPHRASE else DecryptStage.PICK
            }
        }
    }

    // Shared in from another app, or picked here: probe the header, then save or ask for a passphrase.
    fun beginDecrypt(uri: Uri) {
        error = null
        passphrase = ""
        usePassphrase = false
        verdict = null
        savedName = null
        originalName = null
        signatureFailed = false
        nameCovered = true
        signatureNote = null
        stage = DecryptStage.PROBING
        scope.launch {
            try {
                val ref = withContext(Dispatchers.IO) { SafIo.sourceRef(context, uri) }
                source = ref
                val identities = vault.identities.mapNotNull { runCatching { it.toAgeIdentity() }.getOrNull() }
                val opens = identities.isNotEmpty() && withContext(Dispatchers.IO) {
                    headerOpensWith(context, ref, identities)
                }
                if (opens) {
                    vault.autoLockSuppressed = true
                    createOutput.launch(FileEncryptor.decryptedName(ref.name))
                } else {
                    usePassphrase = true
                    stage = DecryptStage.NEED_PASSPHRASE
                }
            } catch (e: Exception) {
                error = e.message ?: "This doesn't look like an age file."
                stage = DecryptStage.PICK
            }
        }
    }

    val openInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) beginDecrypt(uri)
    }

    // Once only: survives rotation, so a recreated screen doesn't reopen the save picker.
    var initialConsumed by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(initialUri) {
        if (!initialConsumed && initialUri != null) { initialConsumed = true; beginDecrypt(initialUri) }
    }

    val pickExtractTree = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { tree: Uri? ->
        val src = savedDest
        if (tree == null || src == null) return@rememberLauncherForActivityResult
        // The button is hidden when the signature failed; refuse here too.
        if (signatureFailed) return@rememberLauncherForActivityResult
        extracting = true
        extractResult = null
        scope.launch {
            try {
                val msg = withContext(Dispatchers.IO) { extractBundleToTree(context, src, tree) }
                extractResult = msg
            } catch (e: Exception) {
                extractResult = "Extract failed: ${e.message}"
            } finally {
                extracting = false
            }
        }
    }

    fun reset() {
        source = null; passphrase = ""; usePassphrase = false
        error = null; savedName = null; originalName = null; verdict = null
        signatureFailed = false; nameCovered = true; signatureNote = null
        bytesDone = 0L
        isBundle = false; savedDest = null; extracting = false; extractResult = null
        stage = DecryptStage.PICK
    }

    val haptics = rememberHaptics()
    LaunchedEffect(stage) { if (stage == DecryptStage.DONE) haptics.success() }

    Column(modifier.fillMaxSize()) {
        when (stage) {
            DecryptStage.PICK -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text("Decrypt a file", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    "Pick an age file (.age, binary or armored). AgePony tries your identities first, " +
                        "then offers a passphrase if the file needs one. Files are streamed, so size " +
                        "is not a limit.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (error != null) ErrorLine(error!!)
                Button(
                    onClick = { error = null; vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Pick a file…") }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            DecryptStage.PROBING -> Column(
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

            DecryptStage.NEED_PASSPHRASE -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text("Passphrase", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    sourceName,
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    "No matching identity in your vault. If this file was encrypted with a passphrase, enter it.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it; error = null },
                    label = { Text("Passphrase") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (error != null) ErrorLine(error!!)
                Button(
                    onClick = {
                        val ref = source ?: return@Button
                        if (passphrase.isEmpty()) { error = "Enter the passphrase."; return@Button }
                        val entered = passphrase
                        error = null
                        stage = DecryptStage.PROBING
                        scope.launch {
                            try {
                                // The scrypt stanza lives in the header, so a wrong passphrase is
                                // caught here, before the user is asked where to save anything.
                                val opens = withContext(Dispatchers.IO) {
                                    headerOpensWith(context, ref, listOf(ScryptIdentity(entered)))
                                }
                                if (!opens) {
                                    error = "Wrong passphrase, or this file isn't passphrase-encrypted."
                                    stage = DecryptStage.NEED_PASSPHRASE
                                } else {
                                    vault.autoLockSuppressed = true
                                    createOutput.launch(FileEncryptor.decryptedName(ref.name))
                                }
                            } catch (e: OutOfMemoryError) {
                                error = decryptOutOfMemoryMessage(true)
                                stage = DecryptStage.NEED_PASSPHRASE
                            } catch (e: Exception) {
                                error = e.message ?: "Decrypt failed."
                                stage = DecryptStage.NEED_PASSPHRASE
                            }
                        }
                    },
                    enabled = passphrase.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Decrypt") }
                TextButton(onClick = onClose) { Text("Cancel") }
            }

            DecryptStage.WORKING -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                val total = source?.size ?: 0L
                if (total > 0) {
                    LinearProgressIndicator(
                        progress = { (bytesDone.toFloat() / total.toFloat()).coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth(),
                        color = MaterialTheme.colorScheme.primary,
                    )
                } else {
                    CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                }
                Text(
                    "Decrypting…",
                    modifier = Modifier.padding(top = 16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (total > 0) {
                    Text(
                        "${SafIo.humanSize(bytesDone)} of ${SafIo.humanSize(total)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            DecryptStage.DONE -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text("Decrypted ✓", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                Text(
                    savedName ?: FileEncryptor.decryptedName(sourceName),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp, bottom = 8.dp),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val original = originalName
                if (original != null && (original != savedName || !nameCovered)) {
                    Text(
                        if (nameCovered) {
                            "Original name inside the signed file: $original"
                        } else {
                            "Name inside the file (not covered by the signature): $original"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                }
                if (verdict != null) {
                    Text(
                        verdict!!,
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (verdict!!.startsWith("⚠")) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(bottom = if (signatureNote != null) 4.dp else 16.dp),
                    )
                }
                signatureNote?.let { note ->
                    Text(
                        note,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 16.dp),
                    )
                }
                if (isBundle && signatureFailed) {
                    Text(
                        "This is a bundle of files, but its signature check failed, so AgePony won't " +
                            "extract it. Only open the saved file if you trust where it came from.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                } else if (isBundle) {
                    Text(
                        "This is a bundle of files. You can extract them into a folder.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                    OutlinedButton(
                        onClick = { vault.autoLockSuppressed = true; pickExtractTree.launch(null) },
                        enabled = !extracting,
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    ) { Text(if (extracting) "Extracting\u2026" else "Extract files into a folder\u2026") }
                    val msg = extractResult
                    if (msg != null) {
                        Text(
                            msg,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                    }
                }
                Button(onClick = { reset() }, modifier = Modifier.fillMaxWidth()) { Text("Decrypt another") }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Done") }
            }
        }
    }
}

// ---- Work ----

private class DecryptOutcome(
    val originalName: String?,
    val verdict: String?,
    /** A signature was present and failed (invalid or unreadable). Blocks bundle extraction. */
    val signatureFailed: Boolean = false,
    /** False for a v1 signed bundle, whose name the signature does not cover (audit L-8). */
    val nameCovered: Boolean = true,
    /** What an older (v1) signature does not cover, shown under the verdict. */
    val note: String? = null,
)

private const val V1_STANZA_NOTE =
    "Older signature format (v1): it covers the contents but not who the file was encrypted to."
private const val V1_BUNDLE_NOTE =
    "Older signature format (v1): it covers the contents but not the file name."

/**
 * Can any of [identities] unwrap this file? Reads the age header and stops there, so this costs
 * a few hundred bytes rather than a decrypt, and it is safe to call before a destination exists.
 */
private fun headerOpensWith(
    context: android.content.Context,
    source: SourceRef,
    identities: List<AgeIdentity>,
): Boolean {
    val (armored, input) = FileEncryptor.sniffArmored(SafIo.openInput(context, source.uri))
    return input.use { stream ->
        val binary: InputStream = if (armored) com.agepony.core.Armor.decodingSource(stream) else stream
        Age.canDecryptStream(FileEncryptor.guardedPassphraseSource(binary), identities)
    }
}

/** Does this file carry an agepony.com/sig stanza in its header? Reads the header only. */
private fun headerHasSignatureStanza(context: android.content.Context, source: SourceRef): Boolean =
    try {
        val (armored, input) = FileEncryptor.sniffArmored(SafIo.openInput(context, source.uri))
        input.use { stream ->
            val binary: InputStream =
                if (armored) com.agepony.core.Armor.decodingSource(stream) else stream
            FileEncryptor.headerHasSignatureStanza(binary)
        }
    } catch (_: Exception) {
        false
    }

private fun verdictFor(result: FileVerifier.Result): String = when (result.trust) {
    FileVerifier.Trust.TRUSTED -> "Signed by ${result.signerName ?: "a known key"} ✓"
    FileVerifier.Trust.VALID_UNKNOWN -> {
        val listed = result.untrustedSignerName
        if (listed != null) {
            "⚠ Valid signature from \"$listed\", but not trusted: ${result.untrustedReason ?: "its trusted-signer entry does not allow it"}"
        } else {
            "Valid signature (signer not in your vault)"
        }
    }
    FileVerifier.Trust.INVALID -> "⚠ Signature invalid: ${result.reason ?: "verification failed"}"
}

/**
 * The verdict for a signature-stanza file, checked against the in-memory plaintext before any of
 * it is written. A stanza that is present but can't be read is a failed signature, never
 * "unsigned" (audit L-9). The namespace and signed message come from the stanza's version.
 */
private fun stanzaOutcome(
    recovered: Age.DecryptedWithSignature,
    known: List<StoredIdentity>,
    signers: List<StoredSigner>,
): DecryptOutcome = when (val opening = recovered.signature) {
    is SignatureStanza.Opening.Absent -> DecryptOutcome(null, null)
    is SignatureStanza.Opening.Unreadable ->
        DecryptOutcome(null, "⚠ Signature present but unreadable: ${opening.reason}", signatureFailed = true)
    is SignatureStanza.Opening.Opened -> {
        val plaintext = recovered.plaintext
        val result = FileVerifier().verifyHashed(
            opening.signatureArmored.toByteArray(Charsets.UTF_8),
            known,
            signers,
            opening.namespace,
        ) { alg -> opening.messageHash(alg) { hashAlg -> SSHSig.hashMessage(plaintext, hashAlg) } }
        DecryptOutcome(
            originalName = null,
            verdict = verdictFor(result),
            signatureFailed = result.trust == FileVerifier.Trust.INVALID,
            note = if (opening.coversRecipients) null else V1_STANZA_NOTE,
        )
    }
}

/**
 * Stream the whole file: ciphertext in from the provider, plaintext out to the provider, with a
 * signed-bundle wrapper stripped on the way past if there is one.
 */
private fun decryptToDocument(
    context: android.content.Context,
    source: SourceRef,
    dest: Uri,
    identities: List<AgeIdentity>,
    passphrase: String?,
    known: List<StoredIdentity>,
    signers: List<StoredSigner>,
    onBytes: (Long) -> Unit,
): DecryptOutcome = try {
    writeDecrypted(context, source, dest, identities, passphrase, known, signers, onBytes)
} catch (t: Throwable) {
    // The picker already created [dest]; don't leave a partial or empty plaintext file there.
    SafIo.discard(context, dest)
    throw t
}

private fun writeDecrypted(
    context: android.content.Context,
    source: SourceRef,
    dest: Uri,
    identities: List<AgeIdentity>,
    passphrase: String?,
    known: List<StoredIdentity>,
    signers: List<StoredSigner>,
    onBytes: (Long) -> Unit,
): DecryptOutcome {
    // New-format signed files (agepony.com/sig) hold the signature in the header over a bare
    // payload, so plain age reads them. Decrypt buffered and verify against the recovered
    // plaintext; old SignedBundle files and unsigned files take the streaming path below.
    if (passphrase == null && headerHasSignatureStanza(context, source)) {
        val rawBytes = CountingInputStream(SafIo.openInput(context, source.uri), onBytes)
            .use { it.readBytes() }
        val recovered = FileEncryptor.decryptSignedBytes(FileEncryptor.toBinary(rawBytes), identities)
        // Everything is in memory, so the verdict is settled before a byte is written.
        val outcome = stanzaOutcome(recovered, known, signers)
        BufferedOutputStream(SafIo.openOutput(context, dest)).use { out ->
            out.write(recovered.plaintext)
            out.flush()
        }
        return outcome
    }

    val (armored, rawInput) = FileEncryptor.sniffArmored(SafIo.openInput(context, source.uri))
    var parsed: SignedBundle.StreamParsed? = null

    CountingInputStream(rawInput, onBytes).use { input ->
        BufferedOutputStream(SafIo.openOutput(context, dest)).use { fileOut ->
            val sink = SignedBundle.UnwrappingSink(fileOut)
            if (passphrase != null) {
                FileEncryptor.decryptStreamWithPassphrase(input, armored, passphrase, sink)
            } else {
                FileEncryptor.decryptStreamWithIdentities(input, armored, identities, sink)
            }
            sink.finish()
            parsed = sink.result()
            fileOut.flush()
        }
    }

    val bundle = parsed ?: return DecryptOutcome(null, null)
    // Verify under the namespace and message the bundle's version defines (v1: "agepony" over
    // the payload; v2: its own namespace over manifest and payload hash).
    val result = FileVerifier().verifyHashed(
        bundle.signatureArmored.toByteArray(Charsets.UTF_8),
        known,
        signers,
        bundle.namespace,
    ) { alg -> bundle.messageHash(alg) }
    val failed = result.trust == FileVerifier.Trust.INVALID
    val verdict = verdictFor(result) +
        if (failed) ". The file was saved before the signature could be checked: treat its contents as untrusted." else ""
    return DecryptOutcome(
        originalName = bundle.name,
        verdict = verdict,
        signatureFailed = failed,
        nameCovered = bundle.nameCovered,
        note = if (bundle.nameCovered) null else V1_BUNDLE_NOTE,
    )
}

private fun peekIsBundle(context: android.content.Context, uri: Uri): Boolean =
    try {
        SafIo.openInput(context, uri).use { input ->
            val block = ByteArray(com.agepony.core.archive.TarArchive.BLOCK_SIZE)
            var read = 0
            while (read < block.size) {
                val r = input.read(block, read, block.size - read)
                if (r < 0) break
                read += r
            }
            read >= block.size && com.agepony.core.archive.TarArchive.looksLikeTar(block)
        }
    } catch (_: Exception) {
        false
    }

/**
 * Extract a decrypted tar bundle into a folder the user granted. Entry names are
 * sanitised to their final path component so a crafted bundle cannot write outside
 * the chosen folder, and collisions are de-duplicated.
 */
private fun extractBundleToTree(context: android.content.Context, src: Uri, tree: Uri): String {
    val used = mutableSetOf<String>()
    var count = 0
    java.io.BufferedInputStream(SafIo.openInput(context, src)).use { input ->
        com.agepony.core.archive.TarArchive.forEachEntry(input) { name, _, data ->
            val unique = SafIo.uniqueName(sanitizeEntryName(name), used)
            val out = SafIo.createInTree(context, tree, unique)
            try {
                SafIo.openOutput(context, out).use { o -> data.copyTo(o, 64 * 1024) }
            } catch (t: Throwable) {
                SafIo.discard(context, out) // no truncated entry left in the folder (audit L-18)
                throw t
            }
            count++
        }
    }
    if (count == 0) throw IllegalStateException("No files found in the bundle.")
    return "Extracted $count file${if (count == 1) "" else "s"} to the folder."
}

private fun sanitizeEntryName(name: String): String {
    val base = name.substringAfterLast('/').substringAfterLast('\\').trim()
    return if (base.isEmpty() || base == "." || base == "..") "file" else base
}

/**
 * Decrypting streams, so a memory failure here is almost always scrypt: the work factor is
 * chosen by whoever encrypted the file, and a hostile one can demand gigabytes.
 */
private fun decryptOutOfMemoryMessage(usingPassphrase: Boolean): String =
    if (usingPassphrase) {
        "Not enough memory to derive the key from this passphrase. The file's scrypt work factor " +
            "sets how much is needed, whatever the file size, and this one asks for more than " +
            "this device has."
    } else {
        "Not enough memory to finish this decrypt. Files are streamed, so this is unusual — " +
            "closing other apps and trying again should clear it."
    }

@Composable
private fun ErrorLine(message: String) {
    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
}
