package com.agepony.app.ui.files

import com.agepony.app.vault.ShownMessageException
import com.agepony.app.ui.UserMessage
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
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.annotation.StringRes
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.DoneAction
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.OneLineValue
import com.agepony.app.ui.components.PrimaryAction
import com.agepony.app.ui.components.QuietAction
import com.agepony.app.ui.components.RowAction
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.StatusText
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.theme.AgeStatus

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
    /** False when embedded under another screen's app bar (the locked-vault passphrase screen). */
    showTopBar: Boolean = true,
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
    var verdict by remember { mutableStateOf<SignatureVerdict?>(null) }
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
                error = UserMessage.text(context, e, R.string.files_decrypt_failed)
                stage = DecryptStage.NEED_PASSPHRASE
            } catch (e: OutOfMemoryError) {
                error = context.getString(decryptOutOfMemoryMessage(pass != null))
                stage = if (usePassphrase) DecryptStage.NEED_PASSPHRASE else DecryptStage.PICK
            } catch (e: Exception) {
                error = UserMessage.textUnlessCancelled(context, e, R.string.files_decrypt_failed)
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
                error = UserMessage.textUnlessCancelled(context, e, R.string.files_not_age_file)
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
                extractResult = UserMessage.text(context, e, R.string.files_decrypt_extract_failed)
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

    // Leaving while the header is read or the file is written would cancel the job, so
    // back is held for those stages.
    if (stage == DecryptStage.PROBING || stage == DecryptStage.WORKING) BackHandler {}
    val onBack: (() -> Unit)? = when (stage) {
        DecryptStage.PROBING, DecryptStage.WORKING -> null
        else -> onClose
    }

    AgeScreen(
        title = stringResource(R.string.files_decrypt),
        modifier = modifier,
        onBack = onBack,
        actions = { if (stage == DecryptStage.DONE) DoneAction(onClose) },
        showTopBar = showTopBar,
    ) { padding ->
    Column(Modifier.fillMaxSize().padding(padding)) {
        when (stage) {
            DecryptStage.PICK -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    stringResource(R.string.files_decrypt_pick_intro),
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

            DecryptStage.PROBING -> Column(
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

            DecryptStage.NEED_PASSPHRASE -> Column(
                Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SectionHeader(stringResource(R.string.files_passphrase))
                OneLineValue(sourceName)
                Text(
                    stringResource(R.string.files_decrypt_no_identity),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it; error = null },
                    label = { Text(stringResource(R.string.files_passphrase)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (error != null) ErrorText(error!!)
                Button(
                    onClick = {
                        val ref = source ?: return@Button
                        if (passphrase.isEmpty()) { error = context.getString(R.string.files_enter_passphrase); return@Button }
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
                                    error = context.getString(R.string.files_decrypt_wrong_passphrase)
                                    stage = DecryptStage.NEED_PASSPHRASE
                                } else {
                                    vault.autoLockSuppressed = true
                                    createOutput.launch(FileEncryptor.decryptedName(ref.name))
                                }
                            } catch (e: OutOfMemoryError) {
                                error = context.getString(decryptOutOfMemoryMessage(true))
                                stage = DecryptStage.NEED_PASSPHRASE
                            } catch (e: Exception) {
                                error = UserMessage.text(context, e, R.string.files_decrypt_failed)
                                stage = DecryptStage.NEED_PASSPHRASE
                            }
                        }
                    },
                    enabled = passphrase.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.files_decrypt_action)) }
                TextButton(onClick = onClose) { Text(stringResource(R.string.action_cancel)) }
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
                    stringResource(R.string.files_decrypting),
                    modifier = Modifier.padding(top = 16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (total > 0) {
                    Text(
                        stringResource(R.string.files_progress_bytes, SafIo.humanSize(LocalContext.current, bytesDone), SafIo.humanSize(LocalContext.current, total)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            DecryptStage.DONE -> Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
            ) {
                // A failed signature changes the headline too (5.1.0, iOS L-3).
                DecryptedHeadline(signatureFailed = signatureFailed)
                OneLineValue(
                    savedName ?: FileEncryptor.decryptedName(sourceName),
                    modifier = Modifier.padding(top = 8.dp, bottom = 8.dp),
                )
                val original = originalName
                if (original != null && (original != savedName || !nameCovered)) {
                    Text(
                        if (nameCovered) {
                            stringResource(R.string.files_decrypt_original_name, original)
                        } else {
                            stringResource(R.string.files_decrypt_name_not_covered, original)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                }
                verdict?.let { v ->
                    // The state travels in a typed value; color and icon follow its kind (SignatureVerdict.kt).
                    SignatureVerdictPanel(
                        v,
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
                        stringResource(R.string.files_decrypt_bundle_failed),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                } else if (isBundle) {
                    Text(
                        stringResource(R.string.files_decrypt_bundle),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                    // The bundle's files are the result, so extracting them is the filled action.
                    PrimaryAction(
                        stringResource(
                            if (extracting) R.string.files_decrypt_extracting else R.string.files_decrypt_extract,
                        ),
                        onClick = { vault.autoLockSuppressed = true; pickExtractTree.launch(null) },
                        enabled = !extracting,
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    )
                    val msg = extractResult
                    if (msg != null) {
                        Text(
                            msg,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                    }
                }
                // Done sits in the app bar; the next file is its own row (5.1.0, U4).
                ListDivider(Modifier.padding(top = 8.dp))
                RowAction(stringResource(R.string.files_decrypt_another), onClick = { reset() })
                if (!showTopBar) {
                    // Embedded under the passphrase screen's bar, which has no Done.
                    QuietAction(stringResource(R.string.files_action_done), onClick = onClose)
                }
            }
        }
    }
    }
}

// ---- Work ----

// VerdictKind, SignatureVerdict and verdictFor live in SignatureVerdict.kt, shared with Text
// decrypt (5.1.0, iOS L-1).

private class DecryptOutcome(
    val originalName: String?,
    val verdict: SignatureVerdict?,
    /** A signature was present and failed (invalid or unreadable). Blocks bundle extraction. */
    val signatureFailed: Boolean = false,
    /** False for a v1 signed bundle, whose name the signature does not cover (audit L-8). */
    val nameCovered: Boolean = true,
    /** What an older (v1) signature does not cover, shown under the verdict. */
    val note: String? = null,
)

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

/**
 * The verdict for a signature-stanza file, checked against the in-memory plaintext before any of
 * it is written. A stanza that is present but can't be read is a failed signature, never
 * "unsigned" (audit L-9). The namespace and signed message come from the stanza's version.
 */
private fun stanzaOutcome(
    context: android.content.Context,
    recovered: Age.DecryptedWithSignature,
    known: List<StoredIdentity>,
    signers: List<StoredSigner>,
): DecryptOutcome = when (val opening = recovered.signature) {
    is SignatureStanza.Opening.Absent -> DecryptOutcome(null, null)
    is SignatureStanza.Opening.Unreadable ->
        DecryptOutcome(
            null,
            SignatureVerdict(
                VerdictKind.FAILED,
                context.getString(R.string.files_decrypt_unreadable),
            ),
            signatureFailed = true,
        )
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
            verdict = verdictFor(context, result),
            signatureFailed = result.trust == FileVerifier.Trust.INVALID,
            note = if (opening.coversRecipients) null else context.getString(R.string.files_decrypt_v1_stanza_note),
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
        val outcome = stanzaOutcome(context, recovered, known, signers)
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
    val checked = verdictFor(context, result)
    val verdict = if (failed) {
        SignatureVerdict(
            checked.kind,
            context.getString(R.string.files_decrypt_saved_before_check, checked.text),
        )
    } else {
        checked
    }
    return DecryptOutcome(
        originalName = bundle.name,
        verdict = verdict,
        signatureFailed = failed,
        nameCovered = bundle.nameCovered,
        note = if (bundle.nameCovered) null else context.getString(R.string.files_decrypt_v1_bundle_note),
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
    if (count == 0) throw ShownMessageException(context.getString(R.string.files_decrypt_bundle_empty))
    return context.resources.getQuantityString(R.plurals.files_decrypt_extracted, count, count)
}

private fun sanitizeEntryName(name: String): String {
    val base = name.substringAfterLast('/').substringAfterLast('\\').trim()
    return if (base.isEmpty() || base == "." || base == "..") "file" else base
}

/**
 * Decrypting streams, so a memory failure here is almost always scrypt: the work factor is
 * chosen by whoever encrypted the file, and a hostile one can demand gigabytes.
 */
@StringRes
private fun decryptOutOfMemoryMessage(usingPassphrase: Boolean): Int =
    if (usingPassphrase) R.string.files_decrypt_oom_passphrase else R.string.files_decrypt_oom
