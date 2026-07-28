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
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.Vault
import com.agepony.app.vault.WrongPassphraseException
import com.agepony.app.vault.toAgeIdentity
import com.agepony.core.Age
import com.agepony.core.archive.SignedBundle
import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.ScryptIdentity
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
// plainly rather than pretending the file was verified before saving.
//

private enum class DecryptStage { PICK, PROBING, NEED_PASSPHRASE, WORKING, DONE }

@Composable
fun DecryptFlow(vault: Vault, modifier: Modifier = Modifier, onClose: () -> Unit) {
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
                        onBytes = { delta -> bytesDone += delta },
                    )
                }
                originalName = outcome.originalName
                verdict = outcome.verdict
                savedName = withContext(Dispatchers.IO) { SafIo.queryNameSize(context, dest).first }
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

    val openInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        error = null
        passphrase = ""
        usePassphrase = false
        verdict = null
        savedName = null
        originalName = null
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

    fun reset() {
        source = null; passphrase = ""; usePassphrase = false
        error = null; savedName = null; originalName = null; verdict = null
        bytesDone = 0L
        stage = DecryptStage.PICK
    }

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
                if (original != null && original != savedName) {
                    Text(
                        "Original name inside the signed file: $original",
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
                        modifier = Modifier.padding(bottom = 16.dp),
                    )
                }
                Button(onClick = { reset() }, modifier = Modifier.fillMaxWidth()) { Text("Decrypt another") }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Done") }
            }
        }
    }
}

// ---- Work ----

private class DecryptOutcome(val originalName: String?, val verdict: String?)

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
        Age.canDecryptStream(binary, identities)
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
    onBytes: (Long) -> Unit,
): DecryptOutcome {
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
    val result = FileVerifier().verifyHashed(
        bundle.signatureArmored.toByteArray(Charsets.UTF_8),
        known,
    ) { alg -> bundle.hash(alg) }
    val verdict = when (result.trust) {
        FileVerifier.Trust.TRUSTED -> "Signed by ${result.signerName ?: "a known key"} ✓"
        FileVerifier.Trust.VALID_UNKNOWN -> "Valid signature — signer not in your vault"
        FileVerifier.Trust.INVALID -> "⚠ Signature invalid: ${result.reason ?: "verification failed"}"
    }
    return DecryptOutcome(bundle.name, verdict)
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
