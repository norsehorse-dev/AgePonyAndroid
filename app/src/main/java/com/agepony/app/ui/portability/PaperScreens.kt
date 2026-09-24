package com.agepony.app.ui.portability

import android.graphics.Bitmap
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.view.WindowManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.agepony.app.ui.components.qrBitmap
import com.agepony.app.ui.files.SafIo
import com.agepony.app.ui.scan.QrScanner
import com.agepony.app.ui.security.rememberSensitiveConfirm
import com.agepony.app.vault.KeyPortability
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.Vault
import com.agepony.app.vault.Wordlist
import com.agepony.core.crypto.Diceware
import com.agepony.core.portability.KeyTransfer
import com.agepony.core.portability.PaperBackup
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDate

// ---- Create ----

/**
 * Paper backup of one age identity, written as a PDF to a place the user picks. The page is
 * built in memory; the only copy that touches storage is the PDF itself.
 */
@Composable
fun PaperBackupScreen(vault: Vault, identity: StoredIdentity, onBack: () -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val activity = context as FragmentActivity
    val scope = rememberCoroutineScope()
    val confirmIdentity = rememberSensitiveConfirm(vault)
    val wordlist = remember { Wordlist.effLong(context) }

    var protect by remember { mutableStateOf(true) }
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var done by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var pdf by remember { mutableStateOf<ByteArray?>(null) }
    var suggested by remember { mutableStateOf<String?>(null) }

    var acceptedWeak by remember { mutableStateOf(false) }

    // This screen always forces FLAG_SECURE. Leaving it only clears the flag when the
    // activity-wide setting allows screenshots, so the default protection stays on (audit M-5).
    DisposableEffect(Unit) {
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            if (vault.allowScreenshots) activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri: Uri? ->
        val bytes = pdf
        pdf = null
        if (uri == null || bytes == null) { busy = false; return@rememberLauncherForActivityResult }
        scope.launch {
            try {
                withContext(Dispatchers.IO) { SafIo.openOutput(context, uri).use { it.write(bytes) } }
                done = true
            } catch (e: Exception) {
                error = e.message ?: "Couldn't save the PDF."
            } finally {
                bytes.fill(0)
                busy = false
            }
        }
    }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack) { Text("‹ Back") }
        Text("Paper backup", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
        Text(identity.name, style = MaterialTheme.typography.titleSmall)

        if (done) {
            Text("PDF saved ✓", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
            Text(
                "Print it on a printer you trust, then delete the PDF. Store the page somewhere safe" +
                    if (protect) ", and keep the passphrase somewhere else." else ". Anyone who sees it has the key.",
            )
            Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Done") }
            return@Column
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = protect, onClick = { protect = true })
            Text("Protect with a passphrase (recommended)")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = !protect, onClick = { protect = false })
            Text("Plain key: whoever reads the page has the key")
        }

        if (protect) {
            OutlinedTextField(
                value = passphrase, onValueChange = { passphrase = it; suggested = null; error = null; acceptedWeak = false },
                label = { Text("Passphrase") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = confirm, onValueChange = { confirm = it; suggested = null; error = null },
                label = { Text("Confirm passphrase") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            if (wordlist.isNotEmpty()) {
                TextButton(onClick = {
                    val p = Diceware.generate(wordlist, Diceware.DEFAULT_WORD_COUNT)
                    passphrase = p; confirm = p; suggested = p; acceptedWeak = false
                }) { Text("Suggest a ${Diceware.DEFAULT_WORD_COUNT}-word passphrase") }
                suggested?.let {
                    Text("Write this down now, apart from the page: $it", style = MaterialTheme.typography.bodyMedium)
                }
            }
            Text(
                "The page is an ordinary age file: restore it in AgePony, or with `age -d` on a computer.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            Text(
                "Only choose this for a page that will live somewhere locked, like a safe.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }

        // A paper page can be photographed or found, and then the passphrase is all that stands
        // between it and the key, offline and at the attacker's leisure. Warn on a weak one and
        // make the user say so explicitly before building the page.
        val weakness = if (protect && passphrase.isNotEmpty()) paperPassphraseWeakness(passphrase) else null
        val ready = !busy && (!protect || (passphrase.isNotEmpty() && passphrase == confirm && (weakness == null || acceptedWeak)))
        if (protect && confirm.isNotEmpty() && passphrase != confirm) {
            Text("The passphrases don't match.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        if (weakness != null) {
            Text(
                "This passphrase is weak: $weakness. Anyone who finds the page can try guesses offline " +
                    "for as long as they like. Use the suggested passphrase, or a longer one of your own.",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
            if (acceptedWeak) {
                Text(
                    "Using the weak passphrase anyway.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                OutlinedButton(onClick = { acceptedWeak = true }, modifier = Modifier.fillMaxWidth()) {
                    Text("Use it anyway")
                }
            }
        }
        Button(
            onClick = {
                confirmIdentity("Create paper backup") {
                    busy = true
                    error = null
                    val pass = if (protect) passphrase else null
                    scope.launch {
                        try {
                            pdf = withContext(Dispatchers.Default) { buildPaperPdf(identity, pass) }
                            vault.autoLockSuppressed = true
                            save.launch("agepony-backup-${safeFileName(identity.name)}-${LocalDate.now()}.pdf")
                        } catch (e: Exception) {
                            error = e.message ?: "Couldn't build the backup."
                            busy = false
                        }
                    }
                }
            },
            enabled = ready,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(if (busy) "Preparing…" else "Create PDF…") }
        if (busy) CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
    }
}

/**
 * Why [passphrase] is too weak to protect a paper backup, or null when it is fine. Under 12
 * characters is weak; so is a passphrase made of words (diceware style) with fewer than
 * [Diceware.MIN_WORD_COUNT] of them, whatever its length.
 */
private fun paperPassphraseWeakness(passphrase: String): String? {
    if (passphrase.length < 12) return "it is shorter than 12 characters"
    val words = passphrase.trim().split(Regex("[\\s._-]+")).filter { it.isNotEmpty() }
    val looksLikeWords = words.size >= 2 && words.all { w -> w.all { it.isLetter() } }
    if (looksLikeWords && words.size < Diceware.MIN_WORD_COUNT) {
        return "it has only ${words.size} words, and at least ${Diceware.MIN_WORD_COUNT} are needed"
    }
    return null
}

private fun safeFileName(name: String): String =
    name.replace(Regex("[^A-Za-z0-9._-]"), "-").trim('-').take(40).ifEmpty { "key" }

/** Lay out the A4 page: what it is, which key, the QR, the text, how to restore. */
private fun buildPaperPdf(identity: StoredIdentity, passphrase: String?): ByteArray {
    val line = KeyPortability.identityLine(identity)
        ?: throw IllegalArgumentException("Only age identities can be backed up on paper.")
    val identityFile = KeyTransfer.identityFile(listOf(line), includePublicKey = false)
    val payload = if (passphrase != null) PaperBackup.seal(identityFile, passphrase) else line.secretKey

    val doc = PdfDocument()
    val page = doc.startPage(PdfDocument.PageInfo.Builder(595, 842, 1).create())
    val c = page.canvas
    val title = Paint().apply { textSize = 20f; typeface = Typeface.DEFAULT_BOLD; isAntiAlias = true }
    val body = Paint().apply { textSize = 10f; isAntiAlias = true }
    val mono = Paint().apply { textSize = 8.5f; typeface = Typeface.MONOSPACE; isAntiAlias = true }
    var y = 56f
    fun text(s: String, p: Paint, gap: Float = 14f) { c.drawText(s, 48f, y, p); y += gap }

    text("AgePony paper backup", title, 26f)
    text("Name: ${identity.name}", body)
    text("Created: ${LocalDate.now()}", body)
    text(if (passphrase != null) "Protected with a passphrase (age scrypt). The passphrase is not on this page." else "UNPROTECTED: this page is the private key.", body)
    text("Public key (to check which key this is):", body)
    val pub = line.publicKey
    text(if (pub.length <= 88) pub else pub.take(40) + " … " + pub.takeLast(24), mono, 11f)
    y += 8f

    val qrSize = 300
    val bmp: Bitmap? = qrBitmap(payload, 1200, ErrorCorrectionLevel.M)
    if (bmp != null) {
        c.drawBitmap(bmp, null, Rect(48, y.toInt(), 48 + qrSize, y.toInt() + qrSize), null)
        bmp.recycle()
    }
    y += qrSize + 18f

    text(if (passphrase != null) "Backup text (an armored age file):" else "Secret key:", body)
    val textLines = if (passphrase != null) payload.lines() else PaperBackup.transcriptionGroups(payload, 12)
    textLines.forEach { text(it, mono, 10.5f) }
    y += 10f
    text("To restore: AgePony › Settings › Restore from paper backup, then scan the code.", body)
    if (passphrase != null) text("Or on a computer: save the text as backup.age and run  age -d -o key.txt backup.age", body)
    doc.finishPage(page)

    val out = java.io.ByteArrayOutputStream()
    doc.writeTo(out)
    doc.close()
    return out.toByteArray()
}

// ---- Restore ----

private enum class RestoreStage { SCAN, INPUT, PASSPHRASE, PREVIEW, DONE }

@Composable
fun PaperRestoreScreen(vault: Vault, onBack: () -> Unit, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    val activity = LocalContext.current as FragmentActivity
    // The typed or scanned page can be a plain secret key: keep it out of screenshots and Recents
    // even when screenshots are allowed elsewhere (audit M-5).
    DisposableEffect(Unit) {
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            if (vault.allowScreenshots) activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
    var stage by remember { mutableStateOf(RestoreStage.INPUT) }
    var scanned by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var found by remember { mutableStateOf<List<StoredIdentity>>(emptyList()) }
    var summary by remember { mutableStateOf<KeyPortability.ImportSummary?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    fun take(text: String) {
        error = null
        scanned = text
        if (PaperBackup.isSealed(text)) {
            stage = RestoreStage.PASSPHRASE
        } else {
            found = KeyPortability.identitiesFromText(text)
            if (found.isEmpty()) { error = "No age secret key found in that."; stage = RestoreStage.INPUT }
            else stage = RestoreStage.PREVIEW
        }
    }

    if (stage == RestoreStage.SCAN) {
        QrScanner(onResult = { take(it) }, onCancel = { stage = RestoreStage.INPUT }, modifier = modifier)
        return
    }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack) { Text("‹ Back") }
        Text("Restore from paper backup", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
        when (stage) {
            RestoreStage.INPUT -> {
                Button(onClick = { stage = RestoreStage.SCAN }, modifier = Modifier.fillMaxWidth()) { Text("Scan the page") }
                OutlinedTextField(
                    value = scanned, onValueChange = { scanned = it },
                    label = { Text("…or type or paste the text") }, minLines = 4,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(onClick = { take(scanned) }, enabled = scanned.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                    Text("Continue")
                }
            }
            RestoreStage.PASSPHRASE -> {
                Text("This page is passphrase-protected.")
                OutlinedTextField(
                    value = passphrase, onValueChange = { passphrase = it; error = null },
                    label = { Text("Passphrase") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(onClick = {
                    busy = true
                    val text = scanned
                    val pass = passphrase
                    scope.launch {
                        try {
                            val identityFile = withContext(Dispatchers.Default) { PaperBackup.open(text, pass) }
                            found = KeyPortability.identitiesFromText(identityFile)
                            stage = if (found.isEmpty()) RestoreStage.INPUT else RestoreStage.PREVIEW
                            if (found.isEmpty()) error = "The backup opened but held no age key."
                        } catch (e: OutOfMemoryError) {
                            error = "Not enough memory to derive the key on this device."
                        } catch (e: Exception) {
                            error = e.message ?: "Couldn't open the backup."
                        } finally {
                            busy = false
                        }
                    }
                }, enabled = passphrase.isNotEmpty() && !busy, modifier = Modifier.fillMaxWidth()) {
                    Text(if (busy) "Opening…" else "Open backup")
                }
            }
            RestoreStage.PREVIEW -> {
                Text("Found:", style = MaterialTheme.typography.titleSmall)
                found.forEach { Text("• ${it.name}") }
                Button(onClick = {
                    summary = KeyPortability.import(vault, KeyPortability.Incoming(found, emptyList(), emptyList()))
                    stage = RestoreStage.DONE
                }, modifier = Modifier.fillMaxWidth()) { Text("Add to vault") }
            }
            RestoreStage.DONE -> {
                val s = summary!!
                Text(
                    if (s.identitiesAdded > 0) "Restored ${s.identitiesAdded} identity ✓" else "That key is already in your vault.",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
                Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Done") }
            }
            RestoreStage.SCAN -> Unit
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
    }
}
