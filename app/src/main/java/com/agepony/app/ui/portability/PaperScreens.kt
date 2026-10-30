package com.agepony.app.ui.portability

import com.agepony.app.vault.ShownMessageException
import com.agepony.app.vault.DefaultKeyNames
import com.agepony.app.ui.UserMessage
import android.content.Context
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
import androidx.compose.foundation.layout.imePadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.RadioRow
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.components.pluralResource
import com.agepony.app.ui.theme.AgeStatus
import androidx.compose.ui.res.stringResource

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
                error = UserMessage.text(context, e, R.string.identities_paper_error_save)
            } finally {
                bytes.fill(0)
                busy = false
            }
        }
    }

    AgeScreen(title = stringResource(R.string.identities_paper_title), modifier = modifier, onBack = onBack) { padding ->
    Column(
        Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionHeader(identity.name)

        if (done) {
            VerdictPanel(
                title = stringResource(R.string.identities_paper_saved),
                detail = null,
                color = AgeStatus.colors.success,
                icon = Icons.Filled.CheckCircle,
            )
            Text(
                stringResource(
                    if (protect) R.string.identities_paper_saved_body_protected
                    else R.string.identities_paper_saved_body_plain
                ),
            )
            Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.identities_transfer_done)) }
            return@Column
        }

        RadioRow(
            title = stringResource(R.string.identities_paper_protect),
            selected = protect,
            onClick = { protect = true },
        )
        RadioRow(
            title = stringResource(R.string.identities_paper_plain),
            selected = !protect,
            onClick = { protect = false },
        )

        if (protect) {
            OutlinedTextField(
                value = passphrase, onValueChange = { passphrase = it; suggested = null; error = null; acceptedWeak = false },
                label = { Text(stringResource(R.string.identities_paper_passphrase)) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = confirm, onValueChange = { confirm = it; suggested = null; error = null },
                label = { Text(stringResource(R.string.identities_paper_confirm_passphrase)) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            if (wordlist.isNotEmpty()) {
                TextButton(onClick = {
                    val p = Diceware.generate(wordlist, Diceware.DEFAULT_WORD_COUNT)
                    passphrase = p; confirm = p; suggested = p; acceptedWeak = false
                }) { Text(stringResource(R.string.identities_paper_suggest, Diceware.DEFAULT_WORD_COUNT)) }
                suggested?.let {
                    Text(stringResource(R.string.identities_paper_write_down, it), style = MaterialTheme.typography.bodyMedium)
                }
            }
            Text(
                stringResource(R.string.identities_paper_ordinary_file),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            Text(
                stringResource(R.string.identities_paper_plain_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }

        // A paper page can be photographed or found, and then the passphrase is all that stands
        // between it and the key, offline and at the attacker's leisure. Warn on a weak one and
        // make the user say so explicitly before building the page.
        val weakness = if (protect && passphrase.isNotEmpty()) paperPassphraseWeakness(context, passphrase) else null
        val ready = !busy && (!protect || (passphrase.isNotEmpty() && passphrase == confirm && (weakness == null || acceptedWeak)))
        if (protect && confirm.isNotEmpty() && passphrase != confirm) {
            Text(stringResource(R.string.identities_paper_mismatch), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        if (weakness != null) {
            Text(
                weakness,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
            if (acceptedWeak) {
                Text(
                    stringResource(R.string.identities_paper_using_weak),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                OutlinedButton(onClick = { acceptedWeak = true }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.identities_paper_use_anyway))
                }
            }
        }
        Button(
            onClick = {
                confirmIdentity(context.getString(R.string.identities_paper_confirm_title)) {
                    busy = true
                    error = null
                    val pass = if (protect) passphrase else null
                    scope.launch {
                        try {
                            pdf = withContext(Dispatchers.Default) { buildPaperPdf(context, identity, pass) }
                            vault.autoLockSuppressed = true
                            save.launch("agepony-backup-${safeFileName(identity.name)}-${LocalDate.now()}.pdf")
                        } catch (e: Exception) {
                            error = UserMessage.text(context, e, R.string.identities_paper_error_build)
                            busy = false
                        }
                    }
                }
            },
            enabled = ready,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(if (busy) R.string.identities_paper_preparing else R.string.identities_paper_create_pdf)) }
        if (busy) CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
        error?.let { ErrorText(it) }
    }
    }
}

/**
 * Why [passphrase] is too weak to protect a paper backup, or null when it is fine. Under 12
 * characters is weak; so is a passphrase made of words (diceware style) with fewer than
 * [Diceware.MIN_WORD_COUNT] of them, whatever its length.
 */
private fun paperPassphraseWeakness(context: Context, passphrase: String): String? {
    if (passphrase.length < 12) return context.getString(R.string.identities_paper_weak_short, 12)
    val words = passphrase.trim().split(Regex("[\\s._-]+")).filter { it.isNotEmpty() }
    val looksLikeWords = words.size >= 2 && words.all { w -> w.all { it.isLetter() } }
    if (looksLikeWords && words.size < Diceware.MIN_WORD_COUNT) {
        return context.resources.getQuantityString(
            R.plurals.identities_paper_weak_few_words, words.size, words.size, Diceware.MIN_WORD_COUNT,
        )
    }
    return null
}

private fun safeFileName(name: String): String =
    name.replace(Regex("[^A-Za-z0-9._-]"), "-").trim('-').take(40).ifEmpty { "key" }

/** Lay out the A4 page: what it is, which key, the QR, the text, how to restore. */
private fun buildPaperPdf(context: Context, identity: StoredIdentity, passphrase: String?): ByteArray {
    val line = KeyPortability.identityLine(identity)
        ?: throw ShownMessageException(context.getString(R.string.identities_paper_error_not_age))
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

    text(context.getString(R.string.identities_paper_pdf_title), title, 26f)
    text(context.getString(R.string.identities_paper_pdf_name, identity.name), body)
    text(context.getString(R.string.identities_paper_pdf_created, LocalDate.now().toString()), body)
    text(
        context.getString(
            if (passphrase != null) R.string.identities_paper_pdf_protected else R.string.identities_paper_pdf_unprotected
        ),
        body,
    )
    text(context.getString(R.string.identities_paper_pdf_public_key), body)
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

    text(
        context.getString(
            if (passphrase != null) R.string.identities_paper_pdf_backup_text else R.string.identities_paper_pdf_secret_key
        ),
        body,
    )
    val textLines = if (passphrase != null) payload.lines() else PaperBackup.transcriptionGroups(payload, 12)
    textLines.forEach { text(it, mono, 10.5f) }
    y += 10f
    text(context.getString(R.string.identities_paper_pdf_restore), body)
    if (passphrase != null) {
        text(context.getString(R.string.identities_paper_pdf_restore_cli, "backup.age", "age -d -o key.txt backup.age"), body)
    }
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
            found = KeyPortability.identitiesFromText(text, DefaultKeyNames.from(activity))
            if (found.isEmpty()) { error = activity.getString(R.string.identities_paper_error_no_key); stage = RestoreStage.INPUT }
            else stage = RestoreStage.PREVIEW
        }
    }

    if (stage == RestoreStage.SCAN) {
        QrScanner(onResult = { take(it) }, onCancel = { stage = RestoreStage.INPUT }, modifier = modifier)
        return
    }

    AgeScreen(title = stringResource(R.string.identities_paper_restore_title), modifier = modifier, onBack = onBack) { padding ->
    Column(
        Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        when (stage) {
            RestoreStage.INPUT -> {
                Button(onClick = { stage = RestoreStage.SCAN }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.identities_paper_scan_page)) }
                OutlinedTextField(
                    value = scanned, onValueChange = { scanned = it },
                    label = { Text(stringResource(R.string.identities_paper_type_label)) }, minLines = 4,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(onClick = { take(scanned) }, enabled = scanned.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.identities_paper_continue))
                }
            }
            RestoreStage.PASSPHRASE -> {
                Text(stringResource(R.string.identities_paper_is_protected))
                OutlinedTextField(
                    value = passphrase, onValueChange = { passphrase = it; error = null },
                    label = { Text(stringResource(R.string.identities_paper_passphrase)) }, singleLine = true,
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
                            found = KeyPortability.identitiesFromText(identityFile, DefaultKeyNames.from(activity))
                            stage = if (found.isEmpty()) RestoreStage.INPUT else RestoreStage.PREVIEW
                            if (found.isEmpty()) error = activity.getString(R.string.identities_paper_error_empty)
                        } catch (e: OutOfMemoryError) {
                            error = activity.getString(R.string.identities_paper_error_memory)
                        } catch (e: Exception) {
                            error = UserMessage.text(activity, e, R.string.identities_paper_error_open)
                        } finally {
                            busy = false
                        }
                    }
                }, enabled = passphrase.isNotEmpty() && !busy, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(if (busy) R.string.identities_paper_opening else R.string.identities_paper_open_backup))
                }
            }
            RestoreStage.PREVIEW -> {
                SectionHeader(stringResource(R.string.identities_paper_found))
                found.forEach { Text(it.name, style = MaterialTheme.typography.bodyLarge) }
                Button(onClick = {
                    summary = KeyPortability.import(vault, KeyPortability.Incoming(found, emptyList(), emptyList()))
                    stage = RestoreStage.DONE
                }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.identities_paper_add_to_vault)) }
            }
            RestoreStage.DONE -> {
                val s = summary!!
                if (s.identitiesAdded > 0) {
                    VerdictPanel(
                        title = pluralResource(R.plurals.paper_restored, s.identitiesAdded, s.identitiesAdded),
                        detail = null,
                        color = AgeStatus.colors.success,
                        icon = Icons.Filled.CheckCircle,
                    )
                } else {
                    Text(stringResource(R.string.identities_paper_already_in_vault), style = MaterialTheme.typography.bodyLarge)
                }
                Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.identities_transfer_done)) }
            }
            RestoreStage.SCAN -> Unit
        }
        error?.let { ErrorText(it) }
    }
    }
}
