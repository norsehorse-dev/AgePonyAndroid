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
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.annotation.StringRes
import com.agepony.app.R
import com.agepony.app.signing.FileSigner
import com.agepony.app.share.ShareOut
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.ScryptMemoryException
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.Vault
import com.agepony.core.archive.SignedBundle
import com.agepony.core.archive.TarArchive
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SignatureStanza
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedOutputStream
import java.io.InputStream
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.RadioRow
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.SwitchRow
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.theme.AgeStatus
import com.agepony.app.ui.theme.mono

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
// 3.2.0 (GitHub issue #2) reshaped the setup around encrypting more than one file in a sitting:
//   - Recipients are chosen inline on the Configure screen instead of on a second full screen,
//     so the whole setup is one window.
//   - "Armor as text" and passphrase mode are remembered between files and between launches.
//   - The passphrase is held until the vault locks, so a run of files asks for it once.
//   - Finishing an encrypt keeps every one of those choices and goes straight to picking the
//     next files, rather than resetting to an empty form.
//

private enum class EncryptStage { PICK, MODE, CONFIGURE, WORKING, DONE }

/** What a batch of files should turn into. Asked whenever more than one file is picked. */
private enum class OutputMode { BUNDLE, SEPARATE }

/** Which pass of the work is running, for the progress line. */
private enum class EncryptPhase { SIGNING, ENCRYPTING }

/** One line of the per-file results list. */
private class EncryptResult(val name: String, val ok: Boolean, val detail: String)

/**
 * The chosen signing identity plus the FileSigner that routes it. Hardware keys prompt
 * for biometrics from inside the encrypt pass (FileSigner.signHashed hops to the main
 * thread for the prompt); security keys are excluded here and live on the Sign tab.
 */
private class SignChoice(val identity: StoredIdentity, val fileSigner: FileSigner)

@Composable
fun EncryptFlow(
    vault: Vault,
    modifier: Modifier = Modifier,
    initialUris: List<Uri>? = null,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val activity = context as FragmentActivity
    val scope = rememberCoroutineScope()

    var stage by remember { mutableStateOf(EncryptStage.PICK) }
    var sources by remember { mutableStateOf<List<SourceRef>>(emptyList()) }
    var mode by remember { mutableStateOf(OutputMode.BUNDLE) }

    // Recipient state is hoisted into a RecipientSelection so collapsing the inline picker — or
    // finishing a file and coming back for the next — does not wipe the choices.
    val selection = rememberRecipientSelection(vault, seedSessionPassphrase = true)
    var pickerOpen by remember { mutableStateOf(false) }
    var recipients by remember { mutableStateOf<List<AgeRecipient>>(emptyList()) }
    // A passphrase still held from earlier in this unlocked session counts as already chosen.
    var passphrase by remember { mutableStateOf(vault.sessionPassphrase) }

    var signerId by remember { mutableStateOf<String?>(null) }
    var armor by remember { mutableStateOf(vault.armorDefault) }
    var error by remember { mutableStateOf<String?>(null) }

    var phase by remember { mutableStateOf(EncryptPhase.ENCRYPTING) }
    var bytesDone by remember { mutableStateOf(0L) }
    var bytesTotal by remember { mutableStateOf(0L) }
    var fileIndex by remember { mutableStateOf(0) }
    var results by remember { mutableStateOf<List<EncryptResult>>(emptyList()) }
    var savedName by remember { mutableStateOf<String?>(null) }
    var savedUri by remember { mutableStateOf<Uri?>(null) }

    val totalSize = sources.sumOf { it.size }
    val separate = sources.size > 1 && mode == OutputMode.SEPARATE
    val hasRecipientChoice = recipients.isNotEmpty() || !passphrase.isNullOrEmpty()

    fun signerKey(): SignChoice? {
        val id = signerId ?: return null
        val identity = vault.identities.firstOrNull { it.id == id } ?: return null
        return SignChoice(identity, FileSigner(activity))
    }

    fun beginEncrypt(uris: List<Uri>) {
        if (uris.isEmpty()) return
        error = null
        scope.launch {
            try {
                val refs = withContext(Dispatchers.IO) { uris.map { SafIo.sourceRef(context, it) } }
                sources = refs
                stage = if (refs.size > 1) EncryptStage.MODE else EncryptStage.CONFIGURE
            } catch (e: Exception) {
                error = e.message ?: context.getString(R.string.files_encrypt_read_failed)
            }
        }
    }

    val openInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris: List<Uri> -> beginEncrypt(uris) }

    var initialConsumed by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(initialUris) {
        if (!initialConsumed && initialUris != null) { initialConsumed = true; beginEncrypt(initialUris) }
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
        phase = if (signer != null) EncryptPhase.SIGNING else EncryptPhase.ENCRYPTING
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
                savedUri = uri
                stage = EncryptStage.DONE
            } catch (e: ScryptMemoryException) {
                error = e.message
                stage = EncryptStage.CONFIGURE
            } catch (e: OutOfMemoryError) {
                error = context.getString(outOfMemoryMessage(!pass.isNullOrEmpty()))
                stage = EncryptStage.CONFIGURE
            } catch (e: Exception) {
                error = e.message ?: context.getString(R.string.files_encrypt_failed)
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
        phase = if (signer != null) EncryptPhase.SIGNING else EncryptPhase.ENCRYPTING
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
                error = context.getString(outOfMemoryMessage(!pass.isNullOrEmpty()))
                stage = EncryptStage.CONFIGURE
            } catch (e: Exception) {
                error = e.message ?: context.getString(R.string.files_encrypt_failed)
                stage = EncryptStage.CONFIGURE
            }
        }
    }

    /** Clear only what belongs to the files just handled; recipients and settings stay. */
    fun clearJob() {
        sources = emptyList()
        mode = OutputMode.BUNDLE
        results = emptyList()
        savedName = null
        savedUri = null
        bytesDone = 0L
        bytesTotal = 0L
        fileIndex = 0
        error = null
    }

    /**
     * Issue #2, item 5: finishing an encrypt used to drop every choice and put the user back at an
     * empty form. Now it keeps recipients, passphrase, signer and armor and opens the file picker,
     * so the next file is one tap away.
     */
    fun encryptMore() {
        clearJob()
        stage = EncryptStage.PICK
        vault.autoLockSuppressed = true
        openInput.launch(arrayOf("*/*"))
    }

    /** Throw away the whole setup, including recipients and any remembered passphrase. */
    fun startOver() {
        clearJob()
        recipients = emptyList()
        passphrase = null
        signerId = null
        pickerOpen = false
        selection.clear()
        vault.forgetSessionPassphrase()
        stage = EncryptStage.PICK
    }

    val haptics = rememberHaptics()
    LaunchedEffect(stage) { if (stage == EncryptStage.DONE) haptics.success() }

    // Leaving mid-write would cancel the job and leave a partial file, so back is held
    // while the work runs.
    if (stage == EncryptStage.WORKING) BackHandler {}
    val onBack: (() -> Unit)? = when (stage) {
        EncryptStage.PICK, EncryptStage.DONE -> onClose
        EncryptStage.MODE -> fun() { stage = EncryptStage.PICK }
        EncryptStage.CONFIGURE -> fun() { if (pickerOpen) pickerOpen = false else onClose() }
        EncryptStage.WORKING -> null
    }

    AgeScreen(title = stringResource(R.string.files_encrypt), modifier = modifier, onBack = onBack) { padding ->
    Column(Modifier.fillMaxSize().padding(padding)) {
        when (stage) {
            EncryptStage.PICK -> Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    stringResource(R.string.files_encrypt_pick_intro),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (hasRecipientChoice) {
                    Text(
                        stringResource(
                            R.string.files_encrypt_still_set,
                            recipientSummary(recipients.size, passphrase),
                            stringResource(if (armor) R.string.files_encrypt_output_armored else R.string.files_encrypt_output_binary),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (error != null) ErrorText(error!!)
                Button(
                    onClick = { vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.files_pick_files)) }
                if (hasRecipientChoice) {
                    TextButton(onClick = { startOver() }) { Text(stringResource(R.string.files_encrypt_clear_choices)) }
                }
                TextButton(onClick = onClose) { Text(stringResource(R.string.action_cancel)) }
            }

            EncryptStage.MODE -> Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SectionHeader(pluralStringResource(R.plurals.files_encrypt_file_count, sources.size, sources.size))
                Text(
                    stringResource(R.string.files_encrypt_mode_question),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                RadioRow(
                    selected = mode == OutputMode.BUNDLE,
                    title = stringResource(R.string.files_encrypt_mode_bundle),
                    subtitle = pluralStringResource(R.plurals.files_encrypt_mode_bundle_detail, sources.size, sources.size),
                    onClick = { mode = OutputMode.BUNDLE },
                )
                RadioRow(
                    selected = mode == OutputMode.SEPARATE,
                    title = stringResource(R.string.files_encrypt_mode_separate),
                    subtitle = pluralStringResource(R.plurals.files_encrypt_mode_separate_detail, sources.size, sources.size),
                    onClick = { mode = OutputMode.SEPARATE },
                )

                Button(onClick = { stage = EncryptStage.CONFIGURE }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.files_action_continue))
                }
            }

            EncryptStage.CONFIGURE -> Column(
                Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SectionHeader(stringResource(R.string.files_encrypt_section_source))
                Text(
                    when {
                        sources.size > 1 && separate ->
                            pluralStringResource(R.plurals.files_encrypt_source_separate, sources.size, sources.size)
                        sources.size > 1 ->
                            pluralStringResource(R.plurals.files_encrypt_source_bundle, sources.size, sources.size)
                        else -> sources.firstOrNull()?.name ?: "file"
                    },
                    style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
                // 0 means the provider reported no size; say nothing rather than "0 B".
                if (totalSize > 0) {
                    Text(
                        SafIo.humanSize(totalSize),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { vault.autoLockSuppressed = true; openInput.launch(arrayOf("*/*")) }) {
                        Text(stringResource(R.string.files_encrypt_change_files))
                    }
                    if (sources.size > 1) {
                        TextButton(onClick = { stage = EncryptStage.MODE }) { Text(stringResource(R.string.files_encrypt_change_output)) }
                    }
                }

                HorizontalDivider()

                // Recipients, inline. Opening this used to replace the whole screen and then throw
                // the user back to the top of the form on the way out (issue #2, item 4).
                SectionHeader(stringResource(R.string.files_section_recipients))
                Text(recipientSummary(recipients.size, passphrase), style = MaterialTheme.typography.bodyMedium)
                if (!passphrase.isNullOrEmpty()) {
                    Text(
                        stringResource(R.string.files_encrypt_passphrase_kept),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { pickerOpen = !pickerOpen }) {
                        Text(
                            when {
                                pickerOpen -> stringResource(R.string.action_hide)
                                hasRecipientChoice -> stringResource(R.string.files_encrypt_change_recipients)
                                else -> stringResource(R.string.files_choose_recipients)
                            }
                        )
                    }
                    if (!passphrase.isNullOrEmpty()) {
                        TextButton(onClick = {
                            passphrase = null
                            vault.forgetSessionPassphrase()
                            selection.passphrase = ""
                            selection.passphraseConfirm = ""
                        }) { Text(stringResource(R.string.files_encrypt_forget_passphrase)) }
                    }
                }

                if (pickerOpen) {
                    RecipientPickerContent(
                        vault = vault,
                        selection = selection,
                        modifier = Modifier.fillMaxWidth(),
                        showTitle = false,
                        rememberPassphrase = true,
                        onCancel = { pickerOpen = false },
                        onConfirm = { r, p ->
                            recipients = r
                            passphrase = p
                            pickerOpen = false
                        },
                    )
                }

                HorizontalDivider()

                // Optional signing: in-app SSH keys sign in-process; a hardware key prompts
                // for biometrics during the encrypt. Security keys stay on the Sign tab.
                val signingIdentities = vault.identities.filter { it.type in FileSigner.ENCRYPT_SIGNING_TYPES }
                if (signingIdentities.isNotEmpty()) {
                    SectionHeader(stringResource(R.string.files_encrypt_section_sign))
                    RadioRow(selected = signerId == null, title = stringResource(R.string.files_encrypt_dont_sign), onClick = { signerId = null })
                    signingIdentities.forEach { id ->
                        RadioRow(selected = signerId == id.id, title = id.name, onClick = { signerId = id.id })
                    }
                    Text(
                        stringResource(R.string.files_encrypt_sign_detail),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    HorizontalDivider()
                }

                // Remembered across files and launches (issue #2, item 1); the same switch
                // lives in Settings under Encryption.
                SwitchRow(
                    title = stringResource(R.string.files_encrypt_armor),
                    subtitle = stringResource(
                        if (armor) R.string.files_encrypt_armor_on else R.string.files_encrypt_armor_off,
                    ),
                    checked = armor,
                    onCheckedChange = { armor = it; vault.armorDefault = it },
                )

                if (error != null) ErrorText(error!!)

                // Deliberately dead while the picker is open. Inlining the picker put this button
                // on the same screen as unconfirmed edits, and encrypting from here would use the
                // last *confirmed* choice — quietly sending a file to the previous recipient, or
                // to a passphrase the user was in the middle of replacing with a key.
                val canEncrypt = sources.isNotEmpty() && hasRecipientChoice && !pickerOpen
                if (pickerOpen && hasRecipientChoice) {
                    Text(
                        stringResource(R.string.files_encrypt_confirm_picker_first),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
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
                            separate -> stringResource(R.string.files_encrypt_folder_and_encrypt)
                            signerId != null -> stringResource(R.string.files_encrypt_sign_and_encrypt)
                            else -> stringResource(R.string.files_encrypt_destination_and_encrypt)
                        }
                    )
                }
                TextButton(onClick = onClose) { Text(stringResource(R.string.action_cancel)) }
            }

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
                    if (sources.size > 1 && separate) {
                        stringResource(
                            if (phase == EncryptPhase.SIGNING) R.string.files_encrypt_signing_n else R.string.files_encrypt_encrypting_n,
                            fileIndex,
                            sources.size,
                        )
                    } else {
                        stringResource(
                            if (phase == EncryptPhase.SIGNING) R.string.files_encrypt_signing else R.string.files_encrypting,
                        )
                    },
                    modifier = Modifier.padding(top = 16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (bytesTotal > 0) {
                    Text(
                        stringResource(R.string.files_progress_bytes, SafIo.humanSize(bytesDone), SafIo.humanSize(bytesTotal)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            EncryptStage.DONE -> Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (results.isEmpty()) {
                    VerdictPanel(
                        title = stringResource(R.string.files_encrypt_done),
                        detail = null,
                        color = AgeStatus.colors.success,
                        icon = Icons.Filled.CheckCircle,
                    )
                    savedName?.let { name ->
                        Text(
                            name,
                            style = MaterialTheme.typography.mono,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    // The output is ciphertext, so it can go straight out to another app.
                    savedUri?.let { out ->
                        OutlinedButton(
                            onClick = { ShareOut.file(context, out, savedName ?: "encrypted.age") },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(stringResource(R.string.files_encrypt_share)) }
                    }
                } else {
                    val okCount = results.count { it.ok }
                    VerdictPanel(
                        title = stringResource(R.string.files_encrypt_done),
                        detail = null,
                        color = if (okCount == results.size) AgeStatus.colors.success else AgeStatus.colors.warning,
                        icon = if (okCount == results.size) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                    )
                    Text(
                        pluralStringResource(R.plurals.files_encrypt_batch_result, results.size, okCount, results.size),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    ListDivider()
                    results.forEach { item ->
                        Column(Modifier.fillMaxWidth()) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    if (item.ok) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                                    contentDescription = null,
                                    tint = if (item.ok) AgeStatus.colors.success else AgeStatus.colors.failure,
                                    modifier = Modifier.size(16.dp),
                                )
                                Text(
                                    item.name,
                                    style = MaterialTheme.typography.mono,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.padding(start = 8.dp),
                                )
                            }
                            Text(
                                item.detail,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        ListDivider()
                    }
                }
                Button(onClick = { encryptMore() }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.files_encrypt_more))
                }
                Text(
                    stringResource(R.string.files_encrypt_more_detail),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text(stringResource(R.string.files_action_done)) }
            }
        }
    }
    }
}

// ---- Work ----

/**
 * Everything that ends up as a single output document: one file, or several bundled into one
 * archive. Input streams and the output stream are the only buffers involved.
 */
private suspend fun encryptToDocument(
    context: Context,
    sources: List<SourceRef>,
    dest: Uri,
    bundle: Boolean,
    recipients: List<AgeRecipient>,
    passphrase: String?,
    signer: SignChoice?,
    armor: Boolean,
    workFactor: Int,
    onPhase: (EncryptPhase) -> Unit,
    onBytes: (Long) -> Unit,
) {
    // A tar header carries each entry's size ahead of its bytes, and a signature covers a payload
    // of declared length, so those paths need exact sizes; a plain single-file encrypt does not.
    if (sources.isEmpty()) throw IllegalStateException("No files chosen.")
    val needSizes = bundle || signer != null
    // Staging copies are collected inside the try, so one that fails part way through a batch
    // still has every earlier copy removed in the finally (audit L-19).
    val prepared = ArrayList<PreparedSource>(sources.size)
    try {
        sources.forEach { prepared += SafIo.prepare(context, it, needSizes) }

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

        if (signer != null && passphrase.isNullOrEmpty()) {
            // Signed to public-key recipients: the signature rides in an encrypted v2 header
            // stanza (agepony.com/sig v2), so the output stays a real age file that plain age
            // still reads. The v2 signature covers the plaintext hash and the recipient stanzas
            // (audit L-8), so the file key is made and wrapped first, then the payload is hashed,
            // signed, and read a second time to encrypt. Nothing is buffered.
            onPhase(EncryptPhase.SIGNING)
            val signedEncryption = FileEncryptor.prepareSigned(recipients)
            val payloadSha512 = openPayload(counting = true).use { SSHSig.hashStream(it, SSHSig.HASH_SHA512) }
            val signature = signer.fileSigner.signHashed(
                signer.identity,
                signedEncryption.messageHash(payloadSha512),
                SignatureStanza.NAMESPACE_V2,
            )
            onPhase(EncryptPhase.ENCRYPTING)
            try {
                openPayload(counting = true).use { input ->
                    BufferedOutputStream(SafIo.openOutput(context, dest)).use { out ->
                        FileEncryptor.encryptSignedV2Stream(signedEncryption, input, payloadSha512, signature, armor, out)
                        out.flush()
                    }
                }
            } catch (t: Throwable) {
                // A source that changed between the two reads throws only after the whole file
                // is written, and its signature would not verify: don't leave it behind.
                SafIo.discard(context, dest)
                throw t
            }
        } else {
            val plaintext: InputStream = if (signer == null) {
                openPayload(counting = true)
            } else {
                // Passphrase files can't carry a sig stanza (scrypt must stand alone), so the
                // signature travels in a v2 SignedBundle, which also covers the name (audit L-8).
                onPhase(EncryptPhase.SIGNING)
                val payloadSha512 = openPayload(counting = true).use { SSHSig.hashStream(it, SSHSig.HASH_SHA512) }
                val signature = signer.fileSigner.signHashed(
                    signer.identity,
                    SignedBundle.v2MessageHash(payloadName, payloadSha512),
                    SignedBundle.NAMESPACE_V2,
                )
                SignedBundle.bundleSourceV2(payloadName, payloadSize, openPayload(counting = true), signature)
            }

            onPhase(EncryptPhase.ENCRYPTING)
            plaintext.use { input ->
                BufferedOutputStream(SafIo.openOutput(context, dest)).use { out ->
                    FileEncryptor.encryptStream(input, recipients, passphrase, armor, out, workFactor)
                    out.flush()
                }
            }
        }
    } finally {
        prepared.forEach { it.cleanup() }
    }
}

/** One encrypted file per input, written into [tree]. One failure does not stop the batch. */
private suspend fun encryptToFolder(
    context: Context,
    sources: List<SourceRef>,
    tree: Uri,
    recipients: List<AgeRecipient>,
    passphrase: String?,
    signer: SignChoice?,
    armor: Boolean,
    workFactor: Int,
    onPhase: (EncryptPhase) -> Unit,
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
            onResult(
                EncryptResult(
                    outName,
                    true,
                    context.getString(
                        if (signer != null) R.string.files_encrypt_item_signed else R.string.files_encrypt_item_done,
                    ),
                ),
            )
        } catch (e: ScryptMemoryException) {
            throw e // the same for every file in the batch; report it once, not N times
        } catch (e: OutOfMemoryError) {
            throw e // a memory failure is not per-file; let the caller report it once
        } catch (e: Exception) {
            onResult(EncryptResult(ref.name, false, e.message ?: context.getString(R.string.files_encrypt_failed)))
        }
    }
}

/**
 * Say which allocation actually failed. Passphrase mode allocates 128 * 2^18 * 8 bytes (256 MiB)
 * inside scrypt no matter how small the file is, so "try a smaller file" is the wrong advice —
 * that was the bug in the 3.0.2 message.
 */
@StringRes
private fun outOfMemoryMessage(usingPassphrase: Boolean): Int =
    if (usingPassphrase) R.string.files_encrypt_oom_passphrase else R.string.files_encrypt_oom

// ---- Small pieces ----

@Composable
private fun recipientSummary(count: Int, passphrase: String?): String = when {
    !passphrase.isNullOrEmpty() -> stringResource(R.string.files_passphrase_only_scrypt)
    count == 0 -> stringResource(R.string.files_recipients_none)
    else -> pluralStringResource(R.plurals.transfer_recipients, count, count)
}
