package com.agepony.app.ui.portability

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.os.Build
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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.agepony.app.net.LocalNetwork
import com.agepony.app.security.ClipboardGuard
import com.agepony.app.share.ShareOut
import com.agepony.app.ui.components.QrImage
import com.agepony.app.ui.files.SafIo
import com.agepony.app.ui.scan.QrScanner
import com.agepony.app.ui.security.rememberSensitiveConfirm
import com.agepony.app.vault.KeyPortability
import com.agepony.app.vault.RecipientImport
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.Vault
import com.agepony.core.Armor
import com.agepony.core.portability.KeyTransfer
import com.agepony.core.portability.LanTransfer
import com.agepony.core.portability.TransferCode
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.HybridIdentity
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.time.LocalDate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.concurrent.thread
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.ui.semantics.Role
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.CheckRow
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.components.pluralResource
import com.agepony.app.ui.identities.rsaTooSmallText
import com.agepony.app.ui.theme.AgeStatus
import com.agepony.app.ui.theme.code
import androidx.compose.ui.res.stringResource

// ---- Receive ----

private const val XFER_TAG = "AgePonyXfer"
private const val RECEIVE_SESSION_MS = 15 * 60 * 1000L
private const val MIN_REUSE_MS = 5 * 60 * 1000L
private const val MAX_TRANSFER_BYTES = 16L * 1024 * 1024

private enum class ReceiveStage { WAITING, OPENING, PREVIEW, DONE, EXPIRED }

/**
 * The one-time receive key, held in memory for the process rather than in the screen, so a
 * rotation or an auto-lock while the user fetches the file doesn't swap it for a new one (which
 * would make the sender's file unopenable). Never written anywhere; gone with the process.
 */
private object ReceiveSession {
    private var identity: HybridIdentity? = null
    private var startedAt = 0L

    fun current(): HybridIdentity {
        val now = System.currentTimeMillis()
        val id = identity
        // Reuse the session across a screen recreate, but not one that's nearly out of time: a
        // screen reopened late would otherwise listen for only a few seconds.
        if (id != null && RECEIVE_SESSION_MS - (now - startedAt) > MIN_REUSE_MS) return id
        return fresh()
    }

    fun fresh(): HybridIdentity = HybridIdentity.generate().also {
        identity = it
        startedAt = System.currentTimeMillis()
    }

    fun remainingMs(): Long = (RECEIVE_SESSION_MS - (System.currentTimeMillis() - startedAt)).coerceAtLeast(0)

    fun end() { identity = null }
}

/**
 * The receiving side of a key transfer. Makes a one-time post-quantum identity that lives only in
 * memory for this screen, shows its recipient for the sender to scan, then opens the file the
 * sender produced and merges it into the vault.
 */
@Composable
fun ReceiveKeysScreen(vault: Vault, onBack: () -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var session by remember { mutableStateOf(ReceiveSession.current()) }
    val recipient = remember(session) { session.recipient().toBech32() }
    val code = remember(recipient) { KeyTransfer.confirmationCode(recipient) }
    var stage by remember { mutableStateOf(ReceiveStage.WAITING) }
    var error by remember { mutableStateOf<String?>(null) }
    var incoming by remember { mutableStateOf<KeyPortability.Incoming?>(null) }
    var summary by remember { mutableStateOf<KeyPortability.ImportSummary?>(null) }
    // Audit M-6: the code over the exact bytes received, which the user compares with the
    // sender's screen before anything can be imported, and what they chose to take.
    var transferCode by remember { mutableStateOf<String?>(null) }
    var codeConfirmed by remember { mutableStateOf(false) }
    val pickedIdentities = remember { mutableStateListOf<Int>() }
    val pickedRecipients = remember { mutableStateListOf<Int>() }
    val pickedSigners = remember { mutableStateListOf<Int>() }
    var leftOut by remember { mutableStateOf(0) }
    var pasted by remember { mutableStateOf("") }
    var showFileRoute by remember { mutableStateOf(false) }
    var server by remember(session) { mutableStateOf<ServerSocket?>(null) }

    LaunchedEffect(session) {
        delay(ReceiveSession.remainingMs())
        if (stage == ReceiveStage.WAITING) {
            ReceiveSession.end()
            runCatching { server?.close() }
            stage = ReceiveStage.EXPIRED
        }
    }

    // Show a transfer for review. Everything starts from "not confirmed": a transfer that
    // replaces another (a second route finishing) must be checked again. New identities and
    // recipients start ticked, except ssh-rsa keys too small to encrypt to; signers start
    // unticked, since trusting one is a decision of its own.
    fun showPreview(inc: KeyPortability.Incoming, received: String) {
        incoming = inc
        transferCode = received
        codeConfirmed = false
        pickedIdentities.clear()
        pickedRecipients.clear()
        pickedSigners.clear()
        inc.identities.forEachIndexed { i, id -> if (!KeyPortability.isKnown(vault, id)) pickedIdentities.add(i) }
        inc.recipients.forEachIndexed { i, r ->
            if (!KeyPortability.isKnown(vault, r) && !RecipientImport.isRsaBelowMinimum(r.type, r.publicKeyB64)) {
                pickedRecipients.add(i)
            }
        }
        error = null
        stage = ReceiveStage.PREVIEW
    }

    fun openBytes(bytes: ByteArray) {
        error = null
        stage = ReceiveStage.OPENING
        scope.launch {
            try {
                val (inc, received) = withContext(Dispatchers.Default) {
                    KeyPortability.readBundle(KeyTransfer.open(bytes, session)) to TransferCode.of(bytes)
                }
                showPreview(inc, received)
            } catch (e: Exception) {
                error = e.message ?: context.getString(R.string.identities_transfer_error_open)
                stage = ReceiveStage.WAITING
            }
        }
    }

    // Phone-to-phone over the local network: listen while this screen is open, and put the port,
    // this phone's addresses and a one-time token into the QR code next to the recipient.
    val token = remember(session) { LanTransfer.newToken() }
    val hosts = remember(session) { LocalNetwork.localAddresses() }
    val bindAddress = remember(session) { wifiBindAddress(context, hosts) }
    // One listener thread per session, tied to this screen: closing the socket in onDispose is
    // what stops it. (A coroutine can't do this: cancelling it doesn't unblock accept(), so a
    // cancelled listener could still take the transfer, ACK it and drop it.) The transfer is
    // opened before the ACK, so "Sent" on the other phone means it arrived and opened here.
    DisposableEffect(session) {
        val id = session
        // Listen on the Wi-Fi address the QR code advertises, not every interface (audit AS-3),
        // so the port isn't open on mobile data or a VPN. If that bind fails, fall back to all
        // interfaces rather than lose the direct route.
        val bound = bindAddress?.let { a ->
            runCatching { LanTransfer.openListener(a) }
                .onFailure { Log.i(XFER_TAG, "couldn't bind to the Wi-Fi address (${it.javaClass.simpleName}), listening on all interfaces") }
                .getOrNull()
        }
        val s = bound ?: runCatching { LanTransfer.openListener() }.getOrNull()
        server = s
        val main = Handler(Looper.getMainLooper())
        if (s != null) {
            thread(name = "agepony-xfer-receive", isDaemon = true) {
                Log.i(XFER_TAG, "listening on port ${s.localPort}, ${if (bound != null) "Wi-Fi address only" else "all interfaces"}, addresses $hosts")
                try {
                    LanTransfer.receive(s, token) { bytes ->
                        Log.i(XFER_TAG, "received ${bytes.size} bytes")
                        try {
                            val inc = KeyPortability.readBundle(KeyTransfer.open(bytes, id))
                            val received = TransferCode.of(bytes)
                            Log.i(XFER_TAG, "opened: ${inc.identities.size} identities, ${inc.recipients.size} recipients, ${inc.signers.size} signers")
                            main.post {
                                if (stage == ReceiveStage.WAITING || stage == ReceiveStage.OPENING) {
                                    showPreview(inc, received)
                                }
                            }
                            true
                        } catch (e: Throwable) {
                            Log.w(XFER_TAG, "couldn't open transfer: ${e.javaClass.simpleName}: ${e.message}")
                            main.post {
                                error = context.getString(
                                    R.string.identities_transfer_error_arrived,
                                    e.message ?: e.javaClass.simpleName,
                                )
                            }
                            false
                        }
                    }
                } catch (e: Exception) {
                    Log.i(XFER_TAG, "listener stopped: ${e.javaClass.simpleName}: ${e.message}")
                }
            }
        }
        onDispose { runCatching { s?.close() } }
    }
    val qrContent = remember(recipient, server, hosts) {
        val listener = server
        val port = listener?.localPort
        // A listener bound to one address advertises only that one (audit AS-3).
        val advertised = listener?.inetAddress?.takeUnless { it.isAnyLocalAddress }?.hostAddress
            ?.let { listOf(it) } ?: hosts
        if (port != null && advertised.isNotEmpty()) LanTransfer.Invite(recipient, token, port, advertised).encode()
        else recipient.uppercase()
    }

    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val bytes = withContext(Dispatchers.IO) {
                runCatching {
                    if (SafIo.queryNameSize(context, uri).second > MAX_TRANSFER_BYTES) null
                    else SafIo.openInput(context, uri).use { it.readBytes() }
                }.getOrNull()
            }
            if (bytes == null) error = context.getString(R.string.identities_transfer_error_read_file) else openBytes(bytes)
        }
    }

    // Leaving a transfer under review retires the receive key too, same as Cancel.
    fun leave() {
        if (stage == ReceiveStage.PREVIEW) ReceiveSession.end()
        onBack()
    }

    AgeScreen(title = stringResource(R.string.identities_transfer_receive_title), modifier = modifier, onBack = { leave() }) { padding ->
    Column(
        Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        error?.let { ErrorText(it) }

        when (stage) {
            ReceiveStage.WAITING, ReceiveStage.OPENING -> {
                Text(
                    stringResource(R.string.identities_transfer_receive_intro),
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (hosts.isEmpty() || server == null) {
                    Text(
                        stringResource(R.string.identities_transfer_no_wifi),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                QrImage(
                    content = qrContent,
                    size = 320.dp,
                    lowErrorCorrection = true,
                    contentDescription = stringResource(R.string.identities_transfer_qr_description),
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                Text(stringResource(R.string.identities_transfer_check_sender_code), style = MaterialTheme.typography.bodyMedium)
                Text(
                    code,
                    style = MaterialTheme.typography.code,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                if (stage == ReceiveStage.OPENING) CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
                ListDivider()
                TextButton(onClick = { showFileRoute = !showFileRoute }) {
                    Text(
                        stringResource(
                            if (showFileRoute) R.string.identities_transfer_hide_file_option
                            else R.string.identities_transfer_show_file_option
                        )
                    )
                }
                if (showFileRoute) {
                TextButton(onClick = { ClipboardGuard.copySensitive(context, recipient) }) {
                    Text(stringResource(R.string.identities_transfer_copy_key))
                }
                SectionHeader(stringResource(R.string.identities_transfer_open_header))
                Button(onClick = { vault.autoLockSuppressed = true; pickFile.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.identities_transfer_open_file))
                }
                OutlinedTextField(
                    value = pasted,
                    onValueChange = { pasted = it },
                    label = { Text(stringResource(R.string.identities_transfer_paste_label)) },
                    minLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(
                    onClick = { openBytes(pasted.trim().toByteArray(Charsets.UTF_8)) },
                    enabled = pasted.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.identities_transfer_open_pasted)) }
                }
            }

            ReceiveStage.PREVIEW -> {
                val inc = incoming!!
                // Audit M-6: anyone who saw the QR code can send a transfer here. Only the code
                // over what actually arrived tells the user it's the one their other phone sent.
                SectionHeader(stringResource(R.string.identities_transfer_code_header))
                Text(
                    transferCode.orEmpty(),
                    style = MaterialTheme.typography.code,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                Text(
                    stringResource(R.string.identities_transfer_code_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                CheckLine(stringResource(R.string.identities_transfer_code_matches), codeConfirmed) { codeConfirmed = !codeConfirmed }
                ListDivider()

                if (inc.identities.isEmpty() && inc.recipients.isEmpty() && inc.signers.isEmpty()) {
                    Text(stringResource(R.string.identities_transfer_nothing), color = MaterialTheme.colorScheme.error)
                }
                if (inc.identities.isNotEmpty()) {
                    SectionHeader(stringResource(R.string.identities_transfer_section_identities, inc.identities.size))
                    inc.identities.forEachIndexed { i, identity ->
                        val known = KeyPortability.isKnown(vault, identity)
                        val notes = buildList {
                            if (known) add(PreviewNote(stringResource(R.string.identities_transfer_already_here), false))
                            KeyPortability.nameClash(vault, identity)?.let {
                                add(PreviewNote(stringResource(R.string.identities_transfer_identity_name_clash, it.name), true))
                            }
                            KeyPortability.unverifiableNote(LocalContext.current, identity)?.let { add(PreviewNote(it, false)) }
                        }
                        PreviewRow(
                            title = identity.name,
                            detail = stringResource(
                                R.string.identities_transfer_type_key,
                                KeyPortability.typeLabel(LocalContext.current, identity.type),
                                KeyPortability.keySummary(LocalContext.current, identity),
                            ),
                            notes = notes,
                            checked = i in pickedIdentities,
                            enabled = !known,
                        ) { if (i in pickedIdentities) pickedIdentities.remove(i) else pickedIdentities.add(i) }
                    }
                    Text(
                        stringResource(R.string.identities_transfer_not_active_note),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (inc.recipients.isNotEmpty()) {
                    SectionHeader(stringResource(R.string.identities_transfer_section_recipients, inc.recipients.size))
                    inc.recipients.forEachIndexed { i, r ->
                        val known = KeyPortability.isKnown(vault, r)
                        val notes = buildList {
                            if (known) add(PreviewNote(stringResource(R.string.identities_transfer_already_here), false))
                            if (RecipientImport.isRsaBelowMinimum(r.type, r.publicKeyB64)) {
                                add(PreviewNote(rsaTooSmallText(context, RecipientImport.rsaBits(r.type, r.publicKeyB64)), true))
                            }
                            KeyPortability.nameClash(vault, r)?.let {
                                add(PreviewNote(stringResource(R.string.identities_transfer_recipient_name_clash, it.name), true))
                            }
                        }
                        PreviewRow(
                            title = r.name,
                            detail = stringResource(
                                R.string.identities_transfer_type_key,
                                KeyPortability.typeLabel(LocalContext.current, r.type),
                                KeyPortability.keySummary(LocalContext.current, r),
                            ),
                            notes = notes,
                            checked = i in pickedRecipients,
                            enabled = !known,
                        ) { if (i in pickedRecipients) pickedRecipients.remove(i) else pickedRecipients.add(i) }
                    }
                }
                if (inc.signers.isNotEmpty()) {
                    SectionHeader(stringResource(R.string.identities_transfer_section_signers, inc.signers.size))
                    Text(
                        stringResource(R.string.identities_transfer_signers_note),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    inc.signers.forEachIndexed { i, signer ->
                        val known = KeyPortability.isKnown(vault, signer)
                        val refused = signer.unenforceableReason(LocalContext.current)
                        val notes = buildList {
                            if (known) add(PreviewNote(stringResource(R.string.identities_transfer_already_trusted), false))
                            signer.restrictions(LocalContext.current).forEach { add(PreviewNote(it, false)) }
                            refused?.let { add(PreviewNote(stringResource(R.string.identities_transfer_not_imported, it), true)) }
                            signer.agePonyWarning(LocalContext.current)?.let { add(PreviewNote(it, true)) }
                            KeyPortability.nameClash(vault, signer)?.let {
                                add(PreviewNote(stringResource(R.string.identities_transfer_signer_name_clash, it), true))
                            }
                        }
                        PreviewRow(
                            title = signer.name,
                            detail = stringResource(
                                R.string.identities_transfer_type_key,
                                signer.keyType,
                                runCatching { signer.fingerprint() }.getOrNull()
                                    ?: stringResource(R.string.identities_transfer_unreadable_key),
                            ),
                            notes = notes,
                            checked = i in pickedSigners,
                            enabled = !known && refused == null,
                        ) { if (i in pickedSigners) pickedSigners.remove(i) else pickedSigners.add(i) }
                    }
                }
                val anyPicked = pickedIdentities.isNotEmpty() || pickedRecipients.isNotEmpty() || pickedSigners.isNotEmpty()
                Button(
                    onClick = {
                        val chosen = KeyPortability.Incoming(
                            inc.identities.filterIndexed { i, _ -> i in pickedIdentities },
                            inc.recipients.filterIndexed { i, _ -> i in pickedRecipients },
                            inc.signers.filterIndexed { i, _ -> i in pickedSigners },
                        )
                        leftOut = inc.identities.size + inc.recipients.size + inc.signers.size -
                            (chosen.identities.size + chosen.recipients.size + chosen.signers.size)
                        summary = KeyPortability.import(vault, chosen)
                        ReceiveSession.end()
                        stage = ReceiveStage.DONE
                    },
                    enabled = codeConfirmed && anyPicked,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.identities_import)) }
                if (!codeConfirmed) {
                    Text(
                        stringResource(
                            R.string.identities_transfer_tick_to_import,
                            stringResource(R.string.identities_transfer_code_matches),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                // Cancelling also retires this receive key: whoever photographed its QR code
                // can't try again with it.
                OutlinedButton(onClick = { ReceiveSession.end(); onBack() }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.action_cancel))
                }
            }

            ReceiveStage.DONE -> {
                val s = summary!!
                VerdictPanel(
                    title = stringResource(R.string.identities_transfer_imported),
                    detail = null,
                    color = AgeStatus.colors.success,
                    icon = Icons.Filled.CheckCircle,
                )
                val identitiesPart = pluralResource(R.plurals.transfer_identities, s.identitiesAdded, s.identitiesAdded)
                val recipientsPart = pluralResource(R.plurals.transfer_recipients, s.recipientsAdded, s.recipientsAdded)
                val signersPart = pluralResource(R.plurals.transfer_signers, s.signersAdded, s.signersAdded)
                Text(
                    when {
                        s.skipped > 0 && leftOut > 0 -> stringResource(
                            R.string.identities_transfer_summary_skipped_left_out,
                            identitiesPart, recipientsPart, signersPart, s.skipped, leftOut,
                        )
                        s.skipped > 0 -> stringResource(
                            R.string.identities_transfer_summary_skipped,
                            identitiesPart, recipientsPart, signersPart, s.skipped,
                        )
                        leftOut > 0 -> stringResource(
                            R.string.identities_transfer_summary_left_out,
                            identitiesPart, recipientsPart, signersPart, leftOut,
                        )
                        else -> stringResource(
                            R.string.identities_transfer_summary,
                            identitiesPart, recipientsPart, signersPart,
                        )
                    },
                )
                Text(
                    stringResource(R.string.identities_transfer_delete_file_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.identities_transfer_done)) }
            }

            ReceiveStage.EXPIRED -> {
                Text(stringResource(R.string.identities_transfer_expired))
                Button(onClick = { session = ReceiveSession.fresh(); stage = ReceiveStage.WAITING }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.identities_transfer_new_session))
                }
            }
        }
    }
    }
}

// ---- Send ----

private enum class SendStage { PICK, SCAN, CONFIRM, WORKING, SENT, DONE }

/** The sending side: choose keys, scan the receiver, confirm the code, write the transfer file. */
@Composable
fun SendKeysScreen(vault: Vault, onBack: () -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val confirmIdentity = rememberSensitiveConfirm(vault)

    val movable = remember { vault.identities.filter(KeyPortability::isTransferable) }
    val bound = remember { vault.identities.filterNot(KeyPortability::isTransferable) }
    val chosen = remember { mutableStateListOf<String>().apply { addAll(movable.map { it.id }) } }
    var includeRecipients by remember { mutableStateOf(true) }
    var includeSigners by remember { mutableStateOf(true) }

    var stage by remember { mutableStateOf(SendStage.PICK) }
    var recipientText by remember { mutableStateOf("") }
    var target by remember { mutableStateOf<AgeRecipient?>(null) }
    var invite by remember { mutableStateOf<LanTransfer.Invite?>(null) }
    var sealed by remember { mutableStateOf<ByteArray?>(null) }
    // The code over the sealed transfer (audit M-6), for the receiving phone to compare.
    var sentCode by remember { mutableStateOf<String?>(null) }
    var savedUri by remember { mutableStateOf<Uri?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    fun useRecipient(raw: String) {
        error = null
        try {
            // The receiver's QR carries its address and a one-time token alongside the key when it
            // can take the transfer directly; a bare age1pq1 key means the file route.
            val inv = if (LanTransfer.Invite.isInvite(raw)) LanTransfer.Invite.decode(raw) else null
            val key = inv?.recipient ?: raw
            target = KeyTransfer.parseRecipient(key)
            invite = inv
            recipientText = key.trim().lowercase()
            stage = SendStage.CONFIRM
        } catch (e: Exception) {
            error = e.message ?: context.getString(R.string.identities_transfer_error_not_receiving_key)
            stage = SendStage.PICK
        }
    }

    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(SafIo.MIME_OCTET)) { uri: Uri? ->
        val bytes = sealed ?: return@rememberLauncherForActivityResult
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            try {
                withContext(Dispatchers.IO) { SafIo.openOutput(context, uri).use { it.write(bytes) } }
                savedUri = uri
            } catch (e: Exception) {
                error = e.message ?: context.getString(R.string.identities_transfer_error_save)
            }
        }
    }

    if (stage == SendStage.SCAN) {
        QrScanner(onResult = { useRecipient(it) }, onCancel = { stage = SendStage.PICK }, modifier = modifier)
        return
    }

    // The app bar back arrow and system back step back one stage; while the transfer is being
    // built or sent, back waits for it.
    if (stage == SendStage.WORKING) BackHandler {}
    fun back() {
        when (stage) {
            SendStage.CONFIRM -> { stage = SendStage.PICK; target = null }
            else -> onBack()
        }
    }

    AgeScreen(
        title = stringResource(R.string.send_keys_title),
        modifier = modifier,
        onBack = if (stage == SendStage.WORKING) null else ({ back() }),
    ) { padding ->
    Column(
        Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {

        when (stage) {
            SendStage.PICK -> {
                Text(
                    stringResource(R.string.identities_transfer_send_intro),
                    style = MaterialTheme.typography.bodyMedium,
                )
                SectionHeader(stringResource(R.string.identities_title))
                if (movable.isEmpty()) Text(stringResource(R.string.identities_transfer_none_movable), style = MaterialTheme.typography.bodySmall)
                movable.forEach { id -> CheckLine(id.name, id.id in chosen) { if (id.id in chosen) chosen.remove(id.id) else chosen.add(id.id) } }
                bound.forEach { id ->
                    Text(
                        stringResource(R.string.identities_transfer_stays_on_device, id.name),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                CheckLine(stringResource(R.string.identities_transfer_section_recipients, vault.recipients.size), includeRecipients) { includeRecipients = !includeRecipients }
                CheckLine(stringResource(R.string.identities_transfer_section_signers, vault.signers.size), includeSigners) { includeSigners = !includeSigners }
                val anything = chosen.isNotEmpty() || (includeRecipients && vault.recipients.isNotEmpty()) ||
                    (includeSigners && vault.signers.isNotEmpty())
                Button(onClick = { stage = SendStage.SCAN }, enabled = anything, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.identities_transfer_scan_receiver))
                }
                OutlinedTextField(
                    value = recipientText,
                    onValueChange = { recipientText = it },
                    label = { Text(stringResource(R.string.identities_transfer_paste_key_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(onClick = { useRecipient(recipientText) }, enabled = anything && recipientText.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.identities_transfer_use_pasted))
                }
            }

            SendStage.CONFIRM -> {
                Text(stringResource(R.string.identities_transfer_confirm_question), style = MaterialTheme.typography.bodyMedium)
                Text(
                    KeyTransfer.confirmationCode(recipientText),
                    style = MaterialTheme.typography.code,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                if (!recipientText.startsWith("age1pq1")) {
                    Text(
                        stringResource(R.string.identities_transfer_not_quantum_safe),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Button(onClick = {
                    confirmIdentity(context.getString(R.string.send_keys_title)) {
                        stage = SendStage.WORKING
                        val ids: List<StoredIdentity> = movable.filter { it.id in chosen }
                        val recips = if (includeRecipients) vault.recipients.toList() else emptyList()
                        val signers = if (includeSigners) vault.signers.toList() else emptyList()
                        val to = target!!
                        scope.launch {
                            try {
                                val (bytes, code) = withContext(Dispatchers.Default) {
                                    val b = KeyTransfer.seal(KeyPortability.buildBundle(ids, recips, signers), to)
                                    b to TransferCode.of(b)
                                }
                                sealed = bytes
                                sentCode = code
                                val inv = invite
                                if (inv == null) {
                                    stage = SendStage.DONE
                                } else {
                                    try {
                                        withContext(Dispatchers.IO) {
                                            LanTransfer.send(inv, bytes, Build.MODEL ?: "phone") { host, port ->
                                                LocalNetwork.connectOverWifi(context, host, port)
                                            }
                                        }
                                        stage = SendStage.SENT
                                    } catch (e: Exception) {
                                        // Direct delivery failed: keep the sealed transfer and offer the file route.
                                        error = e.message ?: context.getString(R.string.identities_transfer_error_reach)
                                        stage = SendStage.DONE
                                    }
                                }
                            } catch (e: Exception) {
                                error = e.message ?: context.getString(R.string.identities_transfer_error_build)
                                stage = SendStage.CONFIRM
                            }
                        }
                    }
                }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.identities_transfer_matches_send)) }
                OutlinedButton(onClick = { stage = SendStage.PICK; target = null }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.identities_transfer_no_match))
                }
            }

            SendStage.WORKING -> {
                CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
                if (invite != null) Text(stringResource(R.string.identities_transfer_sending), modifier = Modifier.align(Alignment.CenterHorizontally))
            }

            SendStage.SENT -> {
                VerdictPanel(
                    title = stringResource(R.string.identities_transfer_sent),
                    detail = null,
                    color = AgeStatus.colors.success,
                    icon = Icons.Filled.CheckCircle,
                )
                Text(
                    stringResource(R.string.identities_transfer_sent_body),
                    style = MaterialTheme.typography.bodyMedium,
                )
                sentCode?.let { SentTransferCode(it) }
                Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.identities_transfer_done)) }
            }

            SendStage.DONE -> {
                val bytes = sealed!!
                SectionHeader(
                    stringResource(
                        if (invite != null) R.string.identities_transfer_fallback_header else R.string.identities_transfer_ready
                    ),
                )
                Text(
                    stringResource(R.string.identities_transfer_move_note),
                    style = MaterialTheme.typography.bodyMedium,
                )
                // The same code for the saved file and the text version: it covers the transfer
                // itself, not how it travels.
                sentCode?.let { SentTransferCode(it) }
                Button(onClick = {
                    vault.autoLockSuppressed = true
                    save.launch("agepony-keys-${LocalDate.now()}.age")
                }, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        stringResource(
                            if (savedUri == null) R.string.identities_transfer_save_file else R.string.identities_transfer_save_again
                        )
                    )
                }
                savedUri?.let { uri ->
                    OutlinedButton(onClick = { ShareOut.file(context, uri, "agepony-keys.age", context.getString(R.string.identities_transfer_share_chooser)) }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.identities_transfer_share_file))
                    }
                }
                if (bytes.size < 64 * 1024) {
                    OutlinedButton(onClick = { ShareOut.text(context, Armor.encode(bytes), context.getString(R.string.identities_transfer_share_text_chooser)) }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.identities_transfer_share_text))
                    }
                }
                TextButton(onClick = onBack) { Text(stringResource(R.string.identities_transfer_done)) }
            }

            SendStage.SCAN -> Unit
        }
        error?.let { ErrorText(it) }
    }
    }
}

/** A checkbox line; the whole row toggles (shared CheckRow). */
@Composable
internal fun CheckLine(label: String, checked: Boolean, onToggle: () -> Unit) {
    CheckRow(title = label, checked = checked, onCheckedChange = { onToggle() })
}

/** The sender's half of the audit M-6 check: the code the receiving phone must show before importing. */
@Composable
private fun SentTransferCode(code: String) {
    SectionHeader(stringResource(R.string.identities_transfer_code_header))
    Text(code, style = MaterialTheme.typography.code)
    Text(
        stringResource(R.string.identities_transfer_sent_code_note),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/** One line under a preview entry; [warning] lines are shown in the error color. */
private class PreviewNote(val text: String, val warning: Boolean)

/** One identity, recipient or signer in the receive preview (audit M-6): name, type and key, and a tick box. */
@Composable
private fun PreviewRow(
    title: String,
    detail: String,
    notes: List<PreviewNote>,
    checked: Boolean,
    enabled: Boolean,
    onToggle: () -> Unit,
) {
    // The whole row toggles; the Checkbox only draws the state.
    Row(
        verticalAlignment = Alignment.Top,
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(
                value = checked && enabled,
                enabled = enabled,
                role = Role.Checkbox,
                onValueChange = { onToggle() },
            )
            .padding(vertical = 8.dp),
    ) {
        Checkbox(checked = checked && enabled, onCheckedChange = null, enabled = enabled)
        Column(Modifier.weight(1f).padding(start = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            notes.forEach { n ->
                Text(
                    n.text,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (n.warning) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/**
 * The address to bind the receive listener to (audit AS-3): the Wi-Fi network's own address when
 * it's one of those in the QR code, or the only one listed (this phone's hotspot, say). Null means
 * listen on all of them: several candidates and none of them on the Wi-Fi network.
 */
private fun wifiBindAddress(context: Context, hosts: List<String>): InetAddress? {
    if (hosts.isEmpty()) return null
    val wifi: List<String> = runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        @Suppress("DEPRECATION")
        val networks = cm.allNetworks
        networks
            .filter { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true }
            .flatMap { n -> cm.getLinkProperties(n)?.linkAddresses.orEmpty() }
            .map { it.address }
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
    }.getOrDefault(emptyList())
    val pick = hosts.firstOrNull { it in wifi } ?: hosts.singleOrNull() ?: return null
    // A numeric literal: parsed, never looked up.
    return runCatching { InetAddress.getByName(pick) }.getOrNull()
}
