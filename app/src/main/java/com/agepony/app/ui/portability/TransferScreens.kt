package com.agepony.app.ui.portability

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
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.agepony.app.net.LocalNetwork
import com.agepony.app.security.ClipboardGuard
import com.agepony.app.share.ShareOut
import com.agepony.app.ui.components.QrImage
import com.agepony.app.ui.files.SafIo
import com.agepony.app.ui.scan.QrScanner
import com.agepony.app.ui.security.rememberSensitiveConfirm
import com.agepony.app.vault.KeyPortability
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.Vault
import com.agepony.core.Armor
import com.agepony.core.portability.KeyTransfer
import com.agepony.core.portability.LanTransfer
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.HybridIdentity
import java.net.ServerSocket
import java.time.LocalDate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.concurrent.thread

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

    fun openBytes(bytes: ByteArray) {
        error = null
        stage = ReceiveStage.OPENING
        scope.launch {
            try {
                incoming = withContext(Dispatchers.Default) {
                    KeyPortability.readBundle(KeyTransfer.open(bytes, session))
                }
                stage = ReceiveStage.PREVIEW
            } catch (e: Exception) {
                error = e.message ?: "Couldn't open that transfer."
                stage = ReceiveStage.WAITING
            }
        }
    }

    // Phone-to-phone over the local network: listen while this screen is open, and put the port,
    // this phone's addresses and a one-time token into the QR code next to the recipient.
    val token = remember(session) { LanTransfer.newToken() }
    val hosts = remember(session) { LocalNetwork.localAddresses() }
    // One listener thread per session, tied to this screen: closing the socket in onDispose is
    // what stops it. (A coroutine can't do this: cancelling it doesn't unblock accept(), so a
    // cancelled listener could still take the transfer, ACK it and drop it.) The transfer is
    // opened before the ACK, so "Sent" on the other phone means it arrived and opened here.
    DisposableEffect(session) {
        val id = session
        val s = runCatching { ServerSocket(0) }.getOrNull()
        server = s
        val main = Handler(Looper.getMainLooper())
        if (s != null) {
            thread(name = "agepony-xfer-receive", isDaemon = true) {
                Log.i(XFER_TAG, "listening on port ${s.localPort}, addresses $hosts")
                try {
                    LanTransfer.receive(s, token) { bytes ->
                        Log.i(XFER_TAG, "received ${bytes.size} bytes")
                        try {
                            val inc = KeyPortability.readBundle(KeyTransfer.open(bytes, id))
                            Log.i(XFER_TAG, "opened: ${inc.identities.size} identities, ${inc.recipients.size} recipients, ${inc.signers.size} signers")
                            main.post {
                                if (stage == ReceiveStage.WAITING || stage == ReceiveStage.OPENING) {
                                    incoming = inc
                                    error = null
                                    stage = ReceiveStage.PREVIEW
                                }
                            }
                            true
                        } catch (e: Throwable) {
                            Log.w(XFER_TAG, "couldn't open transfer: ${e.javaClass.simpleName}: ${e.message}")
                            main.post { error = "A transfer arrived but couldn't be opened: " + (e.message ?: e.javaClass.simpleName) }
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
        val port = server?.localPort
        if (port != null && hosts.isNotEmpty()) LanTransfer.Invite(recipient, token, port, hosts).encode()
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
            if (bytes == null) error = "Couldn't read that file." else openBytes(bytes)
        }
    }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack) { Text("‹ Back") }
        Text("Receive keys", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }

        when (stage) {
            ReceiveStage.WAITING, ReceiveStage.OPENING -> {
                Text(
                    "On the other phone, open AgePony › Settings › Send keys to another device, and scan " +
                        "this code. Keep this screen open: with both phones on the same Wi-Fi, the keys " +
                        "arrive here directly in a few seconds.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (hosts.isEmpty() || server == null) {
                    Text(
                        "This phone isn't on a Wi-Fi network, so the keys can't come across directly. " +
                            "Join the same Wi-Fi as the other phone (or its hotspot) and reopen this screen, " +
                            "or use a file below.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                QrImage(
                    content = qrContent,
                    size = 320.dp,
                    lowErrorCorrection = true,
                    contentDescription = "One-time key for receiving a transfer",
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                Text("Check the sender shows this code:", style = MaterialTheme.typography.bodyMedium)
                Text(
                    code,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 24.sp,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                if (stage == ReceiveStage.OPENING) CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
                HorizontalDivider()
                TextButton(onClick = { showFileRoute = !showFileRoute }) {
                    Text(if (showFileRoute) "Hide the file option" else "No shared Wi-Fi? Use a file instead")
                }
                if (showFileRoute) {
                TextButton(onClick = { ClipboardGuard.copySensitive(context, recipient) }) {
                    Text("Copy the key as text")
                }
                Text("Then open what the sender made:", style = MaterialTheme.typography.titleSmall)
                Button(onClick = { vault.autoLockSuppressed = true; pickFile.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Open the transfer file…")
                }
                OutlinedTextField(
                    value = pasted,
                    onValueChange = { pasted = it },
                    label = { Text("…or paste the transfer text") },
                    minLines = 3,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(
                    onClick = { openBytes(pasted.trim().toByteArray(Charsets.UTF_8)) },
                    enabled = pasted.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Open pasted text") }
                }
            }

            ReceiveStage.PREVIEW -> {
                val inc = incoming!!
                Text("This transfer holds:", style = MaterialTheme.typography.titleSmall)
                if (inc.identities.isEmpty() && inc.recipients.isEmpty() && inc.signers.isEmpty()) {
                    Text("Nothing this phone can import.", color = MaterialTheme.colorScheme.error)
                }
                inc.identities.forEach { Text("• ${it.name}", style = MaterialTheme.typography.bodyMedium) }
                if (inc.recipients.isNotEmpty()) Text("• ${inc.recipients.size} saved recipients")
                if (inc.signers.isNotEmpty()) Text("• ${inc.signers.size} trusted signers")
                Text(
                    "Anything already in your vault is skipped.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(onClick = {
                    summary = KeyPortability.import(vault, inc)
                    ReceiveSession.end()
                    stage = ReceiveStage.DONE
                }, modifier = Modifier.fillMaxWidth()) { Text("Import") }
                OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
            }

            ReceiveStage.DONE -> {
                val s = summary!!
                Text("Imported ✓", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
                Text(
                    "${s.identitiesAdded} identities, ${s.recipientsAdded} recipients, ${s.signersAdded} signers" +
                        if (s.skipped > 0) " (${s.skipped} already here, skipped)." else ".",
                )
                Text(
                    "If you moved it with a file, delete that file from wherever it went through.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Done") }
            }

            ReceiveStage.EXPIRED -> {
                Text("This receive session timed out and its one-time key is gone.")
                Button(onClick = { session = ReceiveSession.fresh(); stage = ReceiveStage.WAITING }, modifier = Modifier.fillMaxWidth()) {
                    Text("Start a new session")
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
            error = e.message ?: "That isn't a receiving key."
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
                error = e.message ?: "Couldn't save the file."
            }
        }
    }

    if (stage == SendStage.SCAN) {
        QrScanner(onResult = { useRecipient(it) }, onCancel = { stage = SendStage.PICK }, modifier = modifier)
        return
    }

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack) { Text("‹ Back") }
        Text("Send keys to another device", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)

        when (stage) {
            SendStage.PICK -> {
                Text(
                    "Your keys are encrypted to a one-time key shown by the receiving device, so the file " +
                        "you move is useless to anyone else. Start Receive keys on the other device first.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text("Identities", style = MaterialTheme.typography.titleSmall)
                if (movable.isEmpty()) Text("No identities that can be moved.", style = MaterialTheme.typography.bodySmall)
                movable.forEach { id -> CheckLine(id.name, id.id in chosen) { if (id.id in chosen) chosen.remove(id.id) else chosen.add(id.id) } }
                bound.forEach { id ->
                    Text(
                        "${id.name}: stays on this device (hardware key)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                CheckLine("Saved recipients (${vault.recipients.size})", includeRecipients) { includeRecipients = !includeRecipients }
                CheckLine("Trusted signers (${vault.signers.size})", includeSigners) { includeSigners = !includeSigners }
                val anything = chosen.isNotEmpty() || (includeRecipients && vault.recipients.isNotEmpty()) ||
                    (includeSigners && vault.signers.isNotEmpty())
                Button(onClick = { stage = SendStage.SCAN }, enabled = anything, modifier = Modifier.fillMaxWidth()) {
                    Text("Scan the receiving device")
                }
                OutlinedTextField(
                    value = recipientText,
                    onValueChange = { recipientText = it },
                    label = { Text("…or paste its key (age1pq1…)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(onClick = { useRecipient(recipientText) }, enabled = anything && recipientText.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                    Text("Use pasted key")
                }
            }

            SendStage.CONFIRM -> {
                Text("Does the receiving device show this code?", style = MaterialTheme.typography.bodyMedium)
                Text(
                    KeyTransfer.confirmationCode(recipientText),
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 24.sp,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
                if (!recipientText.startsWith("age1pq1")) {
                    Text(
                        "This receiving key isn't quantum-safe. Quantum-safe identities sent to it lose that protection in transit.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Button(onClick = {
                    confirmIdentity("Send keys") {
                        stage = SendStage.WORKING
                        val ids: List<StoredIdentity> = movable.filter { it.id in chosen }
                        val recips = if (includeRecipients) vault.recipients.toList() else emptyList()
                        val signers = if (includeSigners) vault.signers.toList() else emptyList()
                        val to = target!!
                        scope.launch {
                            try {
                                val bytes = withContext(Dispatchers.Default) {
                                    KeyTransfer.seal(KeyPortability.buildBundle(ids, recips, signers), to)
                                }
                                sealed = bytes
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
                                        error = e.message ?: "Couldn't reach the other phone."
                                        stage = SendStage.DONE
                                    }
                                }
                            } catch (e: Exception) {
                                error = e.message ?: "Couldn't build the transfer."
                                stage = SendStage.CONFIRM
                            }
                        }
                    }
                }, modifier = Modifier.fillMaxWidth()) { Text("It matches, send") }
                OutlinedButton(onClick = { stage = SendStage.PICK; target = null }, modifier = Modifier.fillMaxWidth()) {
                    Text("It doesn't match")
                }
            }

            SendStage.WORKING -> {
                CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
                if (invite != null) Text("Sending to the other phone…", modifier = Modifier.align(Alignment.CenterHorizontally))
            }

            SendStage.SENT -> {
                Text("Sent ✓", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
                Text(
                    "The other phone has the keys. Check what it lists and tap Import there.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Done") }
            }

            SendStage.DONE -> {
                val bytes = sealed!!
                Text(
                    if (invite != null) "Couldn't send directly, so here's the file instead" else "Transfer ready",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
                Text(
                    "Move it to the other device any way you like: only that receive session can open it. " +
                        "Delete it from the middle once it's imported.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(onClick = {
                    vault.autoLockSuppressed = true
                    save.launch("agepony-keys-${LocalDate.now()}.age")
                }, modifier = Modifier.fillMaxWidth()) { Text(if (savedUri == null) "Save file…" else "Saved ✓ Save again…") }
                savedUri?.let { uri ->
                    OutlinedButton(onClick = { ShareOut.file(context, uri, "agepony-keys.age", "Send transfer") }, modifier = Modifier.fillMaxWidth()) {
                        Text("Share the saved file…")
                    }
                }
                if (bytes.size < 64 * 1024) {
                    OutlinedButton(onClick = { ShareOut.text(context, Armor.encode(bytes), "Send transfer as text") }, modifier = Modifier.fillMaxWidth()) {
                        Text("Share as text…")
                    }
                }
                TextButton(onClick = onBack) { Text("Done") }
            }

            SendStage.SCAN -> Unit
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
internal fun CheckLine(label: String, checked: Boolean, onToggle: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = { onToggle() })
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
}
