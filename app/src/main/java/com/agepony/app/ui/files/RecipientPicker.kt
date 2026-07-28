package com.agepony.app.ui.files

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.RecipientImport
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.StoredRecipient
import com.agepony.app.vault.Wordlist
import com.agepony.app.vault.StoredRecipientType
import com.agepony.app.vault.Vault
import com.agepony.app.vault.isSigningOnly
import com.agepony.app.vault.toAgeRecipient
import com.agepony.core.crypto.Diceware
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.HybridRecipient
import com.agepony.core.recipients.SSHEd25519Recipient
import com.agepony.core.recipients.SSHRSARecipient
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.ssh.OpenSSHPublicKey

import java.util.UUID

//
// Multi-select recipient picker for the encrypt flow (Android counterpart of
// iOS's RecipientPickerView): encrypt-to-self identities, saved recipients,
// ad-hoc pasted recipients, plus a scrypt "passphrase only" mode that replaces
// recipient selection. Returns hydrated AgeRecipients (and an optional
// passphrase) to the caller.
//
// Note: post-quantum recipients cannot be combined with classical ones (age's
// labels rule, enforced in Age.encrypt). Mixing them here surfaces as an encrypt
// error; disabling the mismatched rows in-picker is a queued UX refinement.
//

private class AdHocRecipient(
    val label: String,
    val recipient: AgeRecipient,
    /** The text the user pasted, kept so the entry can be saved to the vault with a name. */
    val raw: String,
) {
    val key: String = label + System.nanoTime()
}

@Composable
fun RecipientPicker(
    vault: Vault,
    modifier: Modifier = Modifier,
    onCancel: () -> Unit,
    onConfirm: (recipients: List<AgeRecipient>, passphrase: String?) -> Unit,
) {
    val selectedIdentityIds = remember {
        mutableStateListOf<String>().apply {
            if (vault.encryptToSelfDefault) {
                val active = vault.activeIdentityId ?: vault.identities.firstOrNull()?.id
                if (active != null && vault.identities.any { it.id == active }) add(active)
            }
        }
    }
    val selectedRecipientIds = remember { mutableStateListOf<String>() }
    val adHoc = remember { mutableStateListOf<AdHocRecipient>() }

    var pasteText by remember { mutableStateOf("") }
    var pasteError by remember { mutableStateOf<String?>(null) }

    var useScrypt by remember { mutableStateOf(false) }
    var savingKey by remember { mutableStateOf<String?>(null) }
    var saveName by remember { mutableStateOf("") }
    var saveError by remember { mutableStateOf<String?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var passphraseConfirm by remember { mutableStateOf("") }
    var suggestion by remember { mutableStateOf<String?>(null) }
    var suggestionWords by remember { mutableStateOf(Diceware.DEFAULT_WORD_COUNT) }
    val context = LocalContext.current

    val selectedCount = selectedIdentityIds.size + selectedRecipientIds.size + adHoc.size
    val scryptValid = passphrase.isNotEmpty() && passphrase == passphraseConfirm
    val canConfirm = if (useScrypt) scryptValid else selectedCount > 0

    Column(
        modifier
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            "Choose recipients",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.primary,
        )

        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = useScrypt, onCheckedChange = { useScrypt = it })
            Text("Passphrase only (scrypt)", modifier = Modifier.padding(start = 12.dp))
        }

        if (useScrypt) {
            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text("Passphrase") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = passphraseConfirm,
                onValueChange = { passphraseConfirm = it },
                label = { Text("Confirm passphrase") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            if (passphraseConfirm.isNotEmpty() && passphrase != passphraseConfirm) {
                Text(
                    "Passphrases don't match.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            // Diceware suggestion. The phrase is shown first and only fills the fields when the
            // user accepts it, so there is a moment to write it down before it becomes the key to
            // a file. Hidden entirely when the word list asset is missing: a shorter fallback list
            // would quietly weaken every passphrase it generated.
            val wordlist = remember { Wordlist.effLong(context) }
            if (wordlist.isNotEmpty()) {
                if (suggestion == null) {
                    TextButton(onClick = { suggestion = Diceware.generate(wordlist, suggestionWords) }) {
                        Text("Suggest a passphrase")
                    }
                } else {
                    Text(
                        suggestion!!,
                        style = MaterialTheme.typography.titleMedium,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        suggestionWords.toString() + " random words, about " +
                            Diceware.entropyBits(wordlist.size, suggestionWords).toInt() +
                            " bits. Write it down before you use it: nothing can recover a file " +
                            "if this is lost.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextButton(
                            onClick = {
                                suggestionWords -= 1
                                suggestion = Diceware.generate(wordlist, suggestionWords)
                            },
                            enabled = suggestionWords > Diceware.MIN_WORD_COUNT,
                        ) { Text("Shorter") }
                        TextButton(
                            onClick = {
                                suggestionWords += 1
                                suggestion = Diceware.generate(wordlist, suggestionWords)
                            },
                            enabled = suggestionWords < Diceware.MAX_WORD_COUNT,
                        ) { Text("Longer") }
                        TextButton(
                            onClick = { suggestion = Diceware.generate(wordlist, suggestionWords) }
                        ) { Text("Again") }
                        Button(onClick = {
                            passphrase = suggestion!!
                            passphraseConfirm = suggestion!!
                            suggestion = null
                        }) { Text("Use it") }
                    }
                }
            }
            val workFactor = vault.scryptWorkFactor
            val scryptMb = FileEncryptor.scryptMemoryBytes(workFactor) shr 20
            Text(
                "Anyone with the passphrase can decrypt; nobody else can. There is no recovery " +
                    "if you forget it. Work factor 2^" + workFactor + ", which needs about " +
                    scryptMb + " MB of memory while the key is derived, whatever the file size " +
                    "(change it in Settings).",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (!FileEncryptor.scryptFitsInMemory(workFactor)) {
                Text(
                    "This device does not have that much free right now. Lower the work factor in " +
                        "Settings, or encrypt to a recipient key instead.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        } else {
            // Encrypt to self
            SectionHeader("Encrypt to self")
            val encryptableIdentities = vault.identities.filter { !it.type.isSigningOnly }
            if (encryptableIdentities.isEmpty()) {
                Text(
                    "You have no identities in this vault.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                encryptableIdentities.forEach { identity ->
                    CheckRow(
                        checked = selectedIdentityIds.contains(identity.id),
                        title = identity.name,
                        subtitle = identityTypeLabel(identity.type),
                        onToggle = { toggle(selectedIdentityIds, identity.id) },
                    )
                }
            }

            // Saved recipients
            if (vault.recipients.isNotEmpty()) {
                SectionHeader("Saved recipients")
                vault.recipients.forEach { recipient ->
                    CheckRow(
                        checked = selectedRecipientIds.contains(recipient.id),
                        title = recipient.name,
                        subtitle = recipientTypeLabel(recipient.type),
                        onToggle = { toggle(selectedRecipientIds, recipient.id) },
                    )
                }
            }

            // Ad-hoc
            SectionHeader("One-time recipient")
            adHoc.forEach { ah ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        ah.label,
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    if (savingKey != ah.key) {
                        TextButton(onClick = { savingKey = ah.key; saveName = ""; saveError = null }) {
                            Text("Save")
                        }
                    }
                    TextButton(onClick = { adHoc.removeAll { it.key == ah.key } }) { Text("Remove") }
                }

                // Promote a one-time key to a named recipient, so the next encrypt shows a person
                // rather than a base64 fragment. Same vault entry the Recipients tab would create.
                if (savingKey == ah.key) {
                    OutlinedTextField(
                        value = saveName,
                        onValueChange = { saveName = it; saveError = null },
                        label = { Text("Name for this recipient") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (saveError != null) {
                        Text(
                            saveError!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextButton(onClick = { savingKey = null }) { Text("Cancel") }
                        Button(
                            onClick = {
                                try {
                                    val candidate = RecipientImport.parsePastedText(ah.raw)
                                    vault.addRecipient(
                                        StoredRecipient(
                                            id = UUID.randomUUID().toString(),
                                            name = saveName.trim().ifBlank { candidate.defaultName },
                                            type = candidate.type,
                                            publicKeyB64 = candidate.publicKeyB64,
                                            sshComment = candidate.sshComment,
                                            source = candidate.source,
                                            sourceMetadata = candidate.sourceMetadata,
                                            createdAt = System.currentTimeMillis(),
                                        )
                                    )
                                    // It is a saved recipient now, so drop the one-time copy and
                                    // select the saved one in its place.
                                    selectedRecipientIds.add(vault.recipients.last().id)
                                    adHoc.removeAll { it.key == ah.key }
                                    savingKey = null
                                } catch (e: Exception) {
                                    saveError = e.message ?: "Couldn't save this recipient."
                                }
                            },
                            enabled = saveName.isNotBlank(),
                        ) { Text("Save to recipients") }
                    }
                }
            }
            OutlinedTextField(
                value = pasteText,
                onValueChange = { pasteText = it; pasteError = null },
                label = { Text("Paste age1… / age1pq… or ssh-* AAAA… (one-time)") },
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
            )
            if (pasteError != null) {
                Text(pasteError!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            TextButton(
                onClick = {
                    try {
                        adHoc.add(parseAdHoc(pasteText))
                        pasteText = ""
                        pasteError = null
                    } catch (e: Exception) {
                        pasteError = e.message ?: "Couldn't parse that."
                    }
                },
                enabled = pasteText.isNotBlank(),
            ) { Text("Add one-time recipient") }
        }

        HorizontalDivider()
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = {
                    if (useScrypt) {
                        onConfirm(emptyList(), passphrase)
                    } else {
                        val built = buildList {
                            vault.identities.filter { selectedIdentityIds.contains(it.id) }
                                .forEach { runCatching { add(it.toAgeRecipient()) } }
                            vault.recipients.filter { selectedRecipientIds.contains(it.id) }
                                .forEach { runCatching { add(it.toAgeRecipient()) } }
                            adHoc.forEach { add(it.recipient) }
                        }
                        onConfirm(built, null)
                    }
                },
                enabled = canConfirm,
                modifier = Modifier.weight(1f),
            ) {
                Text(
                    when {
                        useScrypt -> "Use passphrase"
                        selectedCount == 0 -> "Pick a recipient"
                        selectedCount == 1 -> "Use 1 recipient"
                        else -> "Use $selectedCount recipients"
                    }
                )
            }
            OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) { Text("Cancel") }
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 4.dp),
    )
}

@Composable
private fun CheckRow(checked: Boolean, title: String, subtitle: String, onToggle: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle)
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = { onToggle() })
        Column(Modifier.padding(start = 8.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private fun toggle(set: MutableList<String>, id: String) {
    if (set.contains(id)) set.remove(id) else set.add(id)
}

private fun parseAdHoc(raw: String): AdHocRecipient {
    val t = raw.trim()
    if (t.isEmpty()) throw IllegalArgumentException("Nothing to add.")
    // "age1pq" before "age1": post-quantum recipients share the "age1" prefix.
    if (t.startsWith("age1pq")) {
        val r = HybridRecipient(t)
        return AdHocRecipient(shorten(t), r, t)
    }
    if (t.startsWith("age1")) {
        val r = X25519Recipient(t)
        return AdHocRecipient(shorten(t), r, t)
    }
    if (t.startsWith("ssh-ed25519 ") || t.startsWith("ssh-rsa ")) {
        return when (val parsed = OpenSSHPublicKey.parse(t)) {
            is OpenSSHPublicKey.Ed25519 ->
                AdHocRecipient("SSH Ed25519 (one-time)", SSHEd25519Recipient(parsed.publicKey), t)

            is OpenSSHPublicKey.RSA ->
                AdHocRecipient("SSH RSA (one-time)", SSHRSARecipient(parsed), t)
        }
    }
    throw IllegalArgumentException("Expected an age1… / age1pq… recipient or an ssh-ed25519 / ssh-rsa line.")
}

private fun shorten(s: String): String =
    if (s.length <= 28) s else "${s.take(14)}…${s.takeLast(10)}"

private fun identityTypeLabel(t: StoredIdentityType): String = when (t) {
    StoredIdentityType.X25519 -> "age X25519"
    StoredIdentityType.MLKEM768X25519 -> "Quantum-safe (ML-KEM-768 + X25519)"
    StoredIdentityType.SSH_ED25519 -> "SSH Ed25519"
    StoredIdentityType.SSH_RSA -> "SSH RSA"
    StoredIdentityType.HARDWARE_KEY -> "Hardware Key (P-256)"
    StoredIdentityType.SK_ED25519 -> "Security Key (Ed25519)"
    StoredIdentityType.SK_ECDSA_P256 -> "Security Key (P-256)"
}

private fun recipientTypeLabel(t: StoredRecipientType): String = when (t) {
    StoredRecipientType.X25519 -> "age X25519"
    StoredRecipientType.MLKEM768X25519 -> "Quantum-safe (ML-KEM-768 + X25519)"
    StoredRecipientType.SSH_ED25519 -> "SSH Ed25519"
    StoredRecipientType.SSH_RSA -> "SSH RSA"
}
