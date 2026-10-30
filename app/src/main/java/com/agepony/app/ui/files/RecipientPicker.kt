package com.agepony.app.ui.files

import com.agepony.app.vault.ShownMessageException
import com.agepony.app.vault.DefaultKeyNames
import com.agepony.app.ui.UserMessage
import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.R
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.RecipientImport
import com.agepony.app.vault.StoredRecipient
import com.agepony.app.vault.Wordlist
import com.agepony.app.vault.Vault
import com.agepony.app.vault.isSigningOnly
import com.agepony.app.vault.toAgeRecipient
import com.agepony.core.crypto.Diceware
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.HybridRecipient
import com.agepony.core.recipients.MIN_RSA_RECIPIENT_BITS
import com.agepony.core.recipients.P256Recipient
import com.agepony.core.recipients.TagRecipient
import com.agepony.core.recipients.SSHEd25519Recipient
import com.agepony.core.recipients.SSHRSARecipient
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.ssh.OpenSSHPublicKey

import java.util.UUID
import androidx.compose.foundation.layout.imePadding
import com.agepony.app.ui.components.CheckRow
import com.agepony.app.ui.components.ChoiceField
import com.agepony.app.ui.components.OneLineValue
import com.agepony.app.ui.components.QuietAction
import com.agepony.app.ui.components.SecondaryAction
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.SwitchRow

//
// Multi-select recipient picker for the encrypt flow (Android counterpart of
// iOS's RecipientPickerView): encrypt-to-self identities, saved recipients,
// ad-hoc pasted recipients, plus a scrypt "passphrase only" mode that replaces
// recipient selection. Returns hydrated AgeRecipients (and an optional
// passphrase) to the caller.
//
// The picker comes in two shapes. [RecipientPickerContent] draws the rows into
// whatever column the caller is already scrolling — that is how the encrypt
// screen shows recipients inline instead of pushing a second full screen
// (GitHub issue #2: "it is much more convenient to do all this in ONE window").
// [RecipientPicker] is the standalone, self-scrolling version the Text tab uses.
//
// Selection state lives in [RecipientSelection] rather than inside the composable,
// so a caller can collapse and reopen the picker — or encrypt and come back for
// the next file — without the choices resetting.
//
// Note: post-quantum recipients cannot be combined with classical ones (age's
// labels rule, enforced in Age.encrypt). Mixing them here surfaces as an encrypt
// error; disabling the mismatched rows in-picker is a queued UX refinement.
//

internal class AdHocRecipient(
    val label: String,
    val recipient: AgeRecipient,
    /** The text the user pasted, kept so the entry can be saved to the vault with a name. */
    val raw: String,
) {
    val key: String = label + System.nanoTime()
}

/**
 * Everything the picker lets the user choose, hoisted out of the composable so it survives the
 * picker being collapsed, and so the encrypt flow can carry one selection across several files.
 */
internal class RecipientSelection(
    initialUseScrypt: Boolean,
    initialPassphrase: String,
    preselectIdentityId: String?,
) {
    val identityIds = mutableStateListOf<String>()
    val recipientIds = mutableStateListOf<String>()
    val adHoc = mutableStateListOf<AdHocRecipient>()

    var useScrypt by mutableStateOf(initialUseScrypt)
    var passphrase by mutableStateOf(initialPassphrase)
    var passphraseConfirm by mutableStateOf(initialPassphrase)

    init {
        if (preselectIdentityId != null) identityIds.add(preselectIdentityId)
    }

    /**
     * Hydrate the chosen identities, saved recipients and one-time keys into age recipients.
     * A selected entry that can't be loaded is an error, not a silent drop: quietly skipping it
     * would encrypt the file to fewer people than the user ticked (audit follow-up to L-4).
     */
    fun buildRecipients(context: Context, vault: Vault): List<AgeRecipient> {
        val failed = mutableListOf<String>()
        val out = buildList {
            vault.identities.filter { identityIds.contains(it.id) }.forEach {
                try { add(it.toAgeRecipient()) } catch (e: Exception) { failed.add(it.name) }
            }
            vault.recipients.filter { recipientIds.contains(it.id) }.forEach {
                try { add(it.toAgeRecipient()) } catch (e: Exception) { failed.add(it.name) }
            }
            adHoc.forEach { add(it.recipient) }
        }
        if (failed.isNotEmpty()) {
            throw ShownMessageException(
                context.getString(R.string.files_picker_cant_encrypt_to, failed.joinToString(", ")),
            )
        }
        return out
    }

    val selectedCount: Int get() = identityIds.size + recipientIds.size + adHoc.size

    /** Forget every choice, including the typed passphrase. */
    fun clear() {
        identityIds.clear()
        recipientIds.clear()
        adHoc.clear()
        passphrase = ""
        passphraseConfirm = ""
    }
}

/**
 * A selection seeded from the user's remembered preferences: passphrase mode, plus the active
 * identity when "encrypt to self" is on.
 *
 * [seedSessionPassphrase] is for the file encrypt flow, which is the only caller that should
 * inherit a passphrase held from earlier in the session; the Text tab starts from empty so a
 * passphrase typed for a file never turns up prefilled somewhere else.
 */
@Composable
internal fun rememberRecipientSelection(
    vault: Vault,
    seedSessionPassphrase: Boolean = false,
): RecipientSelection = remember {
    // Only an identity that can actually receive a file is worth preselecting. Signing-only and
    // hardware identities can be active (Settings lets any of them be), but toAgeRecipient throws
    // for them, so preselecting one would tick nothing visible and then quietly hydrate to no
    // recipients at all.
    val preselect = if (vault.encryptToSelfDefault) {
        val encryptable = vault.identities.filter { !it.type.isSigningOnly }
        val active = vault.activeIdentityId
        // Only the identity the user made active. Falling back to "the first one" could tick a
        // key that arrived by transfer or paper restore and was never chosen (audit M-6).
        encryptable.firstOrNull { it.id == active }?.id
    } else {
        null
    }
    RecipientSelection(
        initialUseScrypt = vault.passphraseModeDefault,
        initialPassphrase = if (seedSessionPassphrase) vault.sessionPassphrase.orEmpty() else "",
        preselectIdentityId = preselect,
    )
}

/**
 * Standalone picker: its own selection, its own scrolling. Used by the Text tab, whose app bar
 * carries the "Choose recipients" title and the back arrow.
 */
@Composable
fun RecipientPicker(
    vault: Vault,
    modifier: Modifier = Modifier,
    onCancel: () -> Unit,
    onConfirm: (recipients: List<AgeRecipient>, passphrase: String?) -> Unit,
) {
    val selection = rememberRecipientSelection(vault)
    RecipientPickerContent(
        vault = vault,
        selection = selection,
        modifier = modifier
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        showTitle = false,
        onCancel = onCancel,
        onConfirm = onConfirm,
    )
}

/**
 * The picker rows themselves. Adds no scrolling of its own, so it can be dropped into a column the
 * caller already scrolls; nesting two vertical scrolls would leave the inner one unable to move.
 */
@Composable
internal fun RecipientPickerContent(
    vault: Vault,
    selection: RecipientSelection,
    modifier: Modifier = Modifier,
    showTitle: Boolean = true,
    /** Whether confirming a passphrase should hold it for the rest of the session. */
    rememberPassphrase: Boolean = false,
    onCancel: () -> Unit,
    onConfirm: (recipients: List<AgeRecipient>, passphrase: String?) -> Unit,
) {
    var pasteText by remember { mutableStateOf("") }
    var pasteError by remember { mutableStateOf<String?>(null) }
    var confirmError by remember { mutableStateOf<String?>(null) }

    var savingKey by remember { mutableStateOf<String?>(null) }
    var saveName by remember { mutableStateOf("") }
    var saveError by remember { mutableStateOf<String?>(null) }
    var suggestion by remember { mutableStateOf<String?>(null) }
    var suggestionWords by remember { mutableStateOf(Diceware.DEFAULT_WORD_COUNT) }
    val context = LocalContext.current

    val selectedCount = selection.selectedCount
    val scryptValid = selection.passphrase.isNotEmpty() &&
        selection.passphrase == selection.passphraseConfirm
    val canConfirm = if (selection.useScrypt) scryptValid else selectedCount > 0

    Column(
        modifier,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (showTitle) {
            SectionHeader(stringResource(R.string.files_choose_recipients))
        }

        // Remembered: whoever always encrypts to a passphrase should not re-flip this
        // on every file (issue #2, item 2).
        SwitchRow(
            title = stringResource(R.string.files_passphrase_only_scrypt),
            checked = selection.useScrypt,
            onCheckedChange = { selection.useScrypt = it; vault.passphraseModeDefault = it },
        )

        if (selection.useScrypt) {
            OutlinedTextField(
                value = selection.passphrase,
                onValueChange = { selection.passphrase = it },
                label = { Text(stringResource(R.string.files_passphrase)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = selection.passphraseConfirm,
                onValueChange = { selection.passphraseConfirm = it },
                label = { Text(stringResource(R.string.files_picker_confirm_passphrase)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            if (selection.passphraseConfirm.isNotEmpty() &&
                selection.passphrase != selection.passphraseConfirm
            ) {
                ErrorText(stringResource(R.string.files_picker_mismatch))
            }

            // Diceware suggestion. The phrase is shown first and only fills the fields when the
            // user accepts it, so there is a moment to write it down before it becomes the key to
            // a file. Hidden entirely when the word list asset is missing: a shorter fallback list
            // would quietly weaken every passphrase it generated.
            val wordlist = remember { Wordlist.effLong(context) }
            if (wordlist.isNotEmpty()) {
                if (suggestion == null) {
                    TextButton(onClick = { suggestion = Diceware.generate(wordlist, suggestionWords) }) {
                        Text(stringResource(R.string.files_picker_suggest))
                    }
                } else {
                    // The phrase is key material, so monospace; the accent color is for actions only.
                    Text(
                        suggestion!!,
                        style = MaterialTheme.typography.titleMedium,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        pluralStringResource(
                            R.plurals.files_picker_suggestion_detail,
                            suggestionWords,
                            suggestionWords,
                            Diceware.entropyBits(wordlist.size, suggestionWords).toInt(),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    // A word-count menu and two plain actions instead of four buttons in one row,
                    // which long translated labels would squeeze (5.1.0, U4).
                    ChoiceField(
                        label = stringResource(R.string.files_picker_word_count),
                        selected = suggestionWords,
                        options = (Diceware.MIN_WORD_COUNT..Diceware.MAX_WORD_COUNT).toList(),
                        optionLabel = { it.toString() },
                        onSelect = { words ->
                            suggestionWords = words
                            suggestion = Diceware.generate(wordlist, words)
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    TextButton(
                        onClick = { suggestion = Diceware.generate(wordlist, suggestionWords) }
                    ) { Text(stringResource(R.string.files_picker_new_suggestion)) }
                    SecondaryAction(
                        stringResource(R.string.files_picker_use_it),
                        onClick = {
                            selection.passphrase = suggestion!!
                            selection.passphraseConfirm = suggestion!!
                            suggestion = null
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
            val workFactor = vault.scryptWorkFactor
            val scryptMb = FileEncryptor.scryptMemoryBytes(workFactor) shr 20
            Text(
                stringResource(R.string.files_picker_scrypt_detail, workFactor, scryptMb),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (!FileEncryptor.scryptFitsInMemory(workFactor)) {
                Text(
                    stringResource(R.string.files_picker_scrypt_low_memory),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        } else {
            // Encrypt to self
            SectionHeader(stringResource(R.string.files_picker_section_self))
            val encryptableIdentities = vault.identities.filter { !it.type.isSigningOnly }
            if (encryptableIdentities.isEmpty()) {
                Text(
                    stringResource(R.string.files_picker_no_identities),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                encryptableIdentities.forEach { identity ->
                    // Name, type and short key, so two keys with one name differ (5.1.0 item 3).
                    CheckRow(
                        checked = selection.identityIds.contains(identity.id),
                        title = identity.name,
                        subtitle = KeyPickerText.subtitle(context, identity),
                        onCheckedChange = { toggle(selection.identityIds, identity.id) },
                    )
                }
            }

            // Saved recipients
            if (vault.recipients.isNotEmpty()) {
                SectionHeader(stringResource(R.string.files_picker_section_saved))
                vault.recipients.forEach { recipient ->
                    // An ssh-rsa key under 2048 bits can't be encrypted to any more (audit L-4),
                    // so it's shown but can't be ticked.
                    val tooSmall = RecipientImport.isRsaBelowMinimum(recipient.type, recipient.publicKeyB64)
                    CheckRow(
                        checked = selection.recipientIds.contains(recipient.id),
                        title = recipient.name,
                        subtitle = if (tooSmall) {
                            RecipientImport.rsaTooSmallMessage(
                                LocalContext.current,
                                RecipientImport.rsaBits(recipient.type, recipient.publicKeyB64)
                            )
                        } else {
                            KeyPickerText.subtitle(context, recipient)
                        },
                        enabled = !tooSmall,
                        onCheckedChange = { toggle(selection.recipientIds, recipient.id) },
                    )
                }
            }

            // Ad-hoc
            SectionHeader(stringResource(R.string.files_picker_section_one_time))
            selection.adHoc.forEach { ah ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    // An age key is shown as the key (monospace); an SSH key's label is words.
                    if (ah.raw.startsWith("age1")) {
                        OneLineValue(ah.label, color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.weight(1f))
                    } else {
                        Text(
                            ah.label,
                            style = MaterialTheme.typography.bodyMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                    }
                    if (savingKey != ah.key) {
                        TextButton(onClick = { savingKey = ah.key; saveName = ""; saveError = null }) {
                            Text(stringResource(R.string.files_picker_save))
                        }
                    }
                    TextButton(onClick = { selection.adHoc.removeAll { it.key == ah.key } }) { Text(stringResource(R.string.files_picker_remove)) }
                }

                // Promote a one-time key to a named recipient, so the next encrypt shows a person
                // rather than a base64 fragment. Same vault entry the Recipients tab would create.
                if (savingKey == ah.key) {
                    OutlinedTextField(
                        value = saveName,
                        onValueChange = { saveName = it; saveError = null },
                        label = { Text(stringResource(R.string.files_picker_save_name)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (saveError != null) ErrorText(saveError!!)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextButton(onClick = { savingKey = null }) { Text(stringResource(R.string.action_cancel)) }
                        // Outlined: the picker's own Use button below is the filled one.
                        OutlinedButton(
                            onClick = {
                                try {
                                    val candidate = RecipientImport.parsePastedText(ah.raw, DefaultKeyNames.from(context))
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
                                    selection.recipientIds.add(vault.recipients.last().id)
                                    selection.adHoc.removeAll { it.key == ah.key }
                                    savingKey = null
                                } catch (e: Exception) {
                                    saveError = UserMessage.text(context, e, R.string.files_picker_save_failed)
                                }
                            },
                            enabled = saveName.isNotBlank(),
                        ) { Text(stringResource(R.string.files_picker_save_to_recipients)) }
                    }
                }
            }
            OutlinedTextField(
                value = pasteText,
                onValueChange = { pasteText = it; pasteError = null },
                label = { Text(stringResource(R.string.files_picker_paste_label)) },
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
            )
            if (pasteError != null) ErrorText(pasteError!!)
            TextButton(
                onClick = {
                    try {
                        selection.adHoc.add(parseAdHoc(context, pasteText))
                        pasteText = ""
                        pasteError = null
                    } catch (e: Exception) {
                        pasteError = UserMessage.text(context, e, R.string.files_picker_parse_failed)
                    }
                },
                enabled = pasteText.isNotBlank(),
            ) { Text(stringResource(R.string.files_picker_add_one_time)) }
        }

        if (confirmError != null) ErrorText(confirmError!!)
        ListDivider()
        // Stacked, full width, so long translated labels never squeeze (5.1.0, U4).
        Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = {
                    if (selection.useScrypt) {
                        // Held in memory until the vault locks, so the next file in a run is not
                        // asked for the same passphrase again (issue #2, item 3).
                        if (rememberPassphrase) vault.rememberSessionPassphrase(selection.passphrase)
                        onConfirm(emptyList(), selection.passphrase)
                    } else {
                        // A recipient choice replaces passphrase mode; don't leave a stale
                        // passphrase behind for the next file to silently pick up.
                        if (rememberPassphrase) vault.forgetSessionPassphrase()
                        val built = try {
                            selection.buildRecipients(context, vault)
                        } catch (e: Exception) {
                            confirmError = UserMessage.text(context, e, R.string.files_picker_load_failed)
                            null
                        }
                        if (built != null) {
                            confirmError = null
                            onConfirm(built, null)
                        }
                    }
                },
                enabled = canConfirm,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    when {
                        selection.useScrypt -> stringResource(R.string.files_picker_use_passphrase)
                        selectedCount == 0 -> stringResource(R.string.files_picker_pick_recipient)
                        else -> pluralStringResource(R.plurals.files_picker_use_recipients, selectedCount, selectedCount)
                    }
                )
            }
            QuietAction(stringResource(R.string.action_cancel), onClick = onCancel)
        }
    }
}

private fun toggle(set: MutableList<String>, id: String) {
    if (set.contains(id)) set.remove(id) else set.add(id)
}

private fun parseAdHoc(context: Context, raw: String): AdHocRecipient {
    val t = raw.trim()
    if (t.isEmpty()) throw ShownMessageException(context.getString(R.string.files_picker_nothing_to_add))
    // Longer age1 prefixes first: they all share "age1".
    if (TagRecipient.isTagRecipient(t)) {
        val r = TagRecipient(t)
        return AdHocRecipient(shorten(t), r, t)
    }
    if (t.startsWith("age1yubikey")) {
        val r = P256Recipient(t)
        return AdHocRecipient(shorten(t), r, t)
    }
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
                AdHocRecipient(
                    context.getString(R.string.files_picker_ssh_ed25519_one_time),
                    SSHEd25519Recipient(parsed.publicKey),
                    t,
                )

            is OpenSSHPublicKey.RSA -> {
                val r = SSHRSARecipient(parsed)
                if (r.isBelowMinimumSize) {
                    throw ShownMessageException(
                        context.getString(
                            R.string.files_picker_rsa_too_small,
                            parsed.modulus.bitLength(),
                            MIN_RSA_RECIPIENT_BITS,
                        )
                    )
                }
                AdHocRecipient(context.getString(R.string.files_picker_ssh_rsa_one_time), r, t)
            }
        }
    }
    throw ShownMessageException(context.getString(R.string.files_picker_unrecognised))
}

private fun shorten(s: String): String =
    if (s.length <= 28) s else "${s.take(14)}…${s.takeLast(10)}"
