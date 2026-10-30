package com.agepony.app.ui.notes

import com.agepony.app.ui.UserMessage
import android.text.format.DateUtils
import android.util.Base64
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.StoredNote
import com.agepony.app.vault.Vault
import com.agepony.app.vault.WrongPassphraseException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import androidx.compose.foundation.layout.imePadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.EmptyState
import com.agepony.app.ui.components.ErrorText
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.QuietAction
import com.agepony.app.ui.components.SwitchRow

//
// Notes tab (Phase 2d-1). Android counterpart of iOS's Notes feature. Each note
// has a plaintext title (held inside the encrypted vault file, so the list works
// without prompting) and a body sealed with its OWN passphrase via age + scrypt
// (work factor 2^18 — same as the vault default and the age CLI). Re-entering a
// note always starts locked; the passphrase and decrypted body are never cached.
//

private enum class NotesMode { LIST, CREATE, DETAIL }

@Composable
fun NotesScreen(vault: Vault, modifier: Modifier = Modifier) {
    var mode by rememberSaveable { mutableStateOf(NotesMode.LIST) }
    var selectedId by rememberSaveable { mutableStateOf<String?>(null) }

    when (mode) {
        NotesMode.LIST -> NoteList(
            vault = vault,
            modifier = modifier,
            onCreate = { mode = NotesMode.CREATE },
            onOpen = { selectedId = it; mode = NotesMode.DETAIL },
        )

        NotesMode.CREATE -> CreateNote(
            vault = vault,
            modifier = modifier,
            onDone = { mode = NotesMode.LIST },
            onCancel = { mode = NotesMode.LIST },
        )

        NotesMode.DETAIL -> NoteDetail(
            vault = vault,
            noteId = selectedId.orEmpty(),
            modifier = modifier,
            onBack = { mode = NotesMode.LIST },
        )
    }
}

// MARK: - List

@Composable
private fun NoteList(
    vault: Vault,
    modifier: Modifier,
    onCreate: () -> Unit,
    onOpen: (String) -> Unit,
) {
    AgeScreen(
        title = stringResource(R.string.app_tab_notes),
        modifier = modifier,
        actions = {
            IconButton(onClick = onCreate) {
                Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.notes_new))
            }
        },
    ) { padding ->
    Column(Modifier.fillMaxSize().padding(padding)) {
        val notes = vault.notes.sortedByDescending { it.updatedAt }
        if (notes.isEmpty()) {
            EmptyState(
                title = stringResource(R.string.notes_empty_title),
                body = stringResource(R.string.notes_empty_body),
                actionLabel = stringResource(R.string.notes_new),
                onAction = onCreate,
            )
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(notes, key = { it.id }) { note ->
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .clickable { onOpen(note.id) }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                    ) {
                        Text(
                            note.title.ifBlank { stringResource(R.string.notes_untitled) },
                            style = MaterialTheme.typography.bodyLarge,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            stringResource(R.string.notes_edited, DateUtils.getRelativeTimeSpanString(note.updatedAt)),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    ListDivider()
                }
            }
        }
    }
    }
}

// MARK: - Create

@Composable
private fun CreateNote(
    vault: Vault,
    modifier: Modifier,
    onDone: () -> Unit,
    onCancel: () -> Unit,
) {
    // Note text and passphrases stay out of the saved-state Bundle, which the system can write to
    // disk (audit L-23). A draft lost to a process kill is the accepted cost.
    var title by remember { mutableStateOf("") }
    var body by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var show by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    val mismatch = confirm.isNotEmpty() && passphrase != confirm
    val canSave = !busy && passphrase.isNotEmpty() && passphrase == confirm

    AgeScreen(title = stringResource(R.string.notes_new), modifier = modifier, onBack = onCancel) { padding ->
    Column(
        Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = title,
            onValueChange = { title = it },
            label = { Text(stringResource(R.string.notes_create_title_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = body,
            onValueChange = { body = it },
            label = { Text(stringResource(R.string.notes_create_body_label)) },
            minLines = 6,
            modifier = Modifier.fillMaxWidth(),
        )
        PassphraseFields(
            passphrase = passphrase, onPassphrase = { passphrase = it; error = null },
            confirm = confirm, onConfirm = { confirm = it; error = null },
            show = show, onShow = { show = it }, mismatch = mismatch,
        )
        Text(
            stringResource(R.string.notes_passphrase_warning),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (error != null) ErrorText(error!!)
        // Stacked, full width, so long translated labels never squeeze (5.1.0, U4).
        Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = {
                    if (!canSave) return@Button
                    busy = true; error = null
                    val titleSnapshot = title.trim().ifBlank { context.getString(R.string.notes_untitled) }
                    val bodyBytes = body.toByteArray(Charsets.UTF_8)
                    val pass = passphrase
                    scope.launch {
                        try {
                            val cipher = withContext(Dispatchers.Default) {
                                FileEncryptor.encrypt(bodyBytes, emptyList(), pass, armor = false)
                            }
                            vault.addNote(
                                StoredNote(
                                    id = UUID.randomUUID().toString(),
                                    title = titleSnapshot,
                                    bodyCiphertextB64 = Base64.encodeToString(cipher, Base64.NO_WRAP),
                                    createdAt = System.currentTimeMillis(),
                                    updatedAt = System.currentTimeMillis(),
                                )
                            )
                            busy = false
                            onDone()
                        } catch (e: OutOfMemoryError) {
                            busy = false
                            error = context.getString(R.string.notes_oom_encrypt)
                        } catch (e: Exception) {
                            busy = false
                            error = UserMessage.text(context, e, R.string.notes_create_failed)
                        }
                    }
                },
                enabled = canSave,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(if (busy) R.string.notes_encrypting else R.string.notes_create)) }
            QuietAction(text = stringResource(R.string.action_cancel), onClick = onCancel, enabled = !busy)
        }
    }
    }
}

// MARK: - Detail (locked -> unlocked)

private enum class NotePhase { LOCKED, UNLOCKED }

@Composable
private fun NoteDetail(
    vault: Vault,
    noteId: String,
    modifier: Modifier,
    onBack: () -> Unit,
) {
    val note = vault.notes.firstOrNull { it.id == noteId }
    var phase by remember { mutableStateOf(NotePhase.LOCKED) }
    var passInput by remember { mutableStateOf("") } // not saveable (audit L-23)
    var show by rememberSaveable { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    var unlockedPass by remember { mutableStateOf("") }
    var editTitle by remember { mutableStateOf("") }
    var editBody by remember { mutableStateOf("") }
    var origTitle by remember { mutableStateOf("") }
    var origBody by remember { mutableStateOf("") }

    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var confirmDelete by remember { mutableStateOf(false) }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.note_delete_title)) },
            text = { Text(stringResource(R.string.note_delete_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    vault.deleteNote(noteId)
                    onBack()
                }) { Text(stringResource(R.string.action_delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }

    AgeScreen(
        title = note?.title?.ifBlank { stringResource(R.string.notes_untitled) } ?: stringResource(R.string.note_title),
        modifier = modifier,
        onBack = onBack,
    ) { padding ->
    Column(
        Modifier.fillMaxSize().padding(padding).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (note == null) {
            Text(stringResource(R.string.notes_not_found), style = MaterialTheme.typography.bodyLarge)
            return@Column
        }

        when (phase) {
            NotePhase.LOCKED -> {
                Text(
                    stringResource(R.string.notes_edited, DateUtils.getRelativeTimeSpanString(note.updatedAt)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = passInput,
                    onValueChange = { passInput = it; error = null },
                    label = { Text(stringResource(R.string.notes_passphrase)) },
                    singleLine = true,
                    visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                SwitchRow(title = stringResource(R.string.notes_show_passphrase), checked = show, onCheckedChange = { show = it })
                if (error != null) ErrorText(error!!)
                Button(
                    onClick = {
                        if (passInput.isEmpty() || working) return@Button
                        working = true; error = null
                        val pass = passInput
                        val cipher = Base64.decode(note.bodyCiphertextB64, Base64.NO_WRAP)
                        scope.launch {
                            try {
                                val plain = withContext(Dispatchers.Default) {
                                    FileEncryptor.decryptWithPassphrase(cipher, pass)
                                }
                                val text = String(plain, Charsets.UTF_8)
                                unlockedPass = pass
                                editTitle = note.title; origTitle = note.title
                                editBody = text; origBody = text
                                passInput = ""
                                working = false
                                phase = NotePhase.UNLOCKED
                            } catch (e: WrongPassphraseException) {
                                working = false; error = context.getString(R.string.notes_wrong_passphrase)
                            } catch (e: OutOfMemoryError) {
                                working = false; error = context.getString(R.string.notes_oom_decrypt)
                            } catch (e: Exception) {
                                working = false; error = UserMessage.text(context, e, R.string.notes_unlock_failed)
                            }
                        }
                    },
                    enabled = passInput.isNotEmpty() && !working,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(if (working) R.string.notes_decrypting else R.string.app_unlock)) }
                QuietAction(text = stringResource(R.string.notes_delete), onClick = { confirmDelete = true }, destructive = true)
            }

            NotePhase.UNLOCKED -> {
                val dirty = editTitle != origTitle || editBody != origBody
                OutlinedTextField(
                    value = editTitle,
                    onValueChange = { editTitle = it },
                    label = { Text(stringResource(R.string.notes_title_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = editBody,
                    onValueChange = { editBody = it },
                    label = { Text(stringResource(R.string.notes_body_label)) },
                    minLines = 8,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (error != null) ErrorText(error!!)
                // Stacked, full width, so long translated labels never squeeze (5.1.0, U4).
                Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Button(
                        onClick = {
                            if (!dirty || working) return@Button
                            working = true; error = null
                            val titleSnapshot = editTitle.trim().ifBlank { context.getString(R.string.notes_untitled) }
                            val bodyBytes = editBody.toByteArray(Charsets.UTF_8)
                            val pass = unlockedPass
                            scope.launch {
                                try {
                                    val cipher = withContext(Dispatchers.Default) {
                                        FileEncryptor.encrypt(bodyBytes, emptyList(), pass, armor = false)
                                    }
                                    val updated = StoredNote(
                                        id = note.id,
                                        title = titleSnapshot,
                                        bodyCiphertextB64 = Base64.encodeToString(cipher, Base64.NO_WRAP),
                                        createdAt = note.createdAt,
                                        updatedAt = System.currentTimeMillis(),
                                    )
                                    vault.deleteNote(note.id)
                                    vault.addNote(updated)
                                    origTitle = titleSnapshot; editTitle = titleSnapshot
                                    origBody = editBody
                                    working = false
                                } catch (e: OutOfMemoryError) {
                                    working = false; error = context.getString(R.string.notes_oom_save)
                                } catch (e: Exception) {
                                    working = false; error = UserMessage.text(context, e, R.string.notes_save_failed)
                                }
                            }
                        },
                        enabled = dirty && !working,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(stringResource(if (working) R.string.notes_encrypting else R.string.notes_save)) }
                    OutlinedButton(
                        onClick = {
                            unlockedPass = ""; editTitle = ""; editBody = ""; origTitle = ""; origBody = ""
                            passInput = ""; error = null
                            phase = NotePhase.LOCKED
                        },
                        enabled = !working,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(stringResource(R.string.notes_lock)) }
                }
                if (dirty) {
                    Text(stringResource(R.string.notes_unsaved), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
    }
}

// MARK: - Shared

@Composable
private fun PassphraseFields(
    passphrase: String, onPassphrase: (String) -> Unit,
    confirm: String, onConfirm: (String) -> Unit,
    show: Boolean, onShow: (Boolean) -> Unit,
    mismatch: Boolean,
) {
    val transform = if (show) VisualTransformation.None else PasswordVisualTransformation()
    OutlinedTextField(
        value = passphrase, onValueChange = onPassphrase,
        label = { Text(stringResource(R.string.notes_passphrase)) }, singleLine = true,
        visualTransformation = transform,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = confirm, onValueChange = onConfirm,
        label = { Text(stringResource(R.string.notes_confirm_passphrase)) }, singleLine = true,
        visualTransformation = transform,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth(),
    )
    SwitchRow(title = stringResource(R.string.notes_show_passphrase), checked = show, onCheckedChange = onShow)
    if (mismatch) ErrorText(stringResource(R.string.notes_passphrase_mismatch))
}
