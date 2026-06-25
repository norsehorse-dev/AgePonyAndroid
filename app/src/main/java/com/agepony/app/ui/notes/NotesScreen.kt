package com.agepony.app.ui.notes

import android.text.format.DateUtils
import android.util.Base64
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
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
    Column(modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 20.dp, end = 12.dp, top = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Notes", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.weight(1f))
            TextButton(onClick = onCreate) { Text("New note") }
        }

        val notes = vault.notes.sortedByDescending { it.updatedAt }
        if (notes.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(32.dp)) {
                    Text("No notes yet", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Tap New note to create one. Each note has its own passphrase.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(notes, key = { it.id }) { note ->
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .clickable { onOpen(note.id) }
                            .padding(horizontal = 20.dp, vertical = 14.dp),
                    ) {
                        Text(
                            note.title.ifBlank { "Untitled" },
                            style = MaterialTheme.typography.bodyLarge,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            "Edited " + DateUtils.getRelativeTimeSpanString(note.updatedAt),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    HorizontalDivider()
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
    var title by rememberSaveable { mutableStateOf("") }
    var body by rememberSaveable { mutableStateOf("") }
    var passphrase by rememberSaveable { mutableStateOf("") }
    var confirm by rememberSaveable { mutableStateOf("") }
    var show by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    val mismatch = confirm.isNotEmpty() && passphrase != confirm
    val canSave = !busy && passphrase.isNotEmpty() && passphrase == confirm

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("New note", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
        OutlinedTextField(
            value = title,
            onValueChange = { title = it },
            label = { Text("Title (stored in the vault, searchable)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = body,
            onValueChange = { body = it },
            label = { Text("Body (encrypted with this note's passphrase)") },
            minLines = 6,
            modifier = Modifier.fillMaxWidth(),
        )
        PassphraseFields(
            passphrase = passphrase, onPassphrase = { passphrase = it; error = null },
            confirm = confirm, onConfirm = { confirm = it; error = null },
            show = show, onShow = { show = it }, mismatch = mismatch,
        )
        Text(
            "scrypt work factor 2^18 makes brute force expensive, but a guessable passphrase is still guessable. There's no recovery if you forget it.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (error != null) ErrorLine(error!!)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = {
                    if (!canSave) return@Button
                    busy = true; error = null
                    val titleSnapshot = title.trim().ifBlank { "Untitled" }
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
                            error = "Not enough memory to encrypt this note on this device."
                        } catch (e: Exception) {
                            busy = false
                            error = e.message ?: "Couldn't create the note."
                        }
                    }
                },
                enabled = canSave,
                modifier = Modifier.weight(1f),
            ) { Text(if (busy) "Encrypting…" else "Create note") }
            OutlinedButton(onClick = onCancel, enabled = !busy, modifier = Modifier.weight(1f)) { Text("Cancel") }
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
    var passInput by rememberSaveable { mutableStateOf("") }
    var show by rememberSaveable { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    var unlockedPass by remember { mutableStateOf("") }
    var editTitle by remember { mutableStateOf("") }
    var editBody by remember { mutableStateOf("") }
    var origTitle by remember { mutableStateOf("") }
    var origBody by remember { mutableStateOf("") }

    val scope = rememberCoroutineScope()

    Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TextButton(onClick = onBack) { Text("‹ Back") }

        if (note == null) {
            Text("Note not found.", style = MaterialTheme.typography.bodyLarge)
            return@Column
        }

        when (phase) {
            NotePhase.LOCKED -> {
                Text(note.title.ifBlank { "Untitled" }, style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.primary)
                Text(
                    "Edited " + DateUtils.getRelativeTimeSpanString(note.updatedAt),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = passInput,
                    onValueChange = { passInput = it; error = null },
                    label = { Text("Passphrase") },
                    singleLine = true,
                    visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = show, onCheckedChange = { show = it })
                    Text("Show passphrase", modifier = Modifier.padding(start = 12.dp), style = MaterialTheme.typography.bodySmall)
                }
                if (error != null) ErrorLine(error!!)
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
                                working = false; error = "Wrong passphrase."
                            } catch (e: OutOfMemoryError) {
                                working = false; error = "Not enough memory to decrypt this note."
                            } catch (e: Exception) {
                                working = false; error = e.message ?: "Couldn't unlock the note."
                            }
                        }
                    },
                    enabled = passInput.isNotEmpty() && !working,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (working) "Decrypting…" else "Unlock") }
                TextButton(onClick = {
                    vault.deleteNote(noteId)
                    onBack()
                }) { Text("Delete note", color = MaterialTheme.colorScheme.error) }
            }

            NotePhase.UNLOCKED -> {
                val dirty = editTitle != origTitle || editBody != origBody
                OutlinedTextField(
                    value = editTitle,
                    onValueChange = { editTitle = it },
                    label = { Text("Title") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = editBody,
                    onValueChange = { editBody = it },
                    label = { Text("Body") },
                    minLines = 8,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (error != null) ErrorLine(error!!)
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                    Button(
                        onClick = {
                            if (!dirty || working) return@Button
                            working = true; error = null
                            val titleSnapshot = editTitle.trim().ifBlank { "Untitled" }
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
                                    working = false; error = "Not enough memory to save this note."
                                } catch (e: Exception) {
                                    working = false; error = e.message ?: "Couldn't save the note."
                                }
                            }
                        },
                        enabled = dirty && !working,
                        modifier = Modifier.weight(1f),
                    ) { Text(if (working) "Encrypting…" else "Save") }
                    OutlinedButton(
                        onClick = {
                            unlockedPass = ""; editTitle = ""; editBody = ""; origTitle = ""; origBody = ""
                            passInput = ""; error = null
                            phase = NotePhase.LOCKED
                        },
                        enabled = !working,
                        modifier = Modifier.weight(1f),
                    ) { Text("Lock") }
                }
                if (dirty) {
                    Text("Unsaved changes — tap Save to re-encrypt.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
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
        label = { Text("Passphrase") }, singleLine = true,
        visualTransformation = transform, modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = confirm, onValueChange = onConfirm,
        label = { Text("Confirm passphrase") }, singleLine = true,
        visualTransformation = transform, modifier = Modifier.fillMaxWidth(),
    )
    Row(verticalAlignment = Alignment.CenterVertically) {
        Switch(checked = show, onCheckedChange = onShow)
        Text("Show passphrase", modifier = Modifier.padding(start = 12.dp), style = MaterialTheme.typography.bodySmall)
    }
    if (mismatch) {
        Text("Passphrases don't match.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }
}

@Composable
private fun ErrorLine(message: String) {
    Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
}
