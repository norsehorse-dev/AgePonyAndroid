package com.agepony.app.ui.passphrase

import android.net.Uri
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
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.PrimaryTabRow
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.agepony.app.security.ClipboardGuard
import com.agepony.app.share.ShareOut
import com.agepony.app.share.ShareSniff
import com.agepony.app.ui.files.DecryptFlow
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.ScryptMemoryException
import com.agepony.app.vault.Vault
import com.agepony.app.vault.WrongPassphraseException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Passphrase work without unlocking the vault (issue #13). The app lock guards the vault's keys
 * and notes; a passphrase file needs none of them, so asking for the app PIN first was a second
 * secret for one job. This screen never touches the vault's contents: it encrypts and decrypts
 * text with a passphrase, and decrypts passphrase files (the Files decrypt flow finds no vault
 * identities while locked and goes straight to the passphrase).
 */
@Composable
fun PassphraseOnlyScreen(
    vault: Vault,
    onClose: () -> Unit,
    initialText: String? = null,
    initialFile: Uri? = null,
) {
    var tab by rememberSaveable { mutableStateOf(if (initialFile != null) 1 else 0) }
    Scaffold { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onClose) { Text("‹ Back to unlock") }
            }
            Text(
                "Passphrase only",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 20.dp),
            )
            Text(
                "Your vault stays locked. Nothing here can see your keys, recipients or notes.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp),
            )
            PrimaryTabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Text") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Decrypt a file") })
            }
            when (tab) {
                0 -> PassphraseText(vault, initialText.orEmpty())
                else -> DecryptFlow(vault = vault, initialUri = initialFile, onClose = onClose)
            }
        }
    }
}

@Composable
private fun PassphraseText(vault: Vault, initialText: String) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var input by remember { mutableStateOf(ShareSniff.extractArmor(initialText)) }
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<String?>(null) }
    var resultIsPlaintext by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val decrypting = ShareSniff.textLooksEncrypted(input)

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (result != null) {
            Text(if (resultIsPlaintext) "Decrypted text" else "Armored output", style = MaterialTheme.typography.titleSmall)
            OutlinedTextField(
                value = result!!, onValueChange = {}, readOnly = true, minLines = 6,
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = { ClipboardGuard.copySensitive(context, result!!) }, modifier = Modifier.fillMaxWidth()) { Text("Copy") }
            if (!resultIsPlaintext) {
                OutlinedButton(onClick = { ShareOut.text(context, result!!, "Share encrypted text") }, modifier = Modifier.fillMaxWidth()) {
                    Text("Share…")
                }
            }
            TextButton(onClick = { result = null; input = ""; passphrase = ""; confirm = "" }) { Text("Start over") }
            return@Column
        }

        OutlinedTextField(
            value = input, onValueChange = { input = it; error = null },
            label = { Text("Text to encrypt, or an armored age block to decrypt") },
            minLines = 6, modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = passphrase, onValueChange = { passphrase = it; error = null },
            label = { Text("Passphrase") }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        if (!decrypting) {
            OutlinedTextField(
                value = confirm, onValueChange = { confirm = it; error = null },
                label = { Text("Confirm passphrase") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        val ready = !busy && input.isNotBlank() && passphrase.isNotEmpty() && (decrypting || passphrase == confirm)
        Button(
            onClick = {
                busy = true
                val text = input
                val pass = passphrase
                scope.launch {
                    try {
                        if (decrypting) {
                            val plain = withContext(Dispatchers.Default) {
                                FileEncryptor.decryptWithPassphrase(FileEncryptor.toBinary(text.toByteArray(Charsets.UTF_8)), pass)
                            }
                            result = String(plain, Charsets.UTF_8); resultIsPlaintext = true
                        } else {
                            val out = withContext(Dispatchers.Default) {
                                FileEncryptor.encrypt(text.toByteArray(Charsets.UTF_8), emptyList(), pass, armor = true, workFactor = vault.scryptWorkFactor)
                            }
                            result = String(out, Charsets.UTF_8); resultIsPlaintext = false
                        }
                    } catch (e: WrongPassphraseException) {
                        error = e.message
                    } catch (e: ScryptMemoryException) {
                        error = e.message
                    } catch (e: OutOfMemoryError) {
                        error = "Not enough memory for this passphrase's work factor on this device."
                    } catch (e: Exception) {
                        error = e.message ?: if (decrypting) "Decrypt failed." else "Encrypt failed."
                    } finally {
                        busy = false
                    }
                }
            },
            enabled = ready,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(if (decrypting) "Decrypt with passphrase" else "Encrypt with passphrase") }
        if (busy) CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
        if (!decrypting && confirm.isNotEmpty() && passphrase != confirm) {
            Text("The passphrases don't match.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
    }
}
