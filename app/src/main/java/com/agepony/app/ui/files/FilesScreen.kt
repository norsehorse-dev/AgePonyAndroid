package com.agepony.app.ui.files

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.agepony.app.vault.Vault

//
// Files tab landing (Phase 2c-3a). Encrypt is wired; Decrypt lands in 2c-3b.
//

private enum class FilesMode { HOME, ENCRYPT, DECRYPT }

@Composable
fun FilesScreen(vault: Vault, modifier: Modifier = Modifier) {
    var mode by rememberSaveable { mutableStateOf(FilesMode.HOME) }

    when (mode) {
        FilesMode.HOME -> Column(
            modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text("Files", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
            Text(
                "Encrypt or decrypt a file with your identities, saved recipients, or a passphrase.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 8.dp, bottom = 28.dp),
            )
            Button(onClick = { mode = FilesMode.ENCRYPT }, modifier = Modifier.fillMaxWidth()) {
                Text("Encrypt a file")
            }
            OutlinedButton(
                onClick = { mode = FilesMode.DECRYPT },
                modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
            ) { Text("Decrypt a file") }
        }

        FilesMode.ENCRYPT -> EncryptFlow(vault = vault, modifier = modifier, onClose = { mode = FilesMode.HOME })

        FilesMode.DECRYPT -> DecryptFlow(vault = vault, modifier = modifier, onClose = { mode = FilesMode.HOME })
    }
}
