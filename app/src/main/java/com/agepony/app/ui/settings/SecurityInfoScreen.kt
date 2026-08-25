// SecurityInfoScreen.kt
// AgePony Android 4.3.0
//
// A plain, consolidated account of how AgePony protects your files, and what
// it does not do. The knowledge was scattered across inline hints; this is the
// single trust page. Reached from Settings, Help & feedback.

package com.agepony.app.ui.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

private data class Block(val title: String, val body: String)

private val PROTECTS = listOf(
    Block(
        "Everything happens on this device",
        "AgePony has no account and talks to no server of ours. Encryption, decryption, and your keys all stay on this phone. The one exception is fetching a recipient's public key from GitHub, which only runs when you ask for it, and which you can route through a proxy."
    ),
    Block(
        "The age format and its algorithms",
        "Files use the age format: X25519 for public-key recipients, ChaCha20-Poly1305 for the payload, and scrypt when you encrypt to a passphrase. Post-quantum identities add ML-KEM to the key exchange. These are modern, well-reviewed choices, and the format is the same one the age command-line tool uses."
    ),
    Block(
        "Your vault at rest",
        "Identities, recipients, and notes live in an encrypted vault file. Its key is held by the Android Keystore, and you can gate unlock behind your device credential or a fingerprint. Locked, the vault is just ciphertext on disk."
    ),
    Block(
        "Passphrases in memory only",
        "A passphrase you type to encrypt a file is kept in memory to save you retyping across a run of files. It is never written to disk, never stored in the vault, and is dropped when the app goes to the background or the vault locks."
    ),
    Block(
        "A duress password, if you set one",
        "You can set a second password that, when entered at unlock, silently wipes the vault. It exists for the moment you are compelled to open the app and would rather it come up empty."
    ),
)

private val NOT_DOING = listOf(
    "It does not back your keys up to any cloud. If you lose this device without an export, the keys are gone.",
    "It cannot recover a private key you have deleted for good, and neither can we.",
    "It sends no analytics or telemetry. Nothing about your files or usage leaves the device.",
    "It cannot protect files after they leave AgePony, or defend against a phone that is already compromised at the system level.",
)

@Composable
fun SecurityInfoScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp),
    ) {
        TextButton(onClick = onBack, modifier = Modifier.padding(top = 8.dp)) { Text("‹ Back") }
        Text("How AgePony protects your files", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(bottom = 4.dp))
        Text(
            "What the app does for you, in plain terms, and what it deliberately does not do.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 16.dp),
        )
        PROTECTS.forEach { b ->
            Text(b.title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
            Text(b.body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text("What AgePony does not do", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 24.dp, bottom = 4.dp))
        NOT_DOING.forEach { line ->
            Text("•  $line", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
        }
        Text(
            "AgePony is open source. If you want to check any of this, the source link is in Settings under About.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 24.dp, bottom = 24.dp),
        )
    }
}
