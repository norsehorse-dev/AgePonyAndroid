// HelpScreen.kt
// AgePony Android 4.3.0
//
// In-app FAQ. Plain-language answers to the questions testers actually ask,
// so the app can answer them without an email round-trip. Reached from
// Settings, Help & feedback.

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

private data class Qa(val q: String, val a: String)

private val FAQ = listOf(
    Qa(
        "What is age, and what is AgePony?",
        "age is a modern, open file-encryption format: small, audited, and free of the legacy baggage of older tools. AgePony is a friendly age client for your phone. Files it writes are ordinary age files that any age tool can open."
    ),
    Qa(
        "What is a recipient?",
        "A recipient is someone you encrypt to, identified by their public key (an age1... string or an SSH public key). Add a recipient once and you can encrypt files that only they can open. You never need their private key, only the public one they share."
    ),
    Qa(
        "Passphrase or key: which should I use?",
        "A key (an identity) is best when you encrypt to yourself or to people you exchange keys with: nothing to remember, nothing to type. A passphrase is best for a one-off file you want to hand to someone who does not use AgePony. They only need the word, not a key."
    ),
    Qa(
        "What does Armor as text mean?",
        "Armor writes the encrypted file as plain letters and numbers instead of raw bytes, so you can paste it into a chat or email. It is a little larger. Leave it off for files you send as attachments."
    ),
    Qa(
        "I encrypted several files at once. Where did they go?",
        "Encrypting more than one file packs them into a single archive so it travels as one file. When you decrypt it, AgePony offers Extract files into a folder, which writes each original back out. A single file encrypts and decrypts on its own with no archive."
    ),
    Qa(
        "Can someone open my file without AgePony?",
        "Yes. AgePony writes standard age files, so the age command-line tool and other age clients open them with the matching key or passphrase. You are not locked in."
    ),
    Qa(
        "What happens if I delete or lose an identity?",
        "An identity holds a private key. Without it, files encrypted to that identity cannot be opened by anyone, including you. Deleting an identity now moves it to Recently deleted for a while so you can restore it, but once it is gone for good it cannot be recovered. Export a copy you keep somewhere safe if it matters."
    ),
    Qa(
        "What is a post-quantum identity?",
        "It is a hybrid identity that combines classic X25519 with ML-KEM, a scheme designed to resist future quantum computers. Files encrypted to it stay protected even against an attacker who records them now to break later. It is fully compatible with age tools that support the hybrid recipient."
    ),
    Qa(
        "Can I sign a file without encrypting it?",
        "Yes. The Sign tab produces a detached signature so others can prove a file came from you, and verifies signatures from people on your signers list. Signing and encrypting are separate: you can do either or both."
    ),
)

@Composable
fun HelpScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp),
    ) {
        TextButton(onClick = onBack, modifier = Modifier.padding(top = 8.dp)) { Text("‹ Back") }
        Text("Help & FAQ", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(bottom = 4.dp))
        Text(
            "Short answers to the things people ask most.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 16.dp),
        )
        FAQ.forEach { item ->
            Text(item.q, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
            Text(item.a, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(
            "Still stuck? Settings has a Send feedback button that opens an email to NorseHorse.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 24.dp, bottom = 24.dp),
        )
    }
}
