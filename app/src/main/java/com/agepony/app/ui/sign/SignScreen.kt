package com.agepony.app.ui.sign

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
// Sign tab landing (4.0.0). Detached SSHSIG signing and verification, plus the
// trusted-signers list. Android counterpart of iOS's Features/Sign.
//

private enum class SignMode { HOME, SIGN_FILE, VERIFY_FILE, SIGNERS }

@Composable
fun SignScreen(vault: Vault, modifier: Modifier = Modifier) {
    var mode by rememberSaveable { mutableStateOf(SignMode.HOME) }

    when (mode) {
        SignMode.HOME -> Column(
            modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text("Sign", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
            Text(
                "Sign a file so others can prove it came from you, or verify a signature " +
                    "someone sent alongside a file. Signatures use the SSHSIG format, the same " +
                    "one ssh-keygen makes and checks.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 8.dp, bottom = 28.dp),
            )
            Button(onClick = { mode = SignMode.SIGN_FILE }, modifier = Modifier.fillMaxWidth()) {
                Text("Sign a file")
            }
            OutlinedButton(
                onClick = { mode = SignMode.VERIFY_FILE },
                modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
            ) { Text("Verify a file") }
            TextButton(
                onClick = { mode = SignMode.SIGNERS },
                modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
            ) { Text("Trusted signers") }
        }

        SignMode.SIGN_FILE -> SignFileFlow(
            vault = vault,
            modifier = modifier,
            onClose = { mode = SignMode.HOME },
        )

        SignMode.VERIFY_FILE -> VerifyFileFlow(
            vault = vault,
            modifier = modifier,
            onClose = { mode = SignMode.HOME },
        )

        SignMode.SIGNERS -> SignersScreen(
            vault = vault,
            modifier = modifier,
            onClose = { mode = SignMode.HOME },
        )
    }
}
