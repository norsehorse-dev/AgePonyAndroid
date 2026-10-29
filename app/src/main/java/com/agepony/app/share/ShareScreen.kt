package com.agepony.app.share

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import com.agepony.app.ui.files.DecryptFlow
import com.agepony.app.ui.files.EncryptFlow
import com.agepony.app.ui.text.TextDecrypt
import com.agepony.app.ui.text.TextEncrypt
import com.agepony.app.vault.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.compose.foundation.layout.WindowInsets

private enum class ShareMode { DETECTING, ENCRYPT, DECRYPT }

/**
 * What to do with shared content. Text with an armored age block, or a single age file, goes
 * straight to decrypt; anything else goes to encrypt. The user can switch if the guess is wrong.
 */
@Composable
fun ShareScreen(
    vault: Vault,
    payload: SharePayload,
    onReplaceText: (String) -> Unit,
    onDone: () -> Unit,
) {
    val context = LocalContext.current
    var mode by rememberSaveable { mutableStateOf(ShareMode.DETECTING) }

    LaunchedEffect(payload) {
        if (mode != ShareMode.DETECTING) return@LaunchedEffect
        mode = when (payload) {
            is SharePayload.Text ->
                if (ShareSniff.textLooksEncrypted(payload.text)) ShareMode.DECRYPT else ShareMode.ENCRYPT
            is SharePayload.Files -> {
                val encrypted = payload.uris.size == 1 && withContext(Dispatchers.IO) {
                    ShareSniff.fileLooksEncrypted(context, payload.uris.first())
                }
                if (encrypted) ShareMode.DECRYPT else ShareMode.ENCRYPT
            }
        }
    }

    // The flows below draw their own TopAppBar and handle the system-bar insets
    // themselves, so this Scaffold adds none.
    Scaffold(contentWindowInsets = WindowInsets(0, 0, 0, 0)) { padding ->
        val modifier = Modifier.fillMaxSize().padding(padding)
        when (mode) {
            ShareMode.DETECTING -> Column(
                modifier,
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) { CircularProgressIndicator(color = MaterialTheme.colorScheme.primary) }

            ShareMode.ENCRYPT -> when (payload) {
                is SharePayload.Text -> TextEncrypt(
                    vault = vault,
                    modifier = modifier,
                    onClose = onDone,
                    initialText = payload.text,
                    onReplace = if (payload.canReplace) onReplaceText else null,
                    replaceUnavailableNote = if (payload.processText && !payload.canReplace) {
                        stringResource(R.string.app_share_replace_unavailable)
                    } else null,
                )
                is SharePayload.Files -> EncryptFlow(
                    vault = vault,
                    modifier = modifier,
                    initialUris = payload.uris,
                    onClose = onDone,
                )
            }

            ShareMode.DECRYPT -> when (payload) {
                is SharePayload.Text -> TextDecrypt(
                    vault = vault,
                    modifier = modifier,
                    onClose = onDone,
                    initialText = payload.text,
                    autoStart = true,
                )
                is SharePayload.Files -> DecryptFlow(
                    vault = vault,
                    modifier = modifier,
                    initialUri = payload.uris.first(),
                    onClose = onDone,
                )
            }
        }
    }
}
