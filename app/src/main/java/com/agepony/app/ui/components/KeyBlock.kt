package com.agepony.app.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.agepony.app.R
import com.agepony.app.security.ClipboardGuard
import com.agepony.app.ui.theme.mono
import kotlinx.coroutines.delay

//
// Read-only block for crypto strings (age1…, AGE-SECRET-KEY-1…, SSH lines).
// Monospace, copy-to-clipboard, and optional sensitive masking with a reveal
// toggle. The Android counterpart of iOS's AgePonyKeyBlock.swift. (iOS adds a
// 60s pasteboard auto-expiry; Android has no portable equivalent, so we rely
// on masking + the OS "sensitive content" clipboard handling instead.)
//
@Composable
fun KeyBlock(
    value: String,
    modifier: Modifier = Modifier,
    label: String? = null,
    isSensitive: Boolean = false,
    copyable: Boolean = true,
) {
    val context = LocalContext.current
    var copied by remember { mutableStateOf(false) }
    var revealed by remember(value) { mutableStateOf(!isSensitive) }

    if (copied) {
        LaunchedEffect(value, revealed) {
            delay(1400)
            copied = false
        }
    }

    Column(modifier = modifier.fillMaxWidth()) {
        if (label != null) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 4.dp),
            )
        }

        Text(
            text = if (revealed) value else maskOf(value),
            style = MaterialTheme.typography.mono,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.fillMaxWidth(),
        )

        if (copyable || isSensitive) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                if (copyable) {
                    TextButton(onClick = {
                        ClipboardGuard.copySensitive(context, value)
                        // Android 13+ confirms the copy itself.
                        copied = showOwnCopyConfirmation
                    }) {
                        Text(stringResource(if (copied) R.string.action_copied else R.string.action_copy))
                    }
                }
                if (isSensitive) {
                    TextButton(onClick = { revealed = !revealed }) {
                        Text(stringResource(if (revealed) R.string.action_hide else R.string.action_reveal))
                    }
                }
            }
        }
    }
}

private fun maskOf(value: String): String {
    // Keep a short, fixed-width mask so layout stays stable when hidden.
    val len = value.length.coerceAtMost(48).coerceAtLeast(8)
    return "•".repeat(len)
}
