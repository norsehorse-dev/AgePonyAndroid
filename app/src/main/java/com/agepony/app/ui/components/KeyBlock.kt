package com.agepony.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
) {
    val clipboard = LocalClipboardManager.current
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
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 6.dp),
            )
        }

        Text(
            text = if (revealed) value else maskOf(value),
            fontFamily = FontFamily.Monospace,
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    color = MaterialTheme.colorScheme.primary.copy(alpha = 0.06f),
                    shape = RoundedCornerShape(12.dp),
                )
                .border(
                    width = 1.dp,
                    color = MaterialTheme.colorScheme.primary.copy(alpha = 0.18f),
                    shape = RoundedCornerShape(12.dp),
                )
                .padding(horizontal = 14.dp, vertical = 12.dp),
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            TextButton(onClick = {
                clipboard.setText(AnnotatedString(value))
                copied = true
            }) {
                Text(if (copied) "Copied" else "Copy")
            }
            if (isSensitive) {
                TextButton(onClick = { revealed = !revealed }) {
                    Text(if (revealed) "Hide" else "Reveal")
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
