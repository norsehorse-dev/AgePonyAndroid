// KeyAvatar.kt
// AgePony Android 4.2.0
//
// A small circular avatar for an identity or recipient. age keys present as
// opaque "age1..." strings, so two entries can be hard to tell apart at a
// glance. The avatar gives each one a stable visual fingerprint: initials
// from the name, on a flat circle whose hue is derived from the key material
// (seed). Same key, same color, every time; a renamed key keeps its color, and
// two keys that share initials still differ by hue.

package com.agepony.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * @param seed stable per-key string (use the Base64 public key). Drives color.
 * @param name display name. Drives the initials.
 * @param size avatar diameter.
 */
@Composable
fun KeyAvatar(seed: String, name: String, size: Dp = 40.dp) {
    val hue = (fnv1a(seed) % 360u).toFloat()
    // Mid-dark tone so white initials keep contrast at every hue.
    val fill = Color.hsv(hue, 0.55f, 0.62f)
    Box(
        modifier = Modifier
            .size(size)
            .clip(CircleShape)
            .background(fill),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = initials(name),
            color = Color.White,
            style = if (size < 40.dp) MaterialTheme.typography.labelMedium else MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

/** Up to two initials, mirroring the desktop/iOS rule. Whitespace-split only. */
private fun initials(name: String): String {
    val words = name.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
    return when {
        words.isEmpty() -> "?"
        words.size == 1 -> words[0].take(2).uppercase()
        else -> (words[0].take(1) + words[1].take(1)).uppercase()
    }
}

/** 32-bit FNV-1a over the seed's UTF-8 bytes. Deterministic, no allocation churn. */
private fun fnv1a(s: String): UInt {
    var h = 2166136261u
    for (b in s.encodeToByteArray()) {
        h = h xor (b.toUInt() and 0xffu)
        h *= 16777619u
    }
    return h
}
