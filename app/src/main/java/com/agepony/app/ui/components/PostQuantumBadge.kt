package com.agepony.app.ui.components

import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Small "Quantum-safe" chip shown on post-quantum (MLKEM768-X25519) identities and
 * recipients in lists and detail views. Detail screens additionally show the full
 * algorithm name via their type label.
 */
@Composable
fun PostQuantumBadge(modifier: Modifier = Modifier) {
    Surface(
        color = MaterialTheme.colorScheme.secondary.copy(alpha = 0.15f),
        shape = RoundedCornerShape(8.dp),
        modifier = modifier,
    ) {
        Text(
            text = "Quantum-safe",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.secondary,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
        )
    }
}
