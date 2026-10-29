package com.agepony.app.ui.components

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.agepony.app.R

/**
 * "Quantum-safe" marker on post-quantum (MLKEM768-X25519) identities and
 * recipients: an icon and a word, no pill. Detail screens also show the full
 * algorithm name in their type row.
 */
@Composable
fun PostQuantumBadge(modifier: Modifier = Modifier) {
    StatusText(
        text = stringResource(R.string.post_quantum_label),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        icon = Icons.Filled.Lock,
        modifier = modifier,
    )
}
