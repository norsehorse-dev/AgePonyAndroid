package com.agepony.app.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Create
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.graphics.vector.ImageVector

/**
 * The six top-level destinations, mirroring the iOS tab structure:
 * Files / Sign / Notes / Text / Identities / Settings.
 *
 * Sign joined in 4.0.0. Six items is one over Material's recommended five;
 * matching iOS's dedicated Sign tab was judged worth it (settled in the 4.0.0
 * plan, open question 1), and every label still fits at default font scale.
 *
 * Icons are all from material-icons-core (no extended dependency required).
 */
enum class AgeTab(val label: String, val icon: ImageVector) {
    FILES("Files", Icons.AutoMirrored.Filled.List),
    SIGN("Sign", Icons.Filled.CheckCircle),
    NOTES("Notes", Icons.Filled.Create),
    TEXT("Text", Icons.Filled.Lock),
    IDENTITIES("Identities", Icons.Filled.Person),
    SETTINGS("Settings", Icons.Filled.Settings),
}
