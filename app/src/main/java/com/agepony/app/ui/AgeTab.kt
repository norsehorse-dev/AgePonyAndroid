package com.agepony.app.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Create
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.graphics.vector.ImageVector

/**
 * The five top-level destinations, mirroring the iOS tab structure:
 * Files / Notes / Text / Identities / Settings.
 *
 * Phase 2a wires labels, icons, and placeholder routing only. Real content
 * arrives in later phases:
 *   - 2b: vault unlock gate in front of all tabs
 *   - 2c: Identities + Files
 *   - 2d: Notes + Text + Settings
 *
 * Icons are all from material-icons-core (no extended dependency required).
 */
enum class AgeTab(val label: String, val icon: ImageVector) {
    FILES("Files", Icons.AutoMirrored.Filled.List),
    NOTES("Notes", Icons.Filled.Create),
    TEXT("Text", Icons.Filled.Lock),
    IDENTITIES("Identities", Icons.Filled.Person),
    SETTINGS("Settings", Icons.Filled.Settings),
}
