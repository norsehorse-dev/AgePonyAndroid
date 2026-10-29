package com.agepony.app.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Create
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.annotation.StringRes
import androidx.compose.ui.graphics.vector.ImageVector
import com.agepony.app.R

/**
 * The five top-level destinations, mirroring the iOS tab structure:
 * Files / Notes / Text / Identities / Settings.
 *
 * 5.1.0 folded the Sign tab into Files (as on iOS), which brings the bar back to
 * Material's five-item maximum. Sign a file, verify a signature and trusted
 * signers are rows on the Files screen.
 *
 * Icons are all from material-icons-core (no extended dependency required).
 */
enum class AgeTab(@StringRes val labelRes: Int, val icon: ImageVector) {
    FILES(R.string.files_title, Icons.AutoMirrored.Filled.List),
    NOTES(R.string.app_tab_notes, Icons.Filled.Create),
    TEXT(R.string.app_tab_text, Icons.Filled.Lock),
    IDENTITIES(R.string.app_tab_identities, Icons.Filled.Person),
    SETTINGS(R.string.app_tab_settings, Icons.Filled.Settings),
}
