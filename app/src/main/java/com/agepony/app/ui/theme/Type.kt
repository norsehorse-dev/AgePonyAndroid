package com.agepony.app.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight

// UI text uses the platform sans through Material's type scale. Rows are
// bodyLarge (16sp regular), section headings titleMedium (semibold), secondary
// lines bodyMedium, captions bodySmall. Screen titles live in the TopAppBar.
private val Base = Typography()

val AgeTypography = Base.copy(
    titleMedium = Base.titleMedium.copy(fontWeight = FontWeight.SemiBold),
)

/**
 * Monospace for real data only: age recipients and identities, SSH lines,
 * fingerprints, transfer codes. Never for labels, buttons or headings.
 */
val Typography.mono: TextStyle
    get() = bodyMedium.copy(fontFamily = FontFamily.Monospace)

/** A short code the user compares between two screens (transfer and confirmation codes). */
val Typography.code: TextStyle
    get() = headlineSmall.copy(fontFamily = FontFamily.Monospace)
