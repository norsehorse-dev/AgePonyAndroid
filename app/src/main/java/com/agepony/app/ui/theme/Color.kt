package com.agepony.app.ui.theme

import androidx.compose.ui.graphics.Color

// AgePony brand palette (cyan-teal), shared with the iOS DesignSystem.
//   #38CFE8 cyan-light
//   #14B8B0 teal-core
//   #0E7D7A teal-deep
//   #0A4F4D teal-ink
val CyanLight = Color(0xFF38CFE8)
val TealCore = Color(0xFF14B8B0)
val TealDeep = Color(0xFF0E7D7A)
val TealInk = Color(0xFF0A4F4D)

// Neutral surfaces tuned to the brand.
val SurfaceLight = Color(0xFFFFFFFF)
val BackgroundLight = Color(0xFFF7FAFA)
val SurfaceDark = TealInk
val BackgroundDark = Color(0xFF06302F)
val OnDark = Color(0xFFE6FBFA)

// Phase 2f — explicit secondary-surface, outline, and container tokens. Defining
// these intentionally (rather than leaning on Material3's derived defaults) gives
// subtitle text, dividers, and containers consistent, accessible contrast on the
// cyan-teal scheme. These mirror the iOS DesignSystem secondary/quaternary roles.
val SurfaceVariantLight = Color(0xFFDDECEB)
val OnSurfaceVariantLight = Color(0xFF3C5957)
val OutlineLight = Color(0xFFAEC6C4)
val OutlineVariantLight = Color(0xFFC9DEDC)
val PrimaryContainerLight = Color(0xFFCDEFF4)

val SurfaceVariantDark = Color(0xFF143F3D)
val OnSurfaceVariantDark = Color(0xFFBAD7D5)
val OutlineDark = Color(0xFF386260)
val OutlineVariantDark = Color(0xFF274F4D)
