package com.agepony.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

// Every role is pinned in both schemes so no component falls back to the
// Material baseline palette (nav bar indicator, dialogs, menus, switches).
private val LightColorScheme = lightColorScheme(
    primary = AccentLight,
    onPrimary = Color.White,
    primaryContainer = AccentContainerLight,
    onPrimaryContainer = OnAccentContainerLight,
    inversePrimary = AccentDark,
    secondary = QuietLight,
    onSecondary = Color.White,
    secondaryContainer = QuietContainerLight,
    onSecondaryContainer = OnQuietContainerLight,
    tertiary = QuietLight,
    onTertiary = Color.White,
    tertiaryContainer = QuietContainerLight,
    onTertiaryContainer = OnQuietContainerLight,
    background = NeutralBackgroundLight,
    onBackground = NeutralOnLight,
    surface = NeutralBackgroundLight,
    onSurface = NeutralOnLight,
    surfaceVariant = NeutralVariantLight,
    onSurfaceVariant = NeutralOnVariantLight,
    surfaceTint = NeutralOutlineLight,
    inverseSurface = Color(0xFF2F3131),
    inverseOnSurface = Color(0xFFF1F1F1),
    error = ErrorLight,
    onError = Color.White,
    errorContainer = ErrorContainerLight,
    onErrorContainer = OnErrorContainerLight,
    outline = NeutralOutlineLight,
    outlineVariant = NeutralOutlineVariantLight,
    scrim = Color.Black,
    surfaceBright = NeutralBackgroundLight,
    surfaceDim = NeutralDimLight,
    surfaceContainerLowest = NeutralContainerLowestLight,
    surfaceContainerLow = NeutralContainerLowLight,
    surfaceContainer = NeutralContainerLight,
    surfaceContainerHigh = NeutralContainerHighLight,
    surfaceContainerHighest = NeutralContainerHighestLight,
)

private val DarkColorScheme = darkColorScheme(
    primary = AccentDark,
    onPrimary = OnAccentDark,
    primaryContainer = AccentContainerDark,
    onPrimaryContainer = OnAccentContainerDark,
    inversePrimary = AccentLight,
    secondary = QuietDark,
    onSecondary = OnQuietDark,
    secondaryContainer = QuietContainerDark,
    onSecondaryContainer = OnQuietContainerDark,
    tertiary = QuietDark,
    onTertiary = OnQuietDark,
    tertiaryContainer = QuietContainerDark,
    onTertiaryContainer = OnQuietContainerDark,
    background = NeutralBackgroundDark,
    onBackground = NeutralOnDark,
    surface = NeutralBackgroundDark,
    onSurface = NeutralOnDark,
    surfaceVariant = NeutralVariantDark,
    onSurfaceVariant = NeutralOnVariantDark,
    surfaceTint = NeutralOutlineDark,
    inverseSurface = NeutralOnDark,
    inverseOnSurface = Color(0xFF2F3131),
    error = ErrorDark,
    onError = OnErrorDark,
    errorContainer = ErrorContainerDark,
    onErrorContainer = OnErrorContainerDark,
    outline = NeutralOutlineDark,
    outlineVariant = NeutralOutlineVariantDark,
    scrim = Color.Black,
    surfaceBright = NeutralBrightDark,
    surfaceDim = NeutralBackgroundDark,
    surfaceContainerLowest = NeutralContainerLowestDark,
    surfaceContainerLow = NeutralContainerLowDark,
    surfaceContainer = NeutralContainerDark,
    surfaceContainerHigh = NeutralContainerHighDark,
    surfaceContainerHighest = NeutralContainerHighestDark,
)

// Two corner radii: 12dp for boxes, fields and menus; fully round for buttons
// and avatars (the platform default). Dialogs and sheets keep the platform shape.
private val AgeShapes = Shapes(
    extraSmall = RoundedCornerShape(12.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(12.dp),
)

/** Status colors that sit beside the color scheme: icon and status word only. */
@Immutable
data class StatusColors(val success: Color, val warning: Color, val failure: Color)

val LocalStatusColors = staticCompositionLocalOf {
    StatusColors(success = SuccessLight, warning = WarningLight, failure = ErrorLight)
}

/** Accessor: `AgeStatus.colors.success` inside a composable. */
object AgeStatus {
    val colors: StatusColors
        @Composable get() = LocalStatusColors.current
}

@Composable
fun AgePonyTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    // Dynamic (Material You) color stays off: the palette is the brand.
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    val status = if (darkTheme) {
        StatusColors(success = SuccessDark, warning = WarningDark, failure = ErrorDark)
    } else {
        StatusColors(success = SuccessLight, warning = WarningLight, failure = ErrorLight)
    }
    CompositionLocalProvider(LocalStatusColors provides status) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = AgeTypography,
            shapes = AgeShapes,
            content = content,
        )
    }
}
