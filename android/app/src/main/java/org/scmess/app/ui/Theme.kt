package org.scmess.app.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import org.scmess.app.data.Settings
import org.scmess.app.data.ThemeMode

// Blue scheme in the spirit of the old app's accent (#4073D9), used when wallpaper colors are off.
private val Light = lightColorScheme(
    primary = Color(0xFF3F5F90), onPrimary = Color.White,
    primaryContainer = Color(0xFFD6E3FF), onPrimaryContainer = Color(0xFF254777),
    secondary = Color(0xFF555F71), onSecondary = Color.White,
    secondaryContainer = Color(0xFFD9E3F8), onSecondaryContainer = Color(0xFF3E4759),
    tertiary = Color(0xFF6F5675), onTertiary = Color.White,
    tertiaryContainer = Color(0xFFF8D8FE), onTertiaryContainer = Color(0xFF563E5C),
    background = Color(0xFFF9F9FF), onBackground = Color(0xFF191C20),
    surface = Color(0xFFF9F9FF), onSurface = Color(0xFF191C20),
    surfaceVariant = Color(0xFFE0E2EC), onSurfaceVariant = Color(0xFF43474E),
    outline = Color(0xFF74777F), outlineVariant = Color(0xFFC4C6CF),
    surfaceContainerLowest = Color.White, surfaceContainerLow = Color(0xFFF3F3FA),
    surfaceContainer = Color(0xFFEDEDF4), surfaceContainerHigh = Color(0xFFE7E8EE),
    surfaceContainerHighest = Color(0xFFE2E2E9),
)

private val Dark = darkColorScheme(
    primary = Color(0xFFA8C8FF), onPrimary = Color(0xFF06305F),
    primaryContainer = Color(0xFF254777), onPrimaryContainer = Color(0xFFD6E3FF),
    secondary = Color(0xFFBDC7DC), onSecondary = Color(0xFF273141),
    secondaryContainer = Color(0xFF3E4759), onSecondaryContainer = Color(0xFFD9E3F8),
    tertiary = Color(0xFFDBBDE2), onTertiary = Color(0xFF3E2845),
    tertiaryContainer = Color(0xFF563E5C), onTertiaryContainer = Color(0xFFF8D8FE),
    background = Color(0xFF111318), onBackground = Color(0xFFE2E2E9),
    surface = Color(0xFF111318), onSurface = Color(0xFFE2E2E9),
    surfaceVariant = Color(0xFF43474E), onSurfaceVariant = Color(0xFFC4C6CF),
    outline = Color(0xFF8E9099), outlineVariant = Color(0xFF43474E),
    surfaceContainerLowest = Color(0xFF0C0E13), surfaceContainerLow = Color(0xFF191C20),
    surfaceContainer = Color(0xFF1D2024), surfaceContainerHigh = Color(0xFF282A2F),
    surfaceContainerHighest = Color(0xFF33353A),
)

fun Settings.isDark(system: Boolean) = when (theme) {
    ThemeMode.SYSTEM -> system
    ThemeMode.LIGHT -> false
    ThemeMode.DARK -> true
}

@Composable
fun ScTheme(settings: Settings, content: @Composable () -> Unit) {
    val dark = settings.isDark(isSystemInDarkTheme())
    val ctx = LocalContext.current
    var scheme = when {
        settings.dynamicColor && Build.VERSION.SDK_INT >= 31 ->
            if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> Dark
        else -> Light
    }
    if (dark && settings.pureBlack) scheme = scheme.copy(
        background = Color.Black, surface = Color.Black,
        surfaceContainerLowest = Color.Black, surfaceContainerLow = Color(0xFF0A0A0C),
        surfaceContainer = Color(0xFF111114), surfaceContainerHigh = Color(0xFF1A1A1E),
        surfaceContainerHighest = Color(0xFF242428),
    )
    MaterialTheme(colorScheme = scheme, content = content)
}
