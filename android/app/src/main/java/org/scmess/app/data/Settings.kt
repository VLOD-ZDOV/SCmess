package org.scmess.app.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class ThemeMode { SYSTEM, LIGHT, DARK }

data class Settings(
    val theme: ThemeMode = ThemeMode.SYSTEM,
    val pureBlack: Boolean = false,
    val dynamicColor: Boolean = true,
    val autoCopy: Boolean = true,
    val secureScreen: Boolean = false,
)

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val _state = MutableStateFlow(read())
    val state: StateFlow<Settings> = _state.asStateFlow()

    private fun read() = Settings(
        theme = ThemeMode.entries.getOrElse(prefs.getInt("theme", 0)) { ThemeMode.SYSTEM },
        pureBlack = prefs.getBoolean("pure_black", false),
        dynamicColor = prefs.getBoolean("dynamic_color", true),
        autoCopy = prefs.getBoolean("auto_copy", true),
        secureScreen = prefs.getBoolean("secure_screen", false),
    )

    fun update(f: (Settings) -> Settings) {
        val s = f(_state.value)
        prefs.edit()
            .putInt("theme", s.theme.ordinal)
            .putBoolean("pure_black", s.pureBlack)
            .putBoolean("dynamic_color", s.dynamicColor)
            .putBoolean("auto_copy", s.autoCopy)
            .putBoolean("secure_screen", s.secureScreen)
            .apply()
        _state.value = s
    }
}
