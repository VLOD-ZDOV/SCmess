package org.scmess.app.ui

import android.os.Build
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.scmess.app.data.ThemeMode

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(vm: AppViewModel) {
    val s by vm.settings.state.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val version = remember(ctx) { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName }

    Column(Modifier.fillMaxWidth()) {
        TopAppBar(title = { Text("Настройки") })
        Column(Modifier.verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
            Header("Оформление")
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                listOf(ThemeMode.SYSTEM to "Системная", ThemeMode.LIGHT to "Светлая", ThemeMode.DARK to "Тёмная")
                    .forEachIndexed { i, (mode, label) ->
                        SegmentedButton(
                            selected = s.theme == mode,
                            onClick = { vm.settings.update { it.copy(theme = mode) } },
                            shape = SegmentedButtonDefaults.itemShape(i, 3),
                        ) { Text(label) }
                    }
            }
            if (Build.VERSION.SDK_INT >= 31) Toggle(
                "Цвета обоев", "Material You: палитра подстраивается под обои", s.dynamicColor,
            ) { v -> vm.settings.update { it.copy(dynamicColor = v) } }
            Toggle("Чёрный фон", "Для AMOLED-экранов в тёмной теме", s.pureBlack) { v ->
                vm.settings.update { it.copy(pureBlack = v) }
            }

            Header("Поведение")
            Toggle("Копировать результат", "Зашифрованный текст сразу попадает в буфер обмена", s.autoCopy) { v ->
                vm.settings.update { it.copy(autoCopy = v) }
            }
            Toggle("Запретить скриншоты", "Экран приложения не попадёт на скриншоты и в список недавних", s.secureScreen) { v ->
                vm.settings.update { it.copy(secureScreen = v) }
            }

            Header("О приложении")
            ListItem(
                headlineContent = { Text("SCmess $version") },
                supportingContent = {
                    Text("RSA-OAEP + AES-256-GCM. Совместимо с SCmess для ПК и старой версией приложения. Ключи хранятся только на устройстве.")
                },
            )
        }
    }
}

@Composable
private fun Header(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp),
    )
}

@Composable
private fun Toggle(title: String, sub: String, value: Boolean, onChange: (Boolean) -> Unit) {
    ListItem(
        modifier = Modifier.toggleable(value = value, role = Role.Switch, onValueChange = onChange),
        headlineContent = { Text(title) },
        supportingContent = { Text(sub) },
        trailingContent = { Switch(checked = value, onCheckedChange = null) },
    )
}
