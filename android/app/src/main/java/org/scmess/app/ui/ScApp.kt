package org.scmess.app.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector

private data class Dest(val tab: Tab, val label: String, val on: ImageVector, val off: ImageVector)

private val dests = listOf(
    Dest(Tab.MESSAGES, "Сообщения", Icons.Filled.Lock, Icons.Outlined.Lock),
    Dest(Tab.FILES, "Файлы", Icons.Filled.Folder, Icons.Outlined.Folder),
    Dest(Tab.KEYS, "Ключи", Icons.Filled.Key, Icons.Outlined.Key),
    Dest(Tab.SETTINGS, "Настройки", Icons.Filled.Settings, Icons.Outlined.Settings),
)

@Composable
fun ScApp(vm: AppViewModel) {
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(Unit) { vm.events.collect { snackbar.showSnackbar(it) } }
    BackHandler(enabled = vm.tab != Tab.MESSAGES) { vm.tab = Tab.MESSAGES }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            NavigationBar {
                for (d in dests) {
                    val sel = vm.tab == d.tab
                    NavigationBarItem(
                        selected = sel,
                        onClick = { vm.tab = d.tab },
                        icon = { Icon(if (sel) d.on else d.off, contentDescription = null) },
                        label = { Text(d.label) },
                    )
                }
            }
        },
    ) { pad ->
        Box(
            Modifier.fillMaxSize()
                .padding(bottom = pad.calculateBottomPadding())
                .consumeWindowInsets(PaddingValues(bottom = pad.calculateBottomPadding()))
        ) {
            AnimatedContent(vm.tab, transitionSpec = { fadeIn() togetherWith fadeOut() }, label = "tab") { tab ->
                when (tab) {
                    Tab.MESSAGES -> MessagesScreen(vm)
                    Tab.FILES -> FilesScreen(vm)
                    Tab.KEYS -> KeysScreen(vm)
                    Tab.SETTINGS -> SettingsScreen(vm)
                }
            }
        }
    }
}
