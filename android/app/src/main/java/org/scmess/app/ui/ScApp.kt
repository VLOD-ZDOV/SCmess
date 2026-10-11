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
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.outlined.Tag
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Settings
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
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
    Dest(Tab.HASHES, "Хеши", Icons.Filled.Tag, Icons.Outlined.Tag),
    Dest(Tab.KEYS, "Ключи", Icons.Filled.Key, Icons.Outlined.Key),
    Dest(Tab.SETTINGS, "Настройки", Icons.Filled.Settings, Icons.Outlined.Settings),
)

@Composable
fun ScApp(vm: AppViewModel) {
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(Unit) { vm.events.collect { snackbar.showSnackbar(it) } }
    BackHandler(enabled = vm.tab != Tab.MESSAGES) { vm.tab = Tab.MESSAGES }

    var updateShown by rememberSaveable { mutableStateOf(false) }
    val update = vm.update
    if (update != null && !updateShown) {
        val ctx = LocalContext.current
        AlertDialog(
            onDismissRequest = { updateShown = true },
            icon = { Icon(Icons.Filled.SystemUpdate, null) },
            title = { Text("Доступна версия ${update.version}") },
            text = {
                Text(
                    update.notes.lines().take(12).joinToString("\n").ifBlank { "Новая версия SCmess вышла на GitHub." },
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    updateShown = true
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(update.apkUrl ?: update.pageUrl)))
                }) { Text("Скачать") }
            },
            dismissButton = { TextButton(onClick = { updateShown = true }) { Text("Позже") } },
        )
    }

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
                        label = { Text(d.label, maxLines = 1) },
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
                    Tab.HASHES -> HashesScreen(vm)
                    Tab.KEYS -> KeysScreen(vm)
                    Tab.SETTINGS -> SettingsScreen(vm)
                }
            }
        }
    }
}
