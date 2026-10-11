package org.scmess.app.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.scmess.app.crypto.ScCrypto

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HashesScreen(vm: AppViewModel) {
    val ctx = LocalContext.current
    var fileMode by rememberSaveable { mutableStateOf(false) }
    var text by rememberSaveable { mutableStateOf("") }
    var expected by rememberSaveable { mutableStateOf("") }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.hashFile(uri)
    }

    val textHashes = remember(text) { ScCrypto.hash(text.toByteArray().inputStream()) }
    val task = vm.hashTask
    val hashes = if (fileMode) task?.result else textHashes

    Column(Modifier.fillMaxWidth()) {
        TopAppBar(title = { Text("Хеши") })
        Column(
            Modifier.verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                listOf(false to "Текст", true to "Файл").forEachIndexed { i, (mode, label) ->
                    SegmentedButton(
                        selected = fileMode == mode,
                        onClick = { fileMode = mode },
                        shape = SegmentedButtonDefaults.itemShape(i, 2),
                    ) { Text(label) }
                }
            }

            if (!fileMode) {
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp),
                    label = { Text("Текст") },
                    trailingIcon = {
                        if (text.isNotEmpty()) IconButton(onClick = { text = "" }) { Icon(Icons.Filled.Close, "Очистить") }
                        else IconButton(onClick = { ctx.pasteText()?.let { text = it } }) { Icon(Icons.Filled.ContentPaste, "Вставить") }
                    },
                )
            } else {
                FilledTonalButton(
                    onClick = { pick.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                ) {
                    Icon(Icons.Filled.FileOpen, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Выбрать файл")
                }
                if (task != null) Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(task.name, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (task.result == null) LinearProgressIndicator(progress = { task.progress }, modifier = Modifier.fillMaxWidth())
                }
            }

            OutlinedTextField(
                value = expected,
                onValueChange = { expected = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Ожидаемый хеш (для сверки)") },
                singleLine = true,
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                trailingIcon = {
                    if (expected.isNotEmpty()) IconButton(onClick = { expected = "" }) { Icon(Icons.Filled.Close, "Очистить") }
                    else IconButton(onClick = { ctx.pasteText()?.let { expected = it.trim() } }) { Icon(Icons.Filled.ContentPaste, "Вставить") }
                },
            )

            if (hashes != null) {
                val want = expected.trim().lowercase().replace(Regex("[\\s:]"), "")
                if (want.isNotEmpty()) {
                    val match = when (want) {
                        hashes.sha256 -> "SHA-256"
                        hashes.sha512 -> "SHA-512"
                        else -> null
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            if (match != null) Icons.Filled.CheckCircle else Icons.Filled.Cancel, null,
                            tint = if (match != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            if (match != null) "Совпадает ($match)" else "Не совпадает",
                            color = if (match != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.titleSmall,
                        )
                    }
                }
                HashCard("SHA-256", hashes.sha256, vm)
                HashCard("SHA-512", hashes.sha512, vm)
            }
        }
    }
}

@Composable
private fun HashCard(label: String, value: String, vm: AppViewModel) {
    val ctx = LocalContext.current
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Row(Modifier.padding(start = 16.dp, top = 8.dp, bottom = 12.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(label, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                SelectionContainer {
                    Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                }
            }
            IconButton(onClick = {
                ctx.copyText(value)
                if (!systemShowsCopyToast) vm.toast("Скопировано")
            }) { Icon(Icons.Filled.ContentCopy, "Копировать $label") }
        }
    }
}
