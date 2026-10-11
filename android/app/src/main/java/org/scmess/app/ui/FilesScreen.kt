package org.scmess.app.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.webkit.MimeTypeMap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** ACTION_CREATE_DOCUMENT with a per-call file name and MIME type. */
internal class CreateDoc : ActivityResultContract<Pair<String, String>, Uri?>() {
    override fun createIntent(context: Context, input: Pair<String, String>) =
        Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType(input.second)
            .putExtra(Intent.EXTRA_TITLE, input.first)

    override fun parseResult(resultCode: Int, intent: Intent?) =
        intent?.data.takeIf { resultCode == Activity.RESULT_OK }
}

private fun mimeOf(name: String) =
    MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase())
        ?: "application/octet-stream"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FilesScreen(vm: AppViewModel) {
    val contacts by vm.contacts.collectAsStateWithLifecycle()
    val mine = contacts.filter { it.isMine }
    var recipientId by rememberSaveable { mutableStateOf<String?>(null) }
    val recipient = contacts.find { it.id == recipientId } ?: contacts.firstOrNull()

    var src by rememberSaveable { mutableStateOf<Uri?>(null) }
    var encrypting by rememberSaveable { mutableStateOf(true) }

    val save = rememberLauncherForActivityResult(CreateDoc()) { dst ->
        val s = src
        if (dst != null && s != null) {
            if (encrypting) recipient?.let { vm.encryptFile(s, dst, it.id) } else vm.decryptFile(s, dst)
        }
        src = null
    }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        src = uri
        val name = vm.displayName(uri)
        if (encrypting) save.launch("$name.enc" to "application/octet-stream")
        else {
            val out = if (name.endsWith(".enc", ignoreCase = true)) name.dropLast(4) else "$name.dec"
            save.launch(out to mimeOf(out))
        }
    }

    val busy = vm.fileTask != null
    Column(Modifier.fillMaxWidth()) {
        TopAppBar(title = { Text("Файлы") })
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            AnimatedVisibility(busy) {
                vm.fileTask?.let { t ->
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text(
                                (if (t.encrypt) "Шифрование · " else "Расшифровка · ") + t.name,
                                style = MaterialTheme.typography.titleSmall,
                                maxLines = 1, overflow = TextOverflow.Ellipsis,
                            )
                            val p = t.progress
                            if (p == null) LinearProgressIndicator(Modifier.fillMaxWidth())
                            else LinearProgressIndicator(progress = { p }, modifier = Modifier.fillMaxWidth())
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(p?.let { "${(it * 100).toInt()} %" } ?: "", Modifier.weight(1f))
                                OutlinedButton(onClick = vm::cancelFile) { Text("Отмена") }
                            }
                        }
                    }
                }
            }

            ActionCard(
                icon = Icons.Filled.Lock,
                title = "Зашифровать файл",
                text = "Открыть файл сможет только получатель своим приватным ключом. Размер не ограничен.",
            ) {
                if (contacts.isEmpty()) {
                    Text("Сначала добавьте ключ во вкладке «Ключи»", color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    var open by rememberSaveable { mutableStateOf(false) }
                    ExposedDropdownMenuBox(expanded = open, onExpandedChange = { open = it }) {
                        OutlinedTextField(
                            value = recipient?.let { if (it.isMine) "${it.name} (я)" else it.name } ?: "",
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Получатель") },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(open) },
                            modifier = Modifier.fillMaxWidth().menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable),
                        )
                        ExposedDropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                            for (c in contacts) DropdownMenuItem(
                                text = { Text(if (c.isMine) "${c.name} (я)" else c.name) },
                                leadingIcon = { Avatar(c.name, c.isMine, 28.dp) },
                                onClick = { recipientId = c.id; open = false },
                            )
                        }
                    }
                }
                Button(
                    onClick = { encrypting = true; pick.launch(arrayOf("*/*")) },
                    enabled = !busy && recipient != null,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                ) {
                    Icon(Icons.Filled.FileOpen, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Выбрать файл")
                }
            }

            ActionCard(
                icon = Icons.Filled.LockOpen,
                title = "Расшифровать файл",
                text = "Ключ подбирается автоматически. Подходят файлы .enc из SCmess для ПК и старой версии приложения.",
            ) {
                FilledTonalButton(
                    onClick = { encrypting = false; pick.launch(arrayOf("*/*")) },
                    enabled = !busy && mine.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                ) {
                    Icon(Icons.Filled.FileOpen, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Выбрать файл .enc")
                }
                if (mine.isEmpty()) Text(
                    "Нужен свой приватный ключ",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ActionCard(icon: ImageVector, title: String, text: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(12.dp))
                Text(title, style = MaterialTheme.typography.titleMedium)
            }
            Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            content()
        }
    }
}
