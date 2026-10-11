package org.scmess.app.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Draw
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.scmess.app.crypto.Pem
import org.scmess.app.crypto.ScException
import org.scmess.app.data.Contact

private data class ImportDraft(val name: String, val text: String)

/** "RSA_ivan_pub_20240101.pem" → "ivan"; otherwise the file name without extension. */
private fun guessName(file: String): String =
    Regex("^RSA_(?:imported_)?(.+?)_(?:pub|priv)_").find(file)?.groupValues?.get(1)
        ?: file.substringBeforeLast('.')

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeysScreen(vm: AppViewModel) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val contacts by vm.contacts.collectAsStateWithLifecycle()
    val mine = contacts.filter { it.isMine }
    val others = contacts.filter { !it.isMine }

    var addSheet by rememberSaveable { mutableStateOf(false) }
    var generate by rememberSaveable { mutableStateOf(false) }
    var draft by remember { mutableStateOf<ImportDraft?>(null) }
    var detailsId by rememberSaveable { mutableStateOf<String?>(null) }

    val pickKey = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            try {
                val text = withContext(Dispatchers.IO) {
                    ctx.contentResolver.openInputStream(uri)?.use { s ->
                        val b = s.readNBytes(64 * 1024 + 1)
                        if (b.size > 64 * 1024) throw ScException("Файл слишком большой для ключа")
                        String(b)
                    } ?: throw ScException("Не удалось открыть файл")
                }
                draft = ImportDraft(guessName(vm.displayName(uri)), text)
            } catch (e: Exception) {
                vm.toast(e.message ?: "Ошибка чтения файла")
            }
        }
    }

    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        topBar = { TopAppBar(title = { Text("Ключи") }, scrollBehavior = scroll) },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { addSheet = true },
                icon = { Icon(Icons.Filled.Add, null) },
                text = { Text("Добавить") },
            )
        },
    ) { pad ->
        if (vm.loaded && contacts.isEmpty()) {
            EmptyKeys(Modifier.padding(pad)) { generate = true }
        } else {
            LazyColumn(contentPadding = PaddingValues(top = pad.calculateTopPadding(), bottom = 96.dp)) {
                if (mine.isNotEmpty()) {
                    item { Section("Мои ключи") }
                    items(mine, key = { it.id }) { ContactRow(it) { detailsId = it.id } }
                }
                if (others.isNotEmpty()) {
                    item { Section("Контакты") }
                    items(others, key = { it.id }) { ContactRow(it) { detailsId = it.id } }
                }
            }
        }
    }

    if (addSheet) {
        val state = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(onDismissRequest = { addSheet = false }, sheetState = state) {
            Column(Modifier.padding(bottom = 16.dp)) {
                SheetAction(Icons.Filled.AutoAwesome, "Создать свою пару ключей", "Приватный остаётся на телефоне, публичный отдаёте друзьям") {
                    addSheet = false; generate = true
                }
                SheetAction(Icons.Filled.FileOpen, "Импорт из файла", ".pem — публичный ключ друга или ваш приватный") {
                    addSheet = false; pickKey.launch(arrayOf("*/*"))
                }
                SheetAction(Icons.Filled.ContentPaste, "Вставить текстом", "Ключ, присланный в мессенджере") {
                    addSheet = false; draft = ImportDraft("", ctx.pasteText()?.takeIf { "-----BEGIN" in it } ?: "")
                }
            }
        }
    }

    if (generate) GenerateDialog(vm) { generate = false }
    draft?.let { d -> ImportDialog(vm, d, contacts) { draft = null } }
    contacts.find { it.id == detailsId }?.let { c -> DetailsSheet(vm, c) { detailsId = null } }
}

@Composable
private fun Section(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp),
    )
}

@Composable
private fun ContactRow(c: Contact, onClick: () -> Unit) {
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        leadingContent = { Avatar(c.name, c.isMine) },
        headlineContent = { Text(c.name) },
        supportingContent = {
            Text(c.fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        },
        trailingContent = { Text(c.kind, style = MaterialTheme.typography.labelSmall) },
    )
}

@Composable
private fun SheetAction(icon: ImageVector, title: String, sub: String, onClick: () -> Unit) {
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        colors = ListItemDefaults.colors(containerColor = androidx.compose.ui.graphics.Color.Transparent),
        leadingContent = { Icon(icon, null, tint = MaterialTheme.colorScheme.primary) },
        headlineContent = { Text(title) },
        supportingContent = { Text(sub) },
    )
}

@Composable
private fun EmptyKeys(modifier: Modifier, onCreate: () -> Unit) {
    Column(
        modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Filled.Key, null, Modifier.size(64.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(16.dp))
        Text("Ключей пока нет", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Text(
            "Создайте свою пару ключей и отправьте публичный ключ друзьям. Их публичные ключи добавьте сюда — и можно переписываться.",
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(24.dp))
        Button(onClick = onCreate) { Text("Создать ключи") }
    }
}

@Composable
private fun GenerateDialog(vm: AppViewModel, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var name by rememberSaveable { mutableStateOf("") }
    var kind by rememberSaveable { mutableStateOf(KeyKind.CURVE25519) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDone() },
        icon = { Icon(Icons.Filled.AutoAwesome, null) },
        title = { Text("Новая пара ключей") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                OutlinedTextField(
                    name, { name = it; error = null },
                    label = { Text("Имя") },
                    singleLine = true,
                    enabled = !busy,
                    isError = error != null,
                    supportingText = error?.let { { Text(it) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    listOf(KeyKind.CURVE25519 to "25519", KeyKind.RSA4096 to "RSA-4096", KeyKind.RSA2048 to "RSA-2048")
                        .forEachIndexed { i, (k, label) ->
                            SegmentedButton(
                                selected = kind == k, onClick = { kind = k }, enabled = !busy,
                                shape = SegmentedButtonDefaults.itemShape(i, 3),
                            ) { Text(label, maxLines = 1) }
                        }
                }
                Text(
                    when (kind) {
                        KeyKind.CURVE25519 -> "X25519 + Ed25519: короткий ключ, мгновенная генерация. Работает только между приложениями SCmess для Android."
                        else -> "Совместимо с SCmess для ПК, Rust и C. Ключ подписи Ed25519 добавляется автоматически."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (busy) Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(12.dp))
                    Text("Генерация… до нескольких секунд", style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = {
                error = vm.validateName(name)
                if (error != null) return@TextButton
                busy = true
                scope.launch {
                    try {
                        vm.generate(name, kind); onDone()
                    } catch (e: Exception) {
                        error = e.message; busy = false
                    }
                }
            }) { Text("Создать") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDone) { Text("Отмена") } },
    )
}

@Composable
private fun ImportDialog(vm: AppViewModel, initial: ImportDraft, contacts: List<Contact>, onDone: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var name by rememberSaveable { mutableStateOf(initial.name) }
    var text by rememberSaveable { mutableStateOf(initial.text) }
    var error by remember { mutableStateOf<String?>(null) }
    val parsed = remember(text) { if (text.isBlank()) null else runCatching { Pem.parse(text) } }
    val keys = parsed?.getOrNull()
    val pub = keys?.public?.takeIf { it.canEncrypt }
    val existing = pub?.let(vm::findSame)
    val isPrivate = keys?.private?.canDecrypt == true
    val foreignSigning = keys != null && pub != null && vm.addsForeignSigningKey(keys)
    var confirmed by remember(text) { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDone,
        icon = { Icon(Icons.Filled.Key, null) },
        title = { Text("Импорт ключа") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    text, { text = it; error = null },
                    label = { Text("PEM-ключ") },
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    minLines = 4, maxLines = 8,
                    modifier = Modifier.fillMaxWidth(),
                    trailingIcon = {
                        IconButton(onClick = { ctx.pasteText()?.let { text = it } }) { Icon(Icons.Filled.ContentPaste, "Вставить") }
                    },
                )
                val status = when {
                    parsed == null -> null
                    parsed.isFailure -> parsed.exceptionOrNull()?.message ?: "Не удалось прочитать ключ"
                    pub == null -> "Нужен ключ шифрования (RSA или X25519), а не только ключ подписи"
                    else -> null
                }
                if (status != null) ErrorNote(status)
                else if (pub != null) Text(
                    (if (isPrivate) "Приватный (ваш) ключ" else "Публичный ключ") + " · " +
                        Contact("", "", pub, null).kind + "\n" + Pem.fingerprint(pub),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                if (existing != null && foreignSigning) {
                    Text(
                        "В ключе «${existing.name}» появился ключ подписи. Его мог подложить кто угодно, кто знает публичный ключ " +
                            "«${existing.name}». Сверьте новый отпечаток с владельцем голосом или лично:",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(Pem.fingerprint(pub), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleSmall)
                    Row(
                        Modifier.fillMaxWidth().clickable { confirmed = !confirmed },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(checked = confirmed, onCheckedChange = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Отпечаток сверен, это действительно ключ «${existing.name}»")
                    }
                } else if (existing != null) Text("Совпадает с «${existing.name}»: недостающие части ключа будут добавлены к нему.")
                else OutlinedTextField(
                    name, { name = it; error = null },
                    label = { Text("Имя") }, singleLine = true,
                    isError = error != null, supportingText = error?.let { { Text(it) } },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = pub != null && (!foreignSigning || confirmed),
                onClick = {
                    scope.launch {
                        try {
                            vm.import(name, text, signingKeyConfirmed = confirmed); onDone()
                        } catch (e: Exception) {
                            error = e.message
                        }
                    }
                },
            ) { Text("Сохранить") }
        },
        dismissButton = { TextButton(onClick = onDone) { Text("Отмена") } },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DetailsSheet(vm: AppViewModel, c: Contact, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var rename by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var confirmExport by remember { mutableStateOf(false) }
    val savePem = rememberLauncherForActivityResult(CreateDoc()) { uri ->
        val pem = pendingPem.value ?: return@rememberLauncherForActivityResult
        pendingPem.value = null
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                withContext(Dispatchers.IO) { ctx.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(pem.toByteArray()) } }
            }.onSuccess { vm.toast("Ключ сохранён") }.onFailure { vm.toast("Не удалось сохранить: ${it.message}") }
        }
    }
    val safe = c.name.replace(Regex("[^\\p{L}\\p{N}_-]"), "_")

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(Modifier.navigationBarsPadding().padding(bottom = 16.dp)) {
            Column(
                Modifier.fillMaxWidth().padding(horizontal = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Avatar(c.name, c.isMine, 64.dp)
                Text(c.name, style = MaterialTheme.typography.headlineSmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SuggestionChip(onClick = {}, label = { Text(if (c.isMine) "Мой ключ" else "Контакт") })
                    SuggestionChip(onClick = {}, label = { Text(c.kind) })
                }
                SelectionContainer {
                    Text(c.fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
                }
                Text(
                    "Отпечаток: сверьте его с владельцем ключа голосом или лично",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
            Spacer(Modifier.height(12.dp))
            HorizontalDivider()
            SheetAction(Icons.Filled.Share, "Отправить публичный ключ", "Через мессенджер или почту") {
                ctx.shareText(c.publicPem, "Публичный ключ ${c.name}")
            }
            SheetAction(Icons.Filled.ContentCopy, "Копировать публичный ключ", "PEM-текст в буфер обмена") {
                ctx.copyText(c.publicPem)
                if (!systemShowsCopyToast) vm.toast("Скопировано")
            }
            SheetAction(Icons.Filled.Save, "Сохранить публичный ключ", "Файл .pem") {
                pendingPem.value = c.publicPem
                savePem.launch("RSA_${safe}_pub.pem" to "application/x-pem-file")
            }
            if (c.isMine) SheetAction(Icons.Filled.Warning, "Экспорт приватного ключа", "Для переноса на другое устройство") {
                confirmExport = true
            }
            if (c.isMine && !c.canSign) SheetAction(Icons.Filled.Draw, "Добавить ключ подписи", "Ed25519: друзья смогут проверять, что пишете именно вы") {
                vm.addSigningKey(c.id)
            }
            SheetAction(Icons.Filled.Edit, "Переименовать", "Имя видно только вам") { rename = true }
            ListItem(
                modifier = Modifier.clickable { confirmDelete = true },
                colors = ListItemDefaults.colors(containerColor = androidx.compose.ui.graphics.Color.Transparent),
                leadingContent = { Icon(Icons.Filled.Delete, null, tint = MaterialTheme.colorScheme.error) },
                headlineContent = { Text("Удалить", color = MaterialTheme.colorScheme.error) },
            )
        }
    }

    if (confirmExport) AlertDialog(
        onDismissRequest = { confirmExport = false },
        icon = { Icon(Icons.Filled.Warning, null) },
        title = { Text("Экспорт приватного ключа") },
        text = { Text("Любой, у кого окажется этот файл, сможет читать ваши сообщения. Храните его только у себя и никому не отправляйте.") },
        confirmButton = {
            TextButton(onClick = {
                confirmExport = false
                pendingPem.value = c.privatePem
                savePem.launch("RSA_${safe}_priv.pem" to "application/x-pem-file")
            }) { Text("Понятно, сохранить") }
        },
        dismissButton = { TextButton(onClick = { confirmExport = false }) { Text("Отмена") } },
    )

    if (confirmDelete) AlertDialog(
        onDismissRequest = { confirmDelete = false },
        icon = { Icon(Icons.Filled.Delete, null) },
        title = { Text("Удалить «${c.name}»?") },
        text = {
            Text(
                if (c.isMine) "Приватный ключ будет удалён навсегда. Сообщения и файлы, зашифрованные для него, больше не открыть, если нет копии."
                else "Публичный ключ контакта будет удалён. Его всегда можно добавить снова."
            )
        },
        confirmButton = {
            TextButton(onClick = { confirmDelete = false; onDismiss(); vm.delete(c.id) }) {
                Text("Удалить", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Отмена") } },
    )

    if (rename) {
        var name by rememberSaveable { mutableStateOf(c.name) }
        var error by remember { mutableStateOf<String?>(null) }
        AlertDialog(
            onDismissRequest = { rename = false },
            title = { Text("Переименовать") },
            text = {
                OutlinedTextField(
                    name, { name = it; error = null }, singleLine = true, label = { Text("Имя") },
                    isError = error != null, supportingText = error?.let { { Text(it) } },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    error = vm.validateName(name, c.id)
                    if (error == null) { vm.rename(c.id, name); rename = false }
                }) { Text("Сохранить") }
            },
            dismissButton = { TextButton(onClick = { rename = false }) { Text("Отмена") } },
        )
    }
}

// Not rememberSaveable on purpose: it may hold a private key, which must not end up in saved state.
private val pendingPem = mutableStateOf<String?>(null)
