package org.scmess.app.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.scmess.app.crypto.MessageFormat
import org.scmess.app.crypto.SigStatus
import androidx.compose.foundation.layout.Box
import androidx.compose.material.icons.filled.Draw
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.automirrored.outlined.HelpOutline
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun MessagesScreen(vm: AppViewModel) {
    val ctx = LocalContext.current
    val contacts by vm.contacts.collectAsStateWithLifecycle()
    val settings by vm.settings.state.collectAsStateWithLifecycle()
    val recipients = contacts
    val result = vm.result

    // Auto-copy freshly encrypted text.
    LaunchedEffect(result) {
        if (result is MessageResult.Encrypted && settings.autoCopy) {
            ctx.copyText(result.text)
            if (!systemShowsCopyToast) vm.toast("Скопировано в буфер обмена")
        }
    }

    Column(Modifier.fillMaxWidth()) {
        TopAppBar(title = { Text("SCmess") })
        Column(
            Modifier.verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                listOf(false to "Зашифровать", true to "Расшифровать").forEachIndexed { i, (mode, label) ->
                    SegmentedButton(
                        selected = vm.decryptMode == mode,
                        onClick = {
                            if (vm.decryptMode != mode) {
                                vm.decryptMode = mode
                                vm.result = null
                                vm.messageError = null
                                vm.input = ""
                            }
                        },
                        shape = SegmentedButtonDefaults.itemShape(i, 2),
                        icon = { SegmentedButtonDefaults.Icon(vm.decryptMode == mode) {
                            Icon(if (mode) Icons.Filled.LockOpen else Icons.Filled.Lock, null, Modifier.size(18.dp))
                        } },
                    ) { Text(label) }
                }
            }

            if (!vm.decryptMode) {
                Text("Кому", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (recipients.isEmpty()) {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh)) {
                        ListItem(
                            colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
                            leadingContent = { Icon(Icons.Filled.PersonAdd, null) },
                            headlineContent = { Text("Пока нет ключей") },
                            supportingContent = { Text("Создайте свои ключи или добавьте ключ друга") },
                            trailingContent = { TextButton(onClick = { vm.tab = Tab.KEYS }) { Text("К ключам") } },
                        )
                    }
                } else {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        for (c in recipients) {
                            val sel = c.id in vm.selected
                            FilterChip(
                                selected = sel,
                                onClick = { vm.selected = if (sel) vm.selected - c.id else vm.selected + c.id; vm.result = null },
                                label = { Text(if (c.isMine) "${c.name} (я)" else c.name) },
                                leadingIcon = if (sel) {
                                    { Icon(Icons.Filled.Check, null, Modifier.size(FilterChipDefaults.IconSize)) }
                                } else null,
                            )
                        }
                    }
                    val chosen = recipients.filter { it.id in vm.selected }
                    val count = chosen.size
                    AnimatedVisibility(count == 1 && chosen[0].compatible) {
                        ListItem(
                            modifier = Modifier.fillMaxWidth(),
                            colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surface),
                            headlineContent = { Text("Legacy RSA") },
                            supportingContent = { Text("Старый формат без AES: только короткий текст") },
                            trailingContent = { Switch(vm.legacy, { vm.legacy = it; vm.result = null }) },
                        )
                    }
                    if (count > 1) Hint("Групповое сообщение: каждый из $count получателей сможет его прочитать")
                    if (chosen.any { !it.compatible }) Hint("У получателей с ключом X25519 сообщение откроется только в приложении SCmess для Android")
                    if (!(vm.legacy && count == 1 && chosen[0].compatible)) SignerRow(vm, contacts)
                }
            }

            OutlinedTextField(
                value = vm.input,
                onValueChange = { vm.input = it; vm.messageError = null },
                modifier = Modifier.fillMaxWidth().heightIn(min = 160.dp),
                label = { Text(if (vm.decryptMode) "Зашифрованное сообщение" else "Текст сообщения") },
                textStyle = if (vm.decryptMode) MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace)
                else MaterialTheme.typography.bodyLarge,
                isError = vm.messageError != null,
                supportingText = vm.messageError?.let { { Text(it) } },
                trailingIcon = {
                    if (vm.input.isNotEmpty()) IconButton(onClick = { vm.input = ""; vm.result = null; vm.messageError = null }) {
                        Icon(Icons.Filled.Close, "Очистить")
                    } else IconButton(onClick = { ctx.pasteText()?.let { vm.input = it } }) {
                        Icon(Icons.Filled.ContentPaste, "Вставить")
                    }
                },
            )

            Button(
                onClick = vm::runMessage,
                enabled = !vm.working,
                modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
                contentPadding = ButtonDefaults.ButtonWithIconContentPadding,
            ) {
                if (vm.working) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                else Icon(if (vm.decryptMode) Icons.Filled.LockOpen else Icons.Filled.Lock, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(if (vm.decryptMode) "Расшифровать" else "Зашифровать")
            }

            AnimatedVisibility(result != null) {
                if (result != null) ResultCard(result, vm)
            }
        }
    }
}

@Composable
private fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun SignerRow(vm: AppViewModel, contacts: List<org.scmess.app.data.Contact>) {
    val signers = contacts.filter { it.canSign }
    var open by remember { mutableStateOf(false) }
    val current = vm.signerContact()
    ListItem(
        modifier = Modifier.fillMaxWidth(),
        colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surface),
        leadingContent = { Icon(Icons.Filled.Draw, null) },
        headlineContent = { Text("Подпись") },
        supportingContent = {
            Text(
                when {
                    signers.isEmpty() -> "Нет ключа подписи: создайте ключи или добавьте подпись к своим"
                    current == null -> "Без подписи"
                    else -> "От имени «${current.name}»: получатель увидит, что писали вы"
                }
            )
        },
        trailingContent = {
            if (signers.isNotEmpty()) Box {
                TextButton(onClick = { open = true }) { Text(current?.name ?: "Нет") }
                DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                    for (c in signers) DropdownMenuItem(text = { Text(c.name) }, onClick = { vm.signerId = c.id; open = false })
                    DropdownMenuItem(text = { Text("Без подписи") }, onClick = { vm.signerId = NO_SIGNER; open = false })
                }
            }
        },
    )
}

@Composable
private fun SigLine(sig: SigStatus) {
    val (icon, text, color) = when (sig) {
        SigStatus.Unsigned -> Triple(Icons.AutoMirrored.Outlined.HelpOutline, "Без подписи — отправителя не проверить", MaterialTheme.colorScheme.onSurfaceVariant)
        SigStatus.Invalid -> Triple(Icons.Filled.Warning, "Подпись недействительна! Сообщение подделано или повреждено", MaterialTheme.colorScheme.error)
        is SigStatus.Valid -> Triple(Icons.Filled.Verified, "Подписано: ${sig.name}", MaterialTheme.colorScheme.primary)
        is SigStatus.Unknown -> Triple(Icons.AutoMirrored.Outlined.HelpOutline, "Подписано неизвестным ключом ${sig.fingerprint}", MaterialTheme.colorScheme.tertiary)
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, tint = color, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(text, color = color, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ResultCard(result: MessageResult, vm: AppViewModel) {
    val ctx = LocalContext.current
    val (title, body, sensitive) = when (result) {
        is MessageResult.Encrypted -> Triple(
            buildString {
                append(if (result.legacy) "Legacy RSA · " else "")
                append(if (result.recipients.size == 1) "для ${result.recipients[0]}" else "для ${result.recipients.size} получателей")
                result.signedBy?.let { append(" · подписано") }
            },
            result.text, false,
        )
        is MessageResult.Plain -> Triple(
            buildString {
                append("Ключ «${result.value.keyName}»")
                when (result.value.format) {
                    MessageFormat.GROUP -> append(" · группа")
                    MessageFormat.LEGACY -> append(" · legacy")
                    MessageFormat.SINGLE -> {}
                }
                result.value.sender?.let { append(" · от $it") }
            },
            result.value.text, true,
        )
    }
    val encrypted = result is MessageResult.Encrypted
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    if (encrypted) Icons.Filled.Lock else Icons.Filled.LockOpen, null,
                    tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(title, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            }
            if (result is MessageResult.Plain && result.value.format != MessageFormat.LEGACY) SigLine(result.value.sig)
            SelectionContainer {
                Text(
                    body,
                    style = if (encrypted) MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace)
                    else MaterialTheme.typography.bodyLarge,
                    maxLines = if (encrypted) 8 else Int.MAX_VALUE,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(onClick = {
                    ctx.copyText(body, sensitive)
                    if (!systemShowsCopyToast) vm.toast("Скопировано")
                }) {
                    Icon(Icons.Filled.ContentCopy, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Копировать")
                }
                if (encrypted) TextButton(onClick = { ctx.shareText(body, "Отправить сообщение") }) {
                    Icon(Icons.Filled.Share, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Отправить")
                }
            }
        }
    }
}

@Composable
fun ErrorNote(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Outlined.ErrorOutline, null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(text, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
    }
}
