package org.scmess.app.ui

import android.app.Application
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.scmess.app.crypto.Decrypted
import org.scmess.app.crypto.Pem
import org.scmess.app.crypto.ScCrypto
import org.scmess.app.crypto.ScException
import org.scmess.app.data.Contact
import org.scmess.app.data.ContactStore
import org.scmess.app.data.SettingsStore
import kotlin.coroutines.coroutineContext

enum class Tab { MESSAGES, FILES, KEYS, SETTINGS }

sealed interface MessageResult {
    data class Encrypted(val text: String, val recipients: List<String>, val legacy: Boolean) : MessageResult
    data class Plain(val value: Decrypted) : MessageResult
}

data class FileTask(val name: String, val encrypt: Boolean, val progress: Float?)

class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val store = ContactStore(app)
    val settings = SettingsStore(app)

    private val _contacts = MutableStateFlow<List<Contact>>(emptyList())
    val contacts = _contacts.asStateFlow()
    var loaded by mutableStateOf(false)
        private set

    private val _events = Channel<String>(Channel.BUFFERED)
    val events = _events.receiveAsFlow()
    fun toast(msg: String) {
        _events.trySend(msg)
    }

    var tab by mutableStateOf(Tab.MESSAGES)

    // Messages tab
    var decryptMode by mutableStateOf(false)
    var input by mutableStateOf("")
    var selected by mutableStateOf(setOf<String>())
    var legacy by mutableStateOf(false)
    var result by mutableStateOf<MessageResult?>(null)
    var messageError by mutableStateOf<String?>(null)
    var working by mutableStateOf(false)
        private set

    // Files tab
    var fileTask by mutableStateOf<FileTask?>(null)
        private set
    private var fileJob: Job? = null

    init {
        viewModelScope.launch {
            _contacts.value = withContext(Dispatchers.IO) { store.load() }
            loaded = true
        }
    }

    fun openShared(text: String) {
        tab = Tab.MESSAGES
        decryptMode = true
        input = text
        result = null
        messageError = null
    }

    // ───────────── keys ─────────────

    private suspend fun commit(list: List<Contact>) {
        withContext(Dispatchers.IO) { store.save(list) }
        _contacts.value = list
    }

    private fun nameTaken(name: String, exceptId: String? = null) =
        _contacts.value.any { it.id != exceptId && it.name.equals(name, ignoreCase = true) }

    /** Returns an error text or null when the name is fine. */
    fun validateName(name: String, exceptId: String? = null): String? = when {
        name.isBlank() -> "Введите имя"
        nameTaken(name.trim(), exceptId) -> "Такое имя уже есть"
        else -> null
    }

    suspend fun generate(name: String, bits: Int) {
        val (pub, priv) = withContext(Dispatchers.Default) { ScCrypto.generate(bits) }
        commit(_contacts.value + Contact(ContactStore.newId(), name.trim(), pub, priv))
        toast("Ключи «${name.trim()}» созданы")
    }

    /** Adds a key; a key whose fingerprint is already known updates that contact instead. */
    suspend fun import(name: String, pem: String) {
        val parsed = withContext(Dispatchers.Default) { Pem.parse(pem) }
        val pub = parsed.public ?: throw ScException("Ключ не найден")
        val fp = Pem.fingerprint(pub)
        val list = _contacts.value
        val same = list.find { it.fingerprint == fp }
        if (same != null) {
            if (parsed.private == null || same.isMine) throw ScException("Этот ключ уже есть: «${same.name}»")
            commit(list.map { if (it.id == same.id) Contact(it.id, it.name, pub, parsed.private) else it })
            toast("К «${same.name}» добавлен приватный ключ")
            return
        }
        validateName(name)?.let { throw ScException(it) }
        commit(list + Contact(ContactStore.newId(), name.trim(), pub, parsed.private))
        toast(if (parsed.private != null) "Ваш ключ «${name.trim()}» импортирован" else "Контакт «${name.trim()}» добавлен")
    }

    fun rename(id: String, name: String) = viewModelScope.launch {
        commit(_contacts.value.map { if (it.id == id) Contact(it.id, name.trim(), it.publicKey, it.privateKey) else it })
    }

    fun delete(id: String) = viewModelScope.launch {
        val c = _contacts.value.find { it.id == id } ?: return@launch
        commit(_contacts.value.filter { it.id != id })
        selected = selected - id
        toast("«${c.name}» удалён")
    }

    // ───────────── messages ─────────────

    fun runMessage() {
        if (working) return
        val text = input
        messageError = null
        if (text.isBlank()) {
            messageError = if (decryptMode) "Вставьте зашифрованное сообщение" else "Введите текст"
            return
        }
        val all = _contacts.value
        working = true
        viewModelScope.launch {
            try {
                result = withContext(Dispatchers.Default) {
                    if (decryptMode) {
                        MessageResult.Plain(ScCrypto.decrypt(text, all.mapNotNull { it.ownKey() }))
                    } else {
                        val to = all.filter { it.id in selected }
                        when {
                            to.isEmpty() -> throw ScException("Выберите получателя")
                            legacy && to.size == 1 -> MessageResult.Encrypted(
                                ScCrypto.encryptLegacy(to[0].publicKey, text), to.map { it.name }, true
                            )
                            to.size == 1 -> MessageResult.Encrypted(
                                ScCrypto.encryptSingle(to[0].publicKey, text), to.map { it.name }, false
                            )
                            else -> MessageResult.Encrypted(
                                ScCrypto.encryptGroup(to.map { it.publicKey }, text), to.map { it.name }, false
                            )
                        }
                    }
                }
            } catch (e: ScException) {
                messageError = e.message
            } catch (e: Exception) {
                messageError = "Ошибка: ${e.message ?: e.javaClass.simpleName}"
            } finally {
                working = false
            }
        }
    }

    // ───────────── files ─────────────

    fun displayName(uri: Uri): String {
        getApplication<Application>().contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { if (it.moveToFirst()) it.getString(0)?.let { n -> return n } }
        return uri.lastPathSegment?.substringAfterLast('/') ?: "file"
    }

    private fun size(uri: Uri): Long =
        getApplication<Application>().contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)
            ?.use { if (it.moveToFirst() && !it.isNull(0)) it.getLong(0) else -1L } ?: -1L

    fun encryptFile(src: Uri, dst: Uri, contactId: String) {
        val c = _contacts.value.find { it.id == contactId } ?: return
        runFile(src, dst, true) { input, output, progress ->
            ScCrypto.encryptFile(c.publicKey, input, output, progress)
            "Зашифровано для «${c.name}»"
        }
    }

    fun decryptFile(src: Uri, dst: Uri) {
        val keys = _contacts.value.mapNotNull { it.ownKey() }
        runFile(src, dst, false) { input, output, progress ->
            "Расшифровано ключом «${ScCrypto.decryptFile(keys, input, output, progress)}»"
        }
    }

    private fun runFile(
        src: Uri, dst: Uri, encrypt: Boolean,
        work: (java.io.InputStream, java.io.OutputStream, (Long) -> Unit) -> String,
    ) {
        if (fileJob?.isActive == true) return
        val cr = getApplication<Application>().contentResolver
        val outName = displayName(dst)
        fileTask = FileTask(displayName(src), encrypt, null)
        fileJob = viewModelScope.launch {
            var ok = false
            try {
                val total = withContext(Dispatchers.IO) { size(src) }
                val msg = withContext(Dispatchers.IO) {
                    val ctx = coroutineContext
                    var last = 0L
                    cr.openInputStream(src).use { input ->
                        cr.openOutputStream(dst, "wt").use { output ->
                            if (input == null || output == null) throw ScException("Не удалось открыть файл")
                            val out = output.buffered()
                            work(input.buffered(), out) { done ->
                                ctx.ensureActive()
                                if (total > 0 && done - last > total / 200) {
                                    last = done
                                    fileTask = fileTask?.copy(progress = (done.toFloat() / total).coerceAtMost(1f))
                                }
                            }.also { out.flush() }
                        }
                    }
                }
                ok = true
                toast("$msg → $outName")
            } catch (e: CancellationException) {
                toast("Отменено")
            } catch (e: ScException) {
                toast(e.message ?: "Ошибка")
            } catch (e: Exception) {
                toast("Ошибка: ${e.message ?: e.javaClass.simpleName}")
            } finally {
                if (!ok) withContext(Dispatchers.IO + kotlinx.coroutines.NonCancellable) {
                    runCatching { DocumentsContract.deleteDocument(cr, dst) }
                }
                fileTask = null
            }
        }
    }

    fun cancelFile() {
        fileJob?.cancel()
    }
}
