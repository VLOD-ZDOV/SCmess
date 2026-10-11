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
import org.scmess.app.crypto.PrivateKeys
import org.scmess.app.crypto.PublicKeys
import org.scmess.app.crypto.SigStatus
import org.scmess.app.crypto.ScCrypto
import org.scmess.app.crypto.ScException
import org.scmess.app.data.Contact
import org.scmess.app.data.ContactStore
import org.scmess.app.data.SettingsStore
import org.scmess.app.data.Updates
import kotlin.coroutines.coroutineContext

enum class Tab { MESSAGES, FILES, HASHES, KEYS, SETTINGS }

sealed interface MessageResult {
    data class Encrypted(val text: String, val recipients: List<String>, val legacy: Boolean, val signedBy: String?) : MessageResult
    data class Plain(val value: Decrypted) : MessageResult
}

data class FileTask(val name: String, val encrypt: Boolean, val progress: Float?)

data class HashTask(val name: String, val progress: Float, val result: ScCrypto.Hashes?)

enum class KeyKind { CURVE25519, RSA4096, RSA2048 }

const val NO_SIGNER = "none"

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

    // ───────────── updates ─────────────

    val version: String = app.packageManager.getPackageInfo(app.packageName, 0).versionName ?: "?"
    var update by mutableStateOf<Updates.Release?>(null)
    var updateStatus by mutableStateOf<String?>(null)
        private set
    var checkingUpdates by mutableStateOf(false)
        private set

    // Must stay below the update state above: properties initialize in declaration order.
    init {
        val day = 24 * 60 * 60 * 1000L
        if (settings.state.value.checkUpdates && System.currentTimeMillis() - settings.lastUpdateCheck > day) {
            checkUpdates(manual = false)
        }
    }

    fun checkUpdates(manual: Boolean) {
        if (checkingUpdates) return
        checkingUpdates = true
        viewModelScope.launch {
            try {
                val r = withContext(Dispatchers.IO) { Updates.latest() }
                settings.lastUpdateCheck = System.currentTimeMillis()
                if (Updates.isNewer(r.version, version)) {
                    update = r
                    updateStatus = "Доступна версия ${r.version}"
                } else {
                    updateStatus = "У вас последняя версия"
                    if (manual) toast("У вас последняя версия")
                }
            } catch (e: Exception) {
                android.util.Log.w("SCmess", "update check failed", e)
                updateStatus = "Не удалось проверить: нет связи с GitHub"
                if (manual) toast(updateStatus!!)
            } finally {
                checkingUpdates = false
            }
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

    /** Every new identity also gets an Ed25519 signing key. */
    suspend fun generate(name: String, kind: KeyKind) {
        val priv = withContext(Dispatchers.Default) {
            when (kind) {
                KeyKind.CURVE25519 -> PrivateKeys(x25519 = ScCrypto.generateX25519(), ed25519 = ScCrypto.generateEd25519())
                KeyKind.RSA4096 -> PrivateKeys(rsa = ScCrypto.generateRsa(4096), ed25519 = ScCrypto.generateEd25519())
                KeyKind.RSA2048 -> PrivateKeys(rsa = ScCrypto.generateRsa(2048), ed25519 = ScCrypto.generateEd25519())
            }
        }
        commit(_contacts.value + Contact(ContactStore.newId(), name.trim(), priv.publicKeys(), priv))
        toast("Ключи «${name.trim()}» созданы")
    }

    /** Contact that already holds one of the encryption keys in [pub], if any. */
    fun findSame(pub: PublicKeys): Contact? = _contacts.value.find { c ->
        (pub.rsa != null && c.publicKeys.rsa == pub.rsa) ||
            (pub.x25519 != null && c.publicKeys.x25519?.encoded?.contentEquals(pub.x25519.encoded) == true)
    }

    /**
     * True when importing [parsed] would attach a signing key to an existing contact based only on
     * a public bundle. Anyone knowing the contact's public key can build such a bundle with their own
     * signing key, so the user must confirm the new fingerprint with the owner first.
     */
    fun addsForeignSigningKey(parsed: Pem.Parsed): Boolean {
        val same = findSame(parsed.public) ?: return false
        if (parsed.public.ed25519 == null || same.publicKeys.ed25519 != null) return false
        // Only the owner can include the private half of the contact's known encryption key.
        val priv = parsed.private
        val proven = (priv.rsa != null && same.publicKeys.rsa != null && Pem.publicOf(priv.rsa) == same.publicKeys.rsa) ||
            (priv.x25519 != null && same.publicKeys.x25519 != null &&
                priv.x25519.generatePublicKey().encoded.contentEquals(same.publicKeys.x25519.encoded))
        return !proven
    }

    /** Adds a contact, or merges new keys (private half, signing key) into the one that already has them. */
    suspend fun import(name: String, pem: String, signingKeyConfirmed: Boolean = false) {
        val parsed = withContext(Dispatchers.Default) { Pem.parse(pem) }
        val pub = parsed.public
        if (!pub.canEncrypt) throw ScException("Нужен ключ шифрования (RSA или X25519), а не только ключ подписи")
        val priv = parsed.private.takeIf { !it.isEmpty }
        val list = _contacts.value
        val same = findSame(pub)
        if (same != null && addsForeignSigningKey(parsed) && !signingKeyConfirmed) {
            throw ScException("Подтвердите новый ключ подписи для «${same.name}»")
        }
        if (same != null) {
            val old = same.privateKeys ?: PrivateKeys()
            // A signing private key alone does not make a contact "mine".
            val mergedPriv = PrivateKeys(old.rsa ?: priv?.rsa, old.x25519 ?: priv?.x25519, old.ed25519 ?: priv?.ed25519)
                .takeIf { it.canDecrypt }
            val p = same.publicKeys
            val mergedPub = PublicKeys(p.rsa ?: pub.rsa, p.x25519 ?: pub.x25519, p.ed25519 ?: pub.ed25519)
            val updated = Contact(same.id, same.name, mergedPub, mergedPriv)
            if (updated.privatePem == same.privatePem && updated.publicPem == same.publicPem) {
                throw ScException("Этот ключ уже есть: «${same.name}»")
            }
            commit(list.map { if (it.id == same.id) updated else it })
            toast("Ключ «${same.name}» дополнен")
            return
        }
        validateName(name)?.let { throw ScException(it) }
        commit(list + Contact(ContactStore.newId(), name.trim(), pub, priv?.takeIf { it.canDecrypt }))
        toast(if (priv?.canDecrypt == true) "Ваш ключ «${name.trim()}» импортирован" else "Контакт «${name.trim()}» добавлен")
    }

    fun addSigningKey(id: String) = viewModelScope.launch {
        val c = _contacts.value.find { it.id == id } ?: return@launch
        val priv = (c.privateKeys ?: return@launch).copy(ed25519 = ScCrypto.generateEd25519())
        commit(_contacts.value.map { if (it.id == id) Contact(it.id, it.name, priv.publicKeys(), priv) else it })
        toast("Ключ подписи добавлен — отправьте друзьям обновлённый публичный ключ")
    }

    fun rename(id: String, name: String) = viewModelScope.launch {
        commit(_contacts.value.map { if (it.id == id) Contact(it.id, name.trim(), it.publicKeys, it.privateKeys) else it })
    }

    fun delete(id: String) = viewModelScope.launch {
        val c = _contacts.value.find { it.id == id } ?: return@launch
        commit(_contacts.value.filter { it.id != id })
        selected = selected - id
        toast("«${c.name}» удалён")
    }

    // ───────────── messages ─────────────

    private fun signers(all: List<Contact>) = all.mapNotNull { it.knownSigner() }

    /** null id = sign with the first own signing key; [NO_SIGNER] = do not sign. */
    var signerId by mutableStateOf<String?>(null)

    fun signerContact(): Contact? = when (signerId) {
        NO_SIGNER -> null
        null -> _contacts.value.firstOrNull { it.canSign }
        else -> _contacts.value.find { it.id == signerId && it.canSign } ?: _contacts.value.firstOrNull { it.canSign }
    }

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
                        MessageResult.Plain(ScCrypto.decrypt(text, all.mapNotNull { it.ownKey() }, signers(all)))
                    } else {
                        val to = all.filter { it.id in selected }
                        val rsa = to.singleOrNull()?.publicKeys?.rsa
                        when {
                            to.isEmpty() -> throw ScException("Выберите получателя")
                            legacy && rsa != null -> MessageResult.Encrypted(
                                ScCrypto.encryptLegacy(rsa, text), to.map { it.name }, legacy = true, signedBy = null,
                            )
                            else -> {
                                val signer = signerContact()
                                MessageResult.Encrypted(
                                    ScCrypto.encrypt(to.map { it.recipient() }, text, signer?.signer()),
                                    to.map { it.name }, legacy = false, signedBy = signer?.name,
                                )
                            }
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
        val signer = signerContact()?.signer()
        runFile(src, dst, true) { input, output, progress ->
            val signed = ScCrypto.encryptFile(c.recipient(), signer, input, output, progress)
            "Зашифровано для «${c.name}»" + if (signed) " с подписью" else ""
        }
    }

    fun decryptFile(src: Uri, dst: Uri) {
        val all = _contacts.value
        val keys = all.mapNotNull { it.ownKey() }
        runFile(src, dst, false) { input, output, progress ->
            val r = ScCrypto.decryptFile(keys, signers(all), input, output, progress)
            "Расшифровано ключом «${r.keyName}»" + when (val s = r.sig) {
                SigStatus.Unsigned -> ""
                SigStatus.Invalid -> " · ⚠ ПОДПИСЬ НЕДЕЙСТВИТЕЛЬНА"
                is SigStatus.Valid -> " · подписано: ${s.name} ✓"
                is SigStatus.Unknown -> " · подпись неизвестного ключа ${s.fingerprint}"
            }
        }
    }

    // ───────────── hashes ─────────────

    var hashTask by mutableStateOf<HashTask?>(null)
        private set
    private var hashJob: Job? = null

    fun hashFile(uri: Uri) {
        hashJob?.cancel()
        val cr = getApplication<Application>().contentResolver
        val name = displayName(uri)
        hashTask = HashTask(name, 0f, null)
        hashJob = viewModelScope.launch {
            try {
                val total = withContext(Dispatchers.IO) { size(uri) }
                val h = withContext(Dispatchers.IO) {
                    val ctx = coroutineContext
                    var last = 0L
                    cr.openInputStream(uri)?.use { input ->
                        ScCrypto.hash(input.buffered()) { done ->
                            ctx.ensureActive()
                            if (total > 0 && done - last > total / 200) {
                                last = done
                                hashTask = hashTask?.copy(progress = (done.toFloat() / total).coerceAtMost(1f))
                            }
                        }
                    } ?: throw ScException("Не удалось открыть файл")
                }
                hashTask = HashTask(name, 1f, h)
            } catch (e: CancellationException) {
                hashTask = null
            } catch (e: Exception) {
                hashTask = null
                toast(e.message ?: "Ошибка чтения файла")
            }
        }
    }

    fun clearFileHash() {
        hashJob?.cancel()
        hashTask = null
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
