package org.scmess.app.crypto

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.json.JSONException
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/** One of the user's own private keys, prepared for decryption attempts. */
class OwnKey(val name: String, val private: RSAPrivateCrtKey) {
    val public: RSAPublicKey = Pem.publicOf(private)
    val slot: String = Pem.slotId(public)
    val size: Int = Pem.keyBytes(private.modulus)
}

enum class MessageFormat { SINGLE, GROUP, LEGACY }

data class Decrypted(val text: String, val keyName: String, val format: MessageFormat, val sender: String? = null)

/**
 * Wire formats shared with the desktop (SCmess.py) and the old Kivy app:
 *  - single: JSON {aes_key, iv, tag, ciphertext}, RSA-OAEP(SHA-256) + AES-256-GCM
 *  - group:  JSON {type: "group_message_gcm", iv, tag, ciphertext, keys: {slot: enc_key}}
 *  - legacy: base64(RSA-OAEP(text))
 *  - file v2 (mobile): u16 rsaLen | encKey | iv12 | ciphertext | tag16
 *  - file v1 (desktop): encKey | iv12 | tag16 | ciphertext
 */
object ScCrypto {
    private val random = SecureRandom()
    private const val TAG_BITS = 128
    private const val CHUNK = 64 * 1024
    private const val MAX_RSA_BYTES = 1024

    // Explicit spec: "OAEPWithSHA-256AndMGF1Padding" silently uses MGF1-SHA1 on Android.
    private val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)

    private val b64 = Base64.getEncoder()
    private fun unb64(s: String): ByteArray = Base64.getMimeDecoder().decode(s)

    fun generate(bits: Int): Pair<RSAPublicKey, RSAPrivateCrtKey> {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(bits, random) }.generateKeyPair()
        return kp.public as RSAPublicKey to kp.private as RSAPrivateCrtKey
    }

    fun rsaEncrypt(key: RSAPublicKey, data: ByteArray): ByteArray =
        Cipher.getInstance("RSA/ECB/OAEPPadding").run {
            init(Cipher.ENCRYPT_MODE, key, oaep)
            doFinal(data)
        }

    private fun rsaDecryptOrNull(key: RSAPrivateCrtKey, data: ByteArray, off: Int = 0, len: Int = data.size): ByteArray? =
        try {
            Cipher.getInstance("RSA/ECB/OAEPPadding").run {
                init(Cipher.DECRYPT_MODE, key, oaep)
                doFinal(data, off, len)
            }
        } catch (_: Exception) {
            null
        }

    /** Max UTF-8 bytes that fit into one RSA-OAEP(SHA-256) block. */
    fun legacyLimit(key: RSAPublicKey) = Pem.keyBytes(key.modulus) - 2 * 32 - 2

    private fun randomBytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }

    private class Sealed(val ct: ByteArray, val tag: ByteArray)

    private fun gcmSeal(key: ByteArray, iv: ByteArray, plain: ByteArray): Sealed {
        val out = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            doFinal(plain)
        }
        return Sealed(out.copyOfRange(0, out.size - 16), out.copyOfRange(out.size - 16, out.size))
    }

    private fun gcmOpen(key: ByteArray, iv: ByteArray, ct: ByteArray, tag: ByteArray): ByteArray =
        try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
                doFinal(ct + tag)
            }
        } catch (e: Exception) {
            throw ScException("Сообщение повреждено или изменено (не прошла проверка целостности)", e)
        }

    // ───────────────────────── text ─────────────────────────

    fun encryptSingle(to: RSAPublicKey, text: String): String {
        val key = randomBytes(32)
        val iv = randomBytes(12)
        val s = gcmSeal(key, iv, text.toByteArray())
        return JSONObject()
            .put("aes_key", b64.encodeToString(rsaEncrypt(to, key)))
            .put("iv", b64.encodeToString(iv))
            .put("tag", b64.encodeToString(s.tag))
            .put("ciphertext", b64.encodeToString(s.ct))
            .toString()
    }

    /** Recipients are identified by key fingerprints, so names never leave the device. */
    fun encryptGroup(to: Collection<RSAPublicKey>, text: String): String {
        val key = randomBytes(32)
        val iv = randomBytes(12)
        val s = gcmSeal(key, iv, text.toByteArray())
        val slots = JSONObject()
        for (pub in to) slots.put(Pem.slotId(pub), b64.encodeToString(rsaEncrypt(pub, key)))
        return JSONObject()
            .put("type", "group_message_gcm")
            .put("iv", b64.encodeToString(iv))
            .put("tag", b64.encodeToString(s.tag))
            .put("ciphertext", b64.encodeToString(s.ct))
            .put("keys", slots)
            .toString()
    }

    fun encryptLegacy(to: RSAPublicKey, text: String): String {
        val data = text.toByteArray()
        val limit = legacyLimit(to)
        if (data.size > limit) throw ScException("Legacy RSA вмещает не больше $limit байт, а текст — ${data.size}")
        return b64.encodeToString(rsaEncrypt(to, data))
    }

    /** Detects the format and tries every own key; the user never has to pick one. */
    fun decrypt(input: String, keys: List<OwnKey>): Decrypted {
        if (keys.isEmpty()) throw ScException("Нет своих (приватных) ключей — создайте или импортируйте их во вкладке «Ключи»")
        val s = input.trim()
        if (s.isEmpty()) throw ScException("Вставьте зашифрованное сообщение")
        if (!s.startsWith("{")) return decryptLegacy(s, keys)
        val json = try {
            JSONObject(s)
        } catch (e: JSONException) {
            throw ScException("Сообщение обрезано или повреждено (некорректный JSON)", e)
        }
        return try {
            when {
                json.optString("type") == "group_message_gcm" -> decryptGroup(json, keys)
                json.has("aes_key") -> decryptSingle(json, keys)
                else -> throw ScException("Неизвестный формат сообщения")
            }
        } catch (e: JSONException) {
            throw ScException("В сообщении не хватает полей", e)
        } catch (e: IllegalArgumentException) {
            throw ScException("Повреждённый base64 в сообщении", e)
        }
    }

    private fun decryptSingle(json: JSONObject, keys: List<OwnKey>): Decrypted {
        val encKey = unb64(json.getString("aes_key"))
        val (own, aes) = keys.firstNotNullOfOrNull { k -> rsaDecryptOrNull(k.private, encKey)?.let { k to it } }
            ?: throw ScException("Сообщение зашифровано не для ваших ключей")
        val plain = gcmOpen(aes, unb64(json.getString("iv")), unb64(json.getString("ciphertext")), unb64(json.getString("tag")))
        return Decrypted(String(plain), own.name, MessageFormat.SINGLE)
    }

    private fun decryptGroup(json: JSONObject, keys: List<OwnKey>): Decrypted {
        val slots = json.getJSONObject("keys")
        // Fingerprint match first; the desktop version keys slots by user name, so fall back to trying all.
        val direct = keys.asSequence().mapNotNull { k ->
            slots.optString(k.slot).takeIf { it.isNotEmpty() }?.let { k to it }
        }
        val all = slots.keys().asSequence().flatMap { slot -> keys.asSequence().map { it to slots.getString(slot) } }
        val (own, aes) = (direct + all).firstNotNullOfOrNull { (k, enc) ->
            rsaDecryptOrNull(k.private, unb64(enc))?.let { k to it }
        } ?: throw ScException("Групповое сообщение зашифровано не для ваших ключей")
        val plain = gcmOpen(aes, unb64(json.getString("iv")), unb64(json.getString("ciphertext")), unb64(json.getString("tag")))
        return Decrypted(String(plain), own.name, MessageFormat.GROUP, json.optString("sender").ifEmpty { null })
    }

    private fun decryptLegacy(s: String, keys: List<OwnKey>): Decrypted {
        val data = try {
            unb64(s)
        } catch (e: IllegalArgumentException) {
            throw ScException("Это не похоже на зашифрованное сообщение SCmess", e)
        }
        for (k in keys) {
            if (data.size != k.size) continue
            rsaDecryptOrNull(k.private, data)?.let { return Decrypted(String(it), k.name, MessageFormat.LEGACY) }
        }
        throw ScException("Не удалось расшифровать: сообщение не для ваших ключей или повреждено")
    }

    // ───────────────────────── files ─────────────────────────

    private fun gcm(forEncryption: Boolean, key: ByteArray, iv: ByteArray) =
        GCMBlockCipher.newInstance(AESEngine.newInstance()).apply {
            init(forEncryption, AEADParameters(KeyParameter(key), TAG_BITS, iv))
        }

    /** Writes file format v2. [progress] gets the number of input bytes consumed and may throw to cancel. */
    fun encryptFile(to: RSAPublicKey, input: InputStream, output: OutputStream, progress: (Long) -> Unit) {
        val key = randomBytes(32)
        val iv = randomBytes(12)
        val encKey = rsaEncrypt(to, key)
        output.write(encKey.size shr 8)
        output.write(encKey.size and 0xff)
        output.write(encKey)
        output.write(iv)
        val cipher = gcm(true, key, iv)
        val buf = ByteArray(CHUNK)
        val out = ByteArray(CHUNK + 32)
        var done = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            output.write(out, 0, cipher.processBytes(buf, 0, n, out, 0))
            done += n
            progress(done)
        }
        output.write(out, 0, cipher.doFinal(out, 0)) // appends the 16-byte tag
    }

    /**
     * Reads file format v1 or v2 with whichever own key fits. Plaintext is streamed out before
     * the tag is checked, so on failure the caller must delete the partial output.
     * Returns the name of the key that worked.
     */
    fun decryptFile(keys: List<OwnKey>, input: InputStream, output: OutputStream, progress: (Long) -> Unit): String {
        if (keys.isEmpty()) throw ScException("Нет своих (приватных) ключей для расшифровки")
        val head = input.readUpTo(2 + MAX_RSA_BYTES + 28)
        val u16 = if (head.size >= 2) ((head[0].toInt() and 0xff) shl 8) or (head[1].toInt() and 0xff) else -1

        var own: OwnKey? = null
        var aes: ByteArray? = null
        var iv = ByteArray(0)
        var tag: ByteArray? = null // null = tag sits at the end of the stream (v2)
        var dataStart = 0

        for (k in keys) {
            val n = k.size
            if (u16 != n || head.size < 2 + n + 12 + 16) continue
            aes = rsaDecryptOrNull(k.private, head, 2, n) ?: continue
            own = k; iv = head.copyOfRange(2 + n, 2 + n + 12); dataStart = 2 + n + 12
            break
        }
        if (own == null) for (k in keys) {
            val n = k.size
            if (head.size < n + 28) continue
            aes = rsaDecryptOrNull(k.private, head, 0, n) ?: continue
            own = k; iv = head.copyOfRange(n, n + 12); tag = head.copyOfRange(n + 12, n + 28); dataStart = n + 28
            break
        }
        if (own == null || aes == null) throw ScException("Файл зашифрован не для ваших ключей или это не файл SCmess")

        val cipher = gcm(false, aes, iv)
        val out = ByteArray(CHUNK + 32)
        var done = 0L
        fun feed(b: ByteArray, off: Int, len: Int) {
            if (len > 0) output.write(out, 0, cipher.processBytes(b, off, len, out, 0))
        }
        feed(head, dataStart, head.size - dataStart)
        done += head.size
        progress(done)
        val buf = ByteArray(CHUNK)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            feed(buf, 0, n)
            done += n
            progress(done)
        }
        tag?.let { feed(it, 0, it.size) }
        try {
            output.write(out, 0, cipher.doFinal(out, 0))
        } catch (e: InvalidCipherTextException) {
            throw ScException("Файл повреждён или изменён (не прошла проверка целостности)", e)
        }
        return own.name
    }

    private fun InputStream.readUpTo(n: Int): ByteArray {
        val buf = ByteArray(n)
        var total = 0
        while (total < n) {
            val r = read(buf, total, n - total)
            if (r < 0) break
            total += r
        }
        return buf.copyOf(total)
    }
}
