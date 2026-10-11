package org.scmess.app.crypto

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONException
import org.json.JSONObject
import org.scmess.app.crypto.Pem.hex
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyPairGenerator
import java.security.MessageDigest
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

/** One of the user's own identities, prepared for decryption attempts. */
class OwnKey(val name: String, keys: PrivateKeys) {
    val rsa: RSAPrivateCrtKey? = keys.rsa
    val x25519: X25519PrivateKeyParameters? = keys.x25519
    val rsaSlot: String? = rsa?.let { Pem.slotId(Pem.spki(Pem.publicOf(it))) }
    val xPub: X25519PublicKeyParameters? = x25519?.generatePublicKey()
    val xSlot: String? = xPub?.let { Pem.slotId(Pem.spki(it)) }
    val rsaSize: Int = rsa?.let { Pem.keyBytes(it.modulus) } ?: 0
}

class Recipient(val name: String, val keys: PublicKeys) {
    init {
        require(keys.canEncrypt)
    }

    // RSA wins when both exist: every SCmess version can read it.
    val slot: String = keys.rsa?.let { Pem.slotId(Pem.spki(it)) } ?: Pem.slotId(Pem.spki(keys.x25519!!))
}

class Signer(val key: Ed25519PrivateKeyParameters) {
    val public: Ed25519PublicKeyParameters = key.generatePublicKey()
}

class KnownSigner(val name: String, val key: Ed25519PublicKeyParameters)

sealed interface SigStatus {
    data object Unsigned : SigStatus
    data object Invalid : SigStatus
    data class Valid(val name: String) : SigStatus
    data class Unknown(val fingerprint: String) : SigStatus
}

enum class MessageFormat { SINGLE, GROUP, LEGACY }

data class Decrypted(
    val text: String,
    val keyName: String,
    val format: MessageFormat,
    val sender: String? = null,
    val sig: SigStatus = SigStatus.Unsigned,
)

data class FileResult(val keyName: String, val sig: SigStatus)

/**
 * Wire formats shared with the desktop (SCmess.py) and the old Kivy app:
 *  - single: JSON {aes_key, iv, tag, ciphertext}, RSA-OAEP(SHA-256) + AES-256-GCM
 *  - group:  JSON {type: "group_message_gcm", iv, tag, ciphertext, keys: {slot: enc_key}}
 *  - legacy: base64(RSA-OAEP(text))
 *  - file v2 (mobile): u16 rsaLen | encKey | iv12 | ciphertext | tag16
 *  - file v1 (desktop): encKey | iv12 | tag16 | ciphertext
 * Android-only additions, ignored by older readers:
 *  - group "epk": ephemeral X25519 key; X25519 slots hold iv12 | GCM(HKDF(ECDH), aesKey)
 *  - "sig": iv12 | GCM(aesKey, signerPub32 | Ed25519 sig64) — hidden from outsiders,
 *    signs the sorted recipient slots too, so a signed message cannot be re-sent to someone else
 *  - file v3 (X25519): "SCM3" | flags | slot16 | epk32 | iv12 | ciphertext | tag16 | [sig blob]
 */
object ScCrypto {
    private val random = SecureRandom()
    private const val TAG_BITS = 128
    private const val CHUNK = 64 * 1024
    private const val MAX_RSA_BYTES = 1024
    private const val SIG_BLOB = 12 + 32 + 64 + 16
    private val MAGIC_V3 = "SCM3".toByteArray()
    private const val V3_HEADER = 4 + 1 + 16 + 32 + 12
    private const val CTX_MSG = "SCmess-sig-msg-v1"
    private const val CTX_FILE = "SCmess-sig-file-v3"
    private const val INFO_SLOT = "SCmess x25519 slot v1"
    private const val INFO_FILE = "SCmess x25519 file v3"

    // Explicit spec: "OAEPWithSHA-256AndMGF1Padding" silently uses MGF1-SHA1 on Android.
    private val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)

    private val b64 = Base64.getEncoder()
    private fun unb64(s: String): ByteArray = Base64.getMimeDecoder().decode(s)

    // ───────────────────────── keys ─────────────────────────

    fun generateRsa(bits: Int): RSAPrivateCrtKey =
        KeyPairGenerator.getInstance("RSA").apply { initialize(bits, random) }.generateKeyPair().private as RSAPrivateCrtKey

    fun generateX25519() = X25519PrivateKeyParameters(random)
    fun generateEd25519() = Ed25519PrivateKeyParameters(random)

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

    /** Both sides derive the same key: ECDH, then HKDF salted with both public keys. */
    private fun x25519Key(
        priv: X25519PrivateKeyParameters, peer: X25519PublicKeyParameters,
        epk: ByteArray, rpk: ByteArray, info: String,
    ): ByteArray {
        val shared = ByteArray(32)
        X25519Agreement().apply { init(priv) }.calculateAgreement(peer, shared, 0)
        val out = ByteArray(32)
        HKDFBytesGenerator(SHA256Digest()).apply {
            init(HKDFParameters(shared, epk + rpk, info.toByteArray()))
        }.generateBytes(out, 0, out.size)
        return out
    }

    /** Max UTF-8 bytes that fit into one RSA-OAEP(SHA-256) block. */
    fun legacyLimit(key: RSAPublicKey) = Pem.keyBytes(key.modulus) - 2 * 32 - 2

    private fun randomBytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }

    /** Returns ciphertext with the 16-byte tag appended. */
    private fun gcmSeal(key: ByteArray, iv: ByteArray, plain: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            doFinal(plain)
        }

    private fun gcmOpenOrNull(key: ByteArray, iv: ByteArray, ctAndTag: ByteArray): ByteArray? =
        try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
                doFinal(ctAndTag)
            }
        } catch (_: Exception) {
            null
        }

    private fun gcmOpen(key: ByteArray, iv: ByteArray, ctAndTag: ByteArray) =
        gcmOpenOrNull(key, iv, ctAndTag)
            ?: throw ScException("Сообщение повреждено или изменено (не прошла проверка целостности)")

    // ───────────────────────── signatures ─────────────────────────

    private fun sigData(context: String, slots: List<String>, payload: ByteArray) =
        (context + "\u0000" + slots.sorted().joinToString(",") + "\u0000").toByteArray() + payload

    private fun sealSig(aesKey: ByteArray, signer: Signer, data: ByteArray): ByteArray {
        val sig = Ed25519Signer().run {
            init(true, signer.key)
            update(data, 0, data.size)
            generateSignature()
        }
        val iv = randomBytes(12)
        return iv + gcmSeal(aesKey, iv, signer.public.encoded + sig)
    }

    private fun openSig(aesKey: ByteArray, blob: ByteArray, data: ByteArray, known: List<KnownSigner>): SigStatus {
        if (blob.size != SIG_BLOB) return SigStatus.Invalid
        val plain = gcmOpenOrNull(aesKey, blob.copyOfRange(0, 12), blob.copyOfRange(12, blob.size))
            ?: return SigStatus.Invalid
        val pub = Ed25519PublicKeyParameters(plain, 0)
        val ok = Ed25519Signer().run {
            init(false, pub)
            update(data, 0, data.size)
            verifySignature(plain.copyOfRange(32, 96))
        }
        if (!ok) return SigStatus.Invalid
        val raw = pub.encoded
        return known.firstOrNull { it.key.encoded.contentEquals(raw) }?.let { SigStatus.Valid(it.name) }
            ?: SigStatus.Unknown(Pem.fingerprint(pub))
    }

    // ───────────────────────── text ─────────────────────────

    /**
     * One RSA recipient → classic single format (readable everywhere); otherwise the group
     * format, where X25519 recipients need the Android app.
     */
    fun encrypt(to: List<Recipient>, text: String, signer: Signer? = null): String {
        if (to.isEmpty()) throw ScException("Выберите получателя")
        val plain = text.toByteArray()
        val key = randomBytes(32)
        val iv = randomBytes(12)
        val sealed = gcmSeal(key, iv, plain)
        val json = JSONObject()
        val single = to.size == 1 && to[0].keys.rsa != null
        if (single) {
            json.put("aes_key", b64.encodeToString(rsaEncrypt(to[0].keys.rsa!!, key)))
        } else {
            json.put("type", "group_message_gcm")
        }
        json.put("iv", b64.encodeToString(iv))
            .put("tag", b64.encodeToString(sealed.copyOfRange(sealed.size - 16, sealed.size)))
            .put("ciphertext", b64.encodeToString(sealed.copyOfRange(0, sealed.size - 16)))
        if (!single) {
            val slots = JSONObject()
            var eph: X25519PrivateKeyParameters? = null
            for (r in to) {
                val rsa = r.keys.rsa
                if (rsa != null) {
                    slots.put(r.slot, b64.encodeToString(rsaEncrypt(rsa, key)))
                } else {
                    val e = eph ?: generateX25519().also { eph = it }
                    val x = r.keys.x25519!!
                    val wk = x25519Key(e, x, e.generatePublicKey().encoded, x.encoded, INFO_SLOT)
                    val wiv = randomBytes(12)
                    slots.put(r.slot, b64.encodeToString(wiv + gcmSeal(wk, wiv, key)))
                }
            }
            eph?.let { json.put("epk", b64.encodeToString(it.generatePublicKey().encoded)) }
            json.put("keys", slots)
        }
        signer?.let { json.put("sig", b64.encodeToString(sealSig(key, it, sigData(CTX_MSG, to.map { r -> r.slot }, plain)))) }
        return json.toString()
    }

    fun encryptLegacy(to: RSAPublicKey, text: String): String {
        val data = text.toByteArray()
        val limit = legacyLimit(to)
        if (data.size > limit) throw ScException("Legacy RSA вмещает не больше $limit байт, а текст — ${data.size}")
        return b64.encodeToString(rsaEncrypt(to, data))
    }

    /** Detects the format and tries every own key; the user never has to pick one. */
    fun decrypt(input: String, keys: List<OwnKey>, signers: List<KnownSigner> = emptyList()): Decrypted {
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
                json.optString("type") == "group_message_gcm" -> decryptGroup(json, keys, signers)
                json.has("aes_key") -> decryptSingle(json, keys, signers)
                else -> throw ScException("Неизвестный формат сообщения")
            }
        } catch (e: JSONException) {
            throw ScException("В сообщении не хватает полей", e)
        } catch (e: IllegalArgumentException) {
            throw ScException("Повреждённый base64 в сообщении", e)
        }
    }

    private fun body(json: JSONObject) = unb64(json.getString("ciphertext")) + unb64(json.getString("tag"))

    private fun checkSig(json: JSONObject, aes: ByteArray, slots: List<String>, plain: ByteArray, signers: List<KnownSigner>) =
        if (!json.has("sig")) SigStatus.Unsigned
        else openSig(aes, unb64(json.getString("sig")), sigData(CTX_MSG, slots, plain), signers)

    private fun decryptSingle(json: JSONObject, keys: List<OwnKey>, signers: List<KnownSigner>): Decrypted {
        val encKey = unb64(json.getString("aes_key"))
        val (own, aes) = keys.firstNotNullOfOrNull { k -> k.rsa?.let { rsaDecryptOrNull(it, encKey) }?.let { k to it } }
            ?: throw ScException("Сообщение зашифровано не для ваших ключей")
        val plain = gcmOpen(aes, unb64(json.getString("iv")), body(json))
        val sig = checkSig(json, aes, listOf(own.rsaSlot!!), plain, signers)
        return Decrypted(String(plain), own.name, MessageFormat.SINGLE, sig = sig)
    }

    private fun decryptGroup(json: JSONObject, keys: List<OwnKey>, signers: List<KnownSigner>): Decrypted {
        val slots = json.getJSONObject("keys")
        val epk = json.optString("epk").takeIf { it.isNotEmpty() }?.let(::unb64)

        // X25519 slots are always keyed by fingerprint.
        val viaX = if (epk == null) null else keys.firstNotNullOfOrNull { k ->
            val enc = k.xSlot?.let { slots.optString(it) }?.takeIf { it.isNotEmpty() } ?: return@firstNotNullOfOrNull null
            val raw = unb64(enc)
            if (raw.size < 12 + 16) return@firstNotNullOfOrNull null
            val wk = x25519Key(k.x25519!!, X25519PublicKeyParameters(epk, 0), epk, k.xPub!!.encoded, INFO_SLOT)
            gcmOpenOrNull(wk, raw.copyOfRange(0, 12), raw.copyOfRange(12, raw.size))?.let { k to it }
        }
        // RSA: fingerprint match first; the desktop version keys slots by user name, so fall back to trying all.
        val rsaKeys = keys.filter { it.rsa != null }
        val direct = rsaKeys.asSequence().mapNotNull { k ->
            slots.optString(k.rsaSlot!!).takeIf { it.isNotEmpty() }?.let { k to it }
        }
        val all = slots.keys().asSequence().flatMap { slot -> rsaKeys.asSequence().map { it to slots.getString(slot) } }
        val (own, aes) = viaX ?: (direct + all).firstNotNullOfOrNull { (k, enc) ->
            rsaDecryptOrNull(k.rsa!!, unb64(enc))?.let { k to it }
        } ?: throw ScException("Групповое сообщение зашифровано не для ваших ключей")

        val plain = gcmOpen(aes, unb64(json.getString("iv")), body(json))
        val sig = checkSig(json, aes, slots.keys().asSequence().toList(), plain, signers)
        return Decrypted(String(plain), own.name, MessageFormat.GROUP, json.optString("sender").ifEmpty { null }, sig)
    }

    private fun decryptLegacy(s: String, keys: List<OwnKey>): Decrypted {
        val data = try {
            unb64(s)
        } catch (e: IllegalArgumentException) {
            throw ScException("Это не похоже на зашифрованное сообщение SCmess", e)
        }
        for (k in keys) {
            if (k.rsa == null || data.size != k.rsaSize) continue
            rsaDecryptOrNull(k.rsa, data)?.let { return Decrypted(String(it), k.name, MessageFormat.LEGACY) }
        }
        throw ScException("Не удалось расшифровать: сообщение не для ваших ключей или повреждено")
    }

    // ───────────────────────── files ─────────────────────────

    private fun gcm(forEncryption: Boolean, key: ByteArray, iv: ByteArray) =
        GCMBlockCipher.newInstance(AESEngine.newInstance()).apply {
            init(forEncryption, AEADParameters(KeyParameter(key), TAG_BITS, iv))
        }

    /**
     * RSA recipients get format v2 (readable everywhere, unsigned); X25519 recipients get v3,
     * signed when [signer] is set. [progress] gets input bytes consumed and may throw to cancel.
     * Returns whether the file was signed.
     */
    fun encryptFile(to: Recipient, signer: Signer?, input: InputStream, output: OutputStream, progress: (Long) -> Unit): Boolean {
        val key: ByteArray
        val iv = randomBytes(12)
        val rsa = to.keys.rsa
        val v3 = rsa == null
        if (rsa != null) {
            key = randomBytes(32)
            val encKey = rsaEncrypt(rsa, key)
            output.write(encKey.size shr 8)
            output.write(encKey.size and 0xff)
            output.write(encKey)
        } else {
            val x = to.keys.x25519!!
            val eph = generateX25519()
            val epk = eph.generatePublicKey().encoded
            key = x25519Key(eph, x, epk, x.encoded, INFO_FILE)
            output.write(MAGIC_V3)
            output.write(if (signer != null) 1 else 0)
            output.write(Pem.sha256(Pem.spki(x)), 0, 16)
            output.write(epk)
        }
        output.write(iv)
        val cipher = gcm(true, key, iv)
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(CHUNK)
        val out = ByteArray(CHUNK + 32)
        var done = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
            output.write(out, 0, cipher.processBytes(buf, 0, n, out, 0))
            done += n
            progress(done)
        }
        output.write(out, 0, cipher.doFinal(out, 0)) // appends the 16-byte tag
        if (v3 && signer != null) {
            output.write(sealSig(key, signer, sigData(CTX_FILE, listOf(to.slot), md.digest())))
            return true
        }
        return false
    }

    /**
     * Reads file format v1, v2 or v3 with whichever own key fits. Plaintext is streamed out
     * before the tag is checked, so on failure the caller must delete the partial output.
     */
    fun decryptFile(
        keys: List<OwnKey>, signers: List<KnownSigner>,
        input: InputStream, output: OutputStream, progress: (Long) -> Unit,
    ): FileResult {
        if (keys.isEmpty()) throw ScException("Нет своих (приватных) ключей для расшифровки")
        val head = input.readUpTo(2 + MAX_RSA_BYTES + 28)

        var own: OwnKey? = null
        var aes: ByteArray? = null
        var iv = ByteArray(0)
        var tag: ByteArray? = null // set only for v1, where the tag precedes the data
        var dataStart = 0
        var hold = 0 // trailing bytes kept out of the cipher (v3 signature blob)
        var v3Slot: String? = null

        if (head.size >= V3_HEADER && head.copyOfRange(0, 4).contentEquals(MAGIC_V3)) {
            val slot16 = head.copyOfRange(5, 21)
            val epk = head.copyOfRange(21, 53)
            own = keys.firstOrNull { k -> k.xPub?.let { Pem.sha256(Pem.spki(it)).copyOf(16).contentEquals(slot16) } == true }
                ?: throw ScException("Файл зашифрован не для ваших ключей")
            aes = x25519Key(own.x25519!!, X25519PublicKeyParameters(epk, 0), epk, own.xPub!!.encoded, INFO_FILE)
            iv = head.copyOfRange(53, 65)
            dataStart = V3_HEADER
            if (head[4].toInt() and 1 != 0) hold = SIG_BLOB
            v3Slot = own.xSlot
        } else {
            val u16 = if (head.size >= 2) ((head[0].toInt() and 0xff) shl 8) or (head[1].toInt() and 0xff) else -1
            val rsaKeys = keys.filter { it.rsa != null }
            for (k in rsaKeys) {
                val n = k.rsaSize
                if (u16 != n || head.size < 2 + n + 12 + 16) continue
                aes = rsaDecryptOrNull(k.rsa!!, head, 2, n) ?: continue
                own = k; iv = head.copyOfRange(2 + n, 2 + n + 12); dataStart = 2 + n + 12
                break
            }
            if (own == null) for (k in rsaKeys) {
                val n = k.rsaSize
                if (head.size < n + 28) continue
                aes = rsaDecryptOrNull(k.rsa!!, head, 0, n) ?: continue
                own = k; iv = head.copyOfRange(n, n + 12); tag = head.copyOfRange(n + 12, n + 28); dataStart = n + 28
                break
            }
        }
        if (own == null || aes == null) throw ScException("Файл зашифрован не для ваших ключей или это не файл SCmess")

        val cipher = gcm(false, aes, iv)
        val md = MessageDigest.getInstance("SHA-256")
        var out = ByteArray(CHUNK + 64)
        fun feed(b: ByteArray, off: Int, len: Int) {
            if (len <= 0) return
            if (out.size < len + 32) out = ByteArray(len + 32)
            val n = cipher.processBytes(b, off, len, out, 0)
            md.update(out, 0, n)
            output.write(out, 0, n)
        }
        var carry = head.copyOfRange(dataStart, head.size)
        fun push(b: ByteArray, len: Int) {
            val all = if (len == 0) carry else carry + b.copyOf(len)
            val n = all.size - hold
            if (n > 0) {
                feed(all, 0, n)
                carry = all.copyOfRange(n, all.size)
            } else carry = all
        }
        var done = head.size.toLong()
        push(ByteArray(0), 0)
        progress(done)
        val buf = ByteArray(CHUNK)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            push(buf, n)
            done += n
            progress(done)
        }
        tag?.let { feed(it, 0, it.size) }
        if (carry.size != hold) throw ScException("Файл обрезан или повреждён")
        try {
            val n = cipher.doFinal(out, 0)
            md.update(out, 0, n)
            output.write(out, 0, n)
        } catch (e: InvalidCipherTextException) {
            throw ScException("Файл повреждён или изменён (не прошла проверка целостности)", e)
        }
        val sig = if (hold == 0) SigStatus.Unsigned
        else openSig(aes, carry, sigData(CTX_FILE, listOf(v3Slot!!), md.digest()), signers)
        return FileResult(own.name, sig)
    }

    // ───────────────────────── hashes ─────────────────────────

    class Hashes(val sha256: String, val sha512: String)

    fun hash(input: InputStream, progress: (Long) -> Unit = {}): Hashes {
        val a = MessageDigest.getInstance("SHA-256")
        val b = MessageDigest.getInstance("SHA-512")
        val buf = ByteArray(CHUNK)
        var done = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            a.update(buf, 0, n)
            b.update(buf, 0, n)
            done += n
            progress(done)
        }
        return Hashes(a.digest().hex(), b.digest().hex())
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
