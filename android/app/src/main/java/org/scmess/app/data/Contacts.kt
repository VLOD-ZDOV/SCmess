package org.scmess.app.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import org.scmess.app.crypto.OwnKey
import org.scmess.app.crypto.Pem
import org.scmess.app.crypto.ScException
import java.io.File
import java.security.KeyStore
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class Contact(
    val id: String,
    val name: String,
    val publicKey: RSAPublicKey,
    val privateKey: RSAPrivateCrtKey?,
) {
    val isMine get() = privateKey != null
    val fingerprint: String = Pem.fingerprint(publicKey)
    val bits: Int get() = publicKey.modulus.bitLength()
    val publicPem: String get() = Pem.encodePublic(publicKey)
    val privatePem: String? get() = privateKey?.let(Pem::encodePrivate)
    fun ownKey() = privateKey?.let { OwnKey(name, it) }
}

/**
 * contacts.json in app-private storage. Private keys are additionally sealed with an
 * AES key from the Android Keystore, so a copied data folder alone does not leak them.
 */
class ContactStore(context: Context) {
    private val file = File(context.filesDir, "contacts.json")

    fun load(): List<Contact> {
        if (!file.exists()) return emptyList()
        val arr = JSONArray(file.readText())
        return (0 until arr.length()).mapNotNull { i ->
            val o = arr.getJSONObject(i)
            try {
                val priv = o.optString("private_sealed").takeIf { it.isNotEmpty() }
                    ?.let { Pem.parse(String(Vault.open(it))).private }
                val pub = Pem.parse(o.getString("public")).public!!
                Contact(o.getString("id"), o.getString("name"), pub, priv)
            } catch (e: Exception) {
                Log.e("SCmess", "skipping unreadable contact", e)
                null
            }
        }
    }

    fun save(list: List<Contact>) {
        val arr = JSONArray()
        for (c in list) arr.put(
            JSONObject()
                .put("id", c.id)
                .put("name", c.name)
                .put("public", c.publicPem)
                .apply { c.privatePem?.let { put("private_sealed", Vault.seal(it.toByteArray())) } }
        )
        val tmp = File(file.parentFile, "contacts.json.tmp")
        tmp.writeText(arr.toString())
        if (!tmp.renameTo(file)) throw ScException("Не удалось сохранить ключи")
    }

    companion object {
        fun newId() = UUID.randomUUID().toString()
    }
}

private object Vault {
    private const val ALIAS = "scmess_vault"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            generateKey()
        }
    }

    fun seal(data: ByteArray): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        return Base64.getEncoder().encodeToString(c.iv + c.doFinal(data))
    }

    fun open(sealed: String): ByteArray {
        val raw = Base64.getDecoder().decode(sealed)
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw, 0, 12))
            doFinal(raw, 12, raw.size - 12)
        }
    }
}
