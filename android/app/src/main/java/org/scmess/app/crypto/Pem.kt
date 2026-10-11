package org.scmess.app.crypto

import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class ScException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** PEM import/export compatible with Python `cryptography` (PKCS#8 / SubjectPublicKeyInfo, plus PKCS#1). */
object Pem {
    data class Parsed(val public: RSAPublicKey?, val private: RSAPrivateCrtKey?)

    private val block = Regex("-----BEGIN ([A-Z0-9 ]+)-----([\\s\\S]*?)-----END \\1-----")
    private val rsa get() = KeyFactory.getInstance("RSA")

    /** Parses every PEM block in [text]; a private key also yields its public half. */
    fun parse(text: String): Parsed {
        var pub: RSAPublicKey? = null
        var priv: RSAPrivateCrtKey? = null
        val blocks = block.findAll(text).toList()
        if (blocks.isEmpty()) throw ScException("Не найден PEM-блок «-----BEGIN … KEY-----»")
        for (m in blocks) {
            val der = try {
                Base64.getMimeDecoder().decode(m.groupValues[2].trim())
            } catch (e: IllegalArgumentException) {
                throw ScException("Повреждённый base64 внутри ключа", e)
            }
            try {
                when (m.groupValues[1]) {
                    "PUBLIC KEY" -> pub = rsa.generatePublic(X509EncodedKeySpec(der)) as RSAPublicKey
                    "RSA PUBLIC KEY" -> pub = rsa.generatePublic(X509EncodedKeySpec(spkiFromPkcs1(der))) as RSAPublicKey
                    "PRIVATE KEY" -> priv = rsa.generatePrivate(PKCS8EncodedKeySpec(der)) as RSAPrivateCrtKey
                    "RSA PRIVATE KEY" -> priv = rsa.generatePrivate(PKCS8EncodedKeySpec(pkcs8FromPkcs1(der))) as RSAPrivateCrtKey
                    "ENCRYPTED PRIVATE KEY" -> throw ScException("Ключ защищён паролем — такие пока не поддерживаются")
                    else -> throw ScException("Неподдерживаемый тип: ${m.groupValues[1]}")
                }
            } catch (e: ScException) {
                throw e
            } catch (e: Exception) {
                throw ScException("Это не RSA-ключ или он повреждён", e)
            }
        }
        if (pub == null && priv != null) pub = publicOf(priv)
        return Parsed(pub, priv)
    }

    fun publicOf(priv: RSAPrivateCrtKey): RSAPublicKey =
        rsa.generatePublic(RSAPublicKeySpec(priv.modulus, priv.publicExponent)) as RSAPublicKey

    fun encodePublic(key: RSAPublicKey) = wrap("PUBLIC KEY", key.encoded)
    fun encodePrivate(key: RSAPrivateCrtKey) = wrap("PRIVATE KEY", key.encoded)

    /** Short display fingerprint: first 8 bytes of SHA-256(SPKI), like "A3:F7:…". */
    fun fingerprint(key: RSAPublicKey): String =
        sha256Hex(key).take(16).uppercase().chunked(2).joinToString(":")

    /** Recipient slot id used in group messages: first 32 hex chars of SHA-256(SPKI). */
    fun slotId(key: RSAPublicKey): String = sha256Hex(key).take(32)

    fun keyBytes(modulus: BigInteger) = (modulus.bitLength() + 7) / 8

    private fun sha256Hex(key: RSAPublicKey) =
        MessageDigest.getInstance("SHA-256").digest(key.encoded).joinToString("") { "%02x".format(it) }

    private fun wrap(label: String, der: ByteArray): String {
        val body = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)
        return "-----BEGIN $label-----\n$body\n-----END $label-----\n"
    }

    // AlgorithmIdentifier { rsaEncryption, NULL }
    private val rsaAlgId = bytes(0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00)

    private fun spkiFromPkcs1(pkcs1: ByteArray) = der(0x30, rsaAlgId + der(0x03, byteArrayOf(0) + pkcs1))
    private fun pkcs8FromPkcs1(pkcs1: ByteArray) = der(0x30, bytes(0x02, 0x01, 0x00) + rsaAlgId + der(0x04, pkcs1))

    private fun der(tag: Int, body: ByteArray): ByteArray {
        val n = body.size
        val len = when {
            n < 0x80 -> bytes(n)
            n < 0x100 -> bytes(0x81, n)
            n < 0x10000 -> bytes(0x82, n shr 8, n)
            else -> bytes(0x83, n shr 16, n shr 8, n)
        }
        return bytes(tag) + len + body
    }

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
}
