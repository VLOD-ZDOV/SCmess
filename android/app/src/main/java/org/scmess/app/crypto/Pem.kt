package org.scmess.app.crypto

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
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

/** Public half of an identity: an encryption key (RSA and/or X25519) plus an optional Ed25519 signing key. */
data class PublicKeys(
    val rsa: RSAPublicKey? = null,
    val x25519: X25519PublicKeyParameters? = null,
    val ed25519: Ed25519PublicKeyParameters? = null,
) {
    val canEncrypt get() = rsa != null || x25519 != null
    val isEmpty get() = rsa == null && x25519 == null && ed25519 == null
}

data class PrivateKeys(
    val rsa: RSAPrivateCrtKey? = null,
    val x25519: X25519PrivateKeyParameters? = null,
    val ed25519: Ed25519PrivateKeyParameters? = null,
) {
    val canDecrypt get() = rsa != null || x25519 != null
    val isEmpty get() = rsa == null && x25519 == null && ed25519 == null

    fun publicKeys() = PublicKeys(
        rsa?.let(Pem::publicOf),
        x25519?.generatePublicKey(),
        ed25519?.generatePublicKey(),
    )
}

/**
 * PEM import/export compatible with Python `cryptography`: PKCS#8 / SubjectPublicKeyInfo
 * (plus PKCS#1 for RSA). Several keys are stored as consecutive PEM blocks, RSA first,
 * because the desktop version only reads the first block.
 */
object Pem {
    data class Parsed(val public: PublicKeys, val private: PrivateKeys)

    private val block = Regex("-----BEGIN ([A-Z0-9 ]+)-----([\\s\\S]*?)-----END \\1-----")
    private val rsa get() = KeyFactory.getInstance("RSA")
    private val oidRsa: ASN1ObjectIdentifier = PKCSObjectIdentifiers.rsaEncryption
    private val oidX25519 = ASN1ObjectIdentifier("1.3.101.110")
    private val oidEd25519 = ASN1ObjectIdentifier("1.3.101.112")

    /** Parses every PEM block in [text]; private keys also yield their public halves. */
    fun parse(text: String): Parsed {
        var pub = PublicKeys()
        var priv = PrivateKeys()
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
                    "PUBLIC KEY" -> pub = addPublic(pub, der)
                    "RSA PUBLIC KEY" -> pub = pub.copy(rsa = rsaPublic(spkiFromPkcs1(der)))
                    "PRIVATE KEY" -> priv = addPrivate(priv, der)
                    "RSA PRIVATE KEY" -> priv = priv.copy(rsa = rsaPrivate(pkcs8FromPkcs1(der)))
                    "ENCRYPTED PRIVATE KEY" -> throw ScException("Ключ защищён паролем — такие пока не поддерживаются")
                    else -> throw ScException("Неподдерживаемый тип: ${m.groupValues[1]}")
                }
            } catch (e: ScException) {
                throw e
            } catch (e: Exception) {
                throw ScException("Ключ повреждён или это неподдерживаемый алгоритм", e)
            }
        }
        val derived = priv.publicKeys()
        if ((pub.rsa != null && derived.rsa != null && pub.rsa != derived.rsa) ||
            (pub.x25519 != null && derived.x25519 != null && !pub.x25519.encoded.contentEquals(derived.x25519.encoded)) ||
            (pub.ed25519 != null && derived.ed25519 != null && !pub.ed25519.encoded.contentEquals(derived.ed25519.encoded))
        ) throw ScException("Публичная и приватная части ключа не совпадают")
        pub = PublicKeys(pub.rsa ?: derived.rsa, pub.x25519 ?: derived.x25519, pub.ed25519 ?: derived.ed25519)
        return Parsed(pub, priv)
    }

    private fun addPublic(pub: PublicKeys, der: ByteArray): PublicKeys {
        val info = SubjectPublicKeyInfo.getInstance(der)
        val raw = info.publicKeyData.bytes
        return when (info.algorithm.algorithm) {
            oidRsa -> pub.copy(rsa = rsaPublic(der))
            oidX25519 -> pub.copy(x25519 = X25519PublicKeyParameters(raw, 0))
            oidEd25519 -> pub.copy(ed25519 = Ed25519PublicKeyParameters(raw, 0))
            else -> throw ScException("Неподдерживаемый алгоритм ключа")
        }
    }

    private fun addPrivate(priv: PrivateKeys, der: ByteArray): PrivateKeys =
        when (PrivateKeyInfo.getInstance(der).privateKeyAlgorithm.algorithm) {
            oidRsa -> priv.copy(rsa = rsaPrivate(der))
            oidX25519 -> priv.copy(x25519 = PrivateKeyFactory.createKey(der) as X25519PrivateKeyParameters)
            oidEd25519 -> priv.copy(ed25519 = PrivateKeyFactory.createKey(der) as Ed25519PrivateKeyParameters)
            else -> throw ScException("Неподдерживаемый алгоритм ключа")
        }

    private fun rsaPublic(spki: ByteArray) = rsa.generatePublic(X509EncodedKeySpec(spki)) as RSAPublicKey
    private fun rsaPrivate(pkcs8: ByteArray) = rsa.generatePrivate(PKCS8EncodedKeySpec(pkcs8)) as RSAPrivateCrtKey

    fun publicOf(priv: RSAPrivateCrtKey): RSAPublicKey =
        rsa.generatePublic(RSAPublicKeySpec(priv.modulus, priv.publicExponent)) as RSAPublicKey

    fun spki(key: RSAPublicKey): ByteArray = key.encoded
    fun spki(key: X25519PublicKeyParameters): ByteArray = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key).encoded
    fun spki(key: Ed25519PublicKeyParameters): ByteArray = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key).encoded

    fun encode(keys: PublicKeys) = buildString {
        keys.rsa?.let { append(wrap("PUBLIC KEY", spki(it))) }
        keys.x25519?.let { append(wrap("PUBLIC KEY", spki(it))) }
        keys.ed25519?.let { append(wrap("PUBLIC KEY", spki(it))) }
    }

    fun encode(keys: PrivateKeys) = buildString {
        keys.rsa?.let { append(wrap("PRIVATE KEY", it.encoded)) }
        keys.x25519?.let { append(wrap("PRIVATE KEY", pkcs8v1(oidX25519, it.encoded))) }
        keys.ed25519?.let { append(wrap("PRIVATE KEY", pkcs8v1(oidEd25519, it.encoded))) }
    }

    // BouncyCastle writes PKCS#8 v2 with the public key attached, which Python `cryptography` rejects.
    private fun pkcs8v1(oid: ASN1ObjectIdentifier, raw: ByteArray) =
        PrivateKeyInfo(AlgorithmIdentifier(oid), DEROctetString(raw)).encoded

    /**
     * Short display fingerprint over every key of the identity (first 8 bytes of SHA-256).
     * For a lone RSA key it equals the fingerprint the old app showed.
     */
    fun fingerprint(keys: PublicKeys): String {
        val md = MessageDigest.getInstance("SHA-256")
        keys.rsa?.let { md.update(spki(it)) }
        keys.x25519?.let { md.update(spki(it)) }
        keys.ed25519?.let { md.update(spki(it)) }
        return display(md.digest())
    }

    fun fingerprint(key: Ed25519PublicKeyParameters) = display(sha256(spki(key)))

    /** Recipient slot id used in messages: first 32 hex chars of SHA-256(SPKI). */
    fun slotId(spki: ByteArray): String = sha256(spki).hex().take(32)

    fun keyBytes(modulus: BigInteger) = (modulus.bitLength() + 7) / 8

    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private fun display(digest: ByteArray) = digest.hex().take(16).uppercase().chunked(2).joinToString(":")

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
