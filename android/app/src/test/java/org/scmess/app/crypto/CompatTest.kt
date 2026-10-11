package org.scmess.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * Round-trips plus, when -Dscmess.vectors=<dir> points at `compat.py make` output,
 * decryption of real Python ciphertexts and writing ciphertexts for `compat.py verify`.
 */
class CompatTest {
    private val text = "Привет, мир! 🔐 SCmess"

    private fun own(name: String) = OwnKey(name, ScCrypto.generate(2048).second)

    @Test
    fun textRoundTrips() {
        val me = own("me")
        val other = own("other")
        val keys = listOf(other, me)
        assertEquals(text, ScCrypto.decrypt(ScCrypto.encryptSingle(me.public, text), keys).text)
        val g = ScCrypto.decrypt(ScCrypto.encryptGroup(listOf(other.public, me.public), text), listOf(me))
        assertEquals(text to MessageFormat.GROUP, g.text to g.format)
        val l = ScCrypto.decrypt(ScCrypto.encryptLegacy(me.public, text), keys)
        assertEquals(text to "me", l.text to l.keyName)
    }

    @Test
    fun foreignAndTamperedMessagesFail() {
        val me = own("me")
        val msg = ScCrypto.encryptSingle(own("x").public, text)
        assertThrows(ScException::class.java) { ScCrypto.decrypt(msg, listOf(me)) }
        val mine = ScCrypto.encryptSingle(me.public, text)
        val ct = Regex("\"ciphertext\":\"(.)").find(mine)!!.groupValues[1]
        val bad = mine.replaceFirst("\"ciphertext\":\"$ct", "\"ciphertext\":\"" + (if (ct == "A") "B" else "A"))
        assertThrows(ScException::class.java) { ScCrypto.decrypt(bad, listOf(me)) }
    }

    @Test
    fun fileRoundTripAndTamper() {
        val me = own("me")
        val plain = ByteArray(200_003) { (it * 31).toByte() }
        val enc = ByteArrayOutputStream().also { ScCrypto.encryptFile(me.public, ByteArrayInputStream(plain), it) {} }.toByteArray()
        val dec = ByteArrayOutputStream()
        assertEquals("me", ScCrypto.decryptFile(listOf(own("x"), me), ByteArrayInputStream(enc), dec) {})
        assertArrayEquals(plain, dec.toByteArray())
        enc[enc.size / 2] = (enc[enc.size / 2].toInt() xor 1).toByte()
        assertThrows(ScException::class.java) {
            ScCrypto.decryptFile(listOf(me), ByteArrayInputStream(enc), ByteArrayOutputStream()) {}
        }
    }

    @Test
    fun pemExportParses() {
        val (pub, priv) = ScCrypto.generate(2048)
        val p = Pem.parse(Pem.encodePrivate(priv))
        assertEquals(pub, p.public)
        assertEquals(pub, Pem.parse(Pem.encodePublic(pub)).public)
        assertEquals(23, Pem.fingerprint(pub).length)
    }

    @Test
    fun pythonInterop() {
        val dir = System.getProperty("scmess.vectors")?.let(::File)
        assumeTrue("set -Dscmess.vectors to run", dir != null && dir.isDirectory)
        dir!!
        val a = Pem.parse(File(dir, "key_a.pem").readText())
        val b = Pem.parse(File(dir, "key_b.pem").readText()) // PKCS#1
        val keys = listOf(OwnKey("a", a.private!!), OwnKey("b", b.private!!))
        val onlyB = listOf(keys[1])
        val expected = "Привет, мир! 🔐 SCmess"

        assertEquals("a", ScCrypto.decrypt(File(dir, "single.json").readText(), keys).keyName)
        assertEquals(expected, ScCrypto.decrypt(File(dir, "group_fp.json").readText(), onlyB).text)
        val desk = ScCrypto.decrypt(File(dir, "group_names.json").readText(), keys)
        assertEquals(listOf(expected, "b", "desk"), listOf(desk.text, desk.keyName, desk.sender))
        assertEquals(expected, ScCrypto.decrypt(File(dir, "legacy.txt").readText(), keys).text)

        val plain = File(dir, "plain.bin").readBytes()
        for ((name, key) in listOf("file_v2.enc" to "a", "file_v1.enc" to "b")) {
            val out = ByteArrayOutputStream()
            assertEquals(key, ScCrypto.decryptFile(keys, File(dir, name).inputStream(), out) {})
            assertArrayEquals(name, plain, out.toByteArray())
        }

        val k = File(dir, "kotlin").apply { mkdirs() }
        File(k, "single.json").writeText(ScCrypto.encryptSingle(a.public!!, expected))
        File(k, "group.json").writeText(ScCrypto.encryptGroup(listOf(a.public!!, b.public!!), expected))
        File(k, "legacy.txt").writeText(ScCrypto.encryptLegacy(b.public!!, expected))
        File(k, "file.enc").outputStream().use { ScCrypto.encryptFile(a.public!!, plain.inputStream(), it) {} }
    }
}
