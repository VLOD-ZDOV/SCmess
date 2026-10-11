package org.scmess.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
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

    private fun rsaKeys() = PrivateKeys(rsa = ScCrypto.generateRsa(2048), ed25519 = ScCrypto.generateEd25519())
    private fun xKeys() = PrivateKeys(x25519 = ScCrypto.generateX25519(), ed25519 = ScCrypto.generateEd25519())
    private fun own(name: String, k: PrivateKeys = rsaKeys()) = OwnKey(name, k)
    private fun to(name: String, k: PrivateKeys) = Recipient(name, k.publicKeys())

    @Test
    fun textRoundTrips() {
        val mine = rsaKeys()
        val me = own("me", mine)
        val other = own("other")
        val keys = listOf(other, me)
        assertEquals(text, ScCrypto.decrypt(ScCrypto.encrypt(listOf(to("me", mine)), text), keys).text)
        val g = ScCrypto.decrypt(ScCrypto.encrypt(listOf(to("o", rsaKeys()), to("me", mine)), text), listOf(me))
        assertEquals(text to MessageFormat.GROUP, g.text to g.format)
        val l = ScCrypto.decrypt(ScCrypto.encryptLegacy(mine.publicKeys().rsa!!, text), keys)
        assertEquals(text to "me", l.text to l.keyName)
    }

    @Test
    fun x25519AndMixedGroups() {
        val x = xKeys()
        val r = rsaKeys()
        val solo = ScCrypto.decrypt(ScCrypto.encrypt(listOf(to("x", x)), text), listOf(own("x", x)))
        assertEquals(text, solo.text)
        val msg = ScCrypto.encrypt(listOf(to("x", x), to("r", r)), text)
        assertEquals("x", ScCrypto.decrypt(msg, listOf(own("x", x))).keyName)
        assertEquals("r", ScCrypto.decrypt(msg, listOf(own("r", r))).keyName)
        assertThrows(ScException::class.java) { ScCrypto.decrypt(msg, listOf(own("z", xKeys()))) }
    }

    @Test
    fun signatures() {
        val alice = rsaKeys()
        val bob = xKeys()
        val carol = rsaKeys()
        val signer = Signer(alice.ed25519!!)
        val known = listOf(KnownSigner("alice", alice.publicKeys().ed25519!!))
        val msg = ScCrypto.encrypt(listOf(to("bob", bob)), text, signer)
        assertEquals(SigStatus.Valid("alice"), ScCrypto.decrypt(msg, listOf(own("bob", bob)), known).sig)
        assertTrue(ScCrypto.decrypt(msg, listOf(own("bob", bob))).sig is SigStatus.Unknown)
        val single = ScCrypto.encrypt(listOf(to("carol", carol)), text, signer)
        assertEquals(SigStatus.Valid("alice"), ScCrypto.decrypt(single, listOf(own("carol", carol)), known).sig)
        assertEquals(SigStatus.Unsigned, ScCrypto.decrypt(ScCrypto.encrypt(listOf(to("c", carol)), text), listOf(own("c", carol))).sig)
        // A signature lifted from a message to someone else must not verify.
        val sigOther = Regex("\"sig\":\"([^\"]+)\"").find(msg)!!.groupValues[1]
        val forged = single.replace(Regex("\"sig\":\"[^\"]+\""), "\"sig\":\"$sigOther\"")
        assertEquals(SigStatus.Invalid, ScCrypto.decrypt(forged, listOf(own("carol", carol)), known).sig)
    }

    @Test
    fun foreignAndTamperedMessagesFail() {
        val mine = rsaKeys()
        val me = own("me", mine)
        val msg = ScCrypto.encrypt(listOf(to("x", rsaKeys())), text)
        assertThrows(ScException::class.java) { ScCrypto.decrypt(msg, listOf(me)) }
        val good = ScCrypto.encrypt(listOf(to("me", mine)), text)
        val ct = Regex("\"ciphertext\":\"(.)").find(good)!!.groupValues[1]
        val bad = good.replaceFirst("\"ciphertext\":\"$ct", "\"ciphertext\":\"" + (if (ct == "A") "B" else "A"))
        assertThrows(ScException::class.java) { ScCrypto.decrypt(bad, listOf(me)) }
    }

    private fun encFile(r: Recipient, signer: Signer?, plain: ByteArray) =
        ByteArrayOutputStream().also { ScCrypto.encryptFile(r, signer, ByteArrayInputStream(plain), it) {} }.toByteArray()

    @Test
    fun fileRoundTripsAndTamper() {
        val plain = ByteArray(200_003) { (it * 31).toByte() }
        val alice = rsaKeys()
        val known = listOf(KnownSigner("alice", alice.publicKeys().ed25519!!))
        for (k in listOf(rsaKeys(), xKeys())) {
            for (signer in listOf(null, Signer(alice.ed25519!!))) {
                val enc = encFile(to("me", k), signer, plain)
                val dec = ByteArrayOutputStream()
                val r = ScCrypto.decryptFile(listOf(own("x"), own("me", k)), known, ByteArrayInputStream(enc), dec) {}
                assertEquals("me", r.keyName)
                assertArrayEquals(plain, dec.toByteArray())
                val expectSig = if (signer != null && k.rsa == null) SigStatus.Valid("alice") else SigStatus.Unsigned
                assertEquals(expectSig, r.sig)
                enc[enc.size / 2] = (enc[enc.size / 2].toInt() xor 1).toByte()
                assertThrows(ScException::class.java) {
                    ScCrypto.decryptFile(listOf(own("me", k)), known, ByteArrayInputStream(enc), ByteArrayOutputStream()) {}
                }
            }
        }
    }

    @Test
    fun pemBundles() {
        for (k in listOf(rsaKeys(), xKeys())) {
            val p = Pem.parse(Pem.encode(k))
            assertEquals(Pem.fingerprint(k.publicKeys()), Pem.fingerprint(p.public))
            assertEquals(Pem.fingerprint(k.publicKeys()), Pem.fingerprint(Pem.parse(Pem.encode(k.publicKeys())).public))
            assertEquals(23, Pem.fingerprint(p.public).length)
        }
    }

    @Test
    fun pythonInterop() {
        val dir = System.getProperty("scmess.vectors")?.let(::File)
        assumeTrue("set -Dscmess.vectors to run", dir != null && dir.isDirectory)
        dir!!
        val a = Pem.parse(File(dir, "key_a.pem").readText())
        val b = Pem.parse(File(dir, "key_b.pem").readText()) // PKCS#1
        val keys = listOf(OwnKey("a", a.private), OwnKey("b", b.private))
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
            assertEquals(key, ScCrypto.decryptFile(keys, emptyList(), File(dir, name).inputStream(), out) {}.keyName)
            assertArrayEquals(name, plain, out.toByteArray())
        }

        val curve = Pem.parse(File(dir, "curve_priv.pem").readText()).private
        assertTrue(curve.x25519 != null && curve.ed25519 != null)

        val k = File(dir, "kotlin").apply { mkdirs() }
        File(k, "curve.pem").writeText(Pem.encode(xKeys()))
        // Signed on purpose: older readers must ignore the extra "sig" field.
        val signer = Signer(ScCrypto.generateEd25519())
        val ra = Recipient("a", a.public)
        File(k, "single.json").writeText(ScCrypto.encrypt(listOf(ra), expected, signer))
        File(k, "group.json").writeText(ScCrypto.encrypt(listOf(ra, Recipient("b", b.public)), expected, signer))
        File(k, "legacy.txt").writeText(ScCrypto.encryptLegacy(b.public.rsa!!, expected))
        File(k, "file.enc").outputStream().use { ScCrypto.encryptFile(ra, signer, plain.inputStream(), it) {} }
    }
}
