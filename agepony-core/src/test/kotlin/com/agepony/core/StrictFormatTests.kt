package com.agepony.core

import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.HKDF
import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.ScryptIdentity
import com.agepony.core.recipients.ScryptRecipient
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Hand-built negative vectors in the style of the C2SP age CCTV testkit (audit L-1, L-2, L-3,
 * L-5 and the empty-final-chunk finding). Every malformed file must be refused by both the
 * whole-buffer and the streaming decrypt. Where the reference `age` binary is on PATH, each
 * vector is also fed to it, to prove AgePony is never stricter than Go age, and every positive
 * control is checked to open there too.
 */
class StrictFormatTests {
    private val rng = SecureRandom()
    private val id = X25519Identity.generate()
    private val recipient = X25519Recipient(id.publicKey)
    private val plaintext = "strict parsing".toByteArray()

    private fun fileKey() = ByteArray(16).also { rng.nextBytes(it) }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(data) }

    /** Header text up to and including "---", given a correct MAC, then [payload]. */
    private fun craft(
        key: ByteArray,
        headerNoMac: String,
        payload: ByteArray = AgePayload.encrypt(key, plaintext),
        macLine: ((String) -> String)? = null,
    ): ByteArray {
        val macInput = headerNoMac.toByteArray(Charsets.ISO_8859_1)
        val mac = Stanza.base64NoPad(hmac(HKDF.derive(key, ByteArray(0), "header".toByteArray(), 32), macInput))
        val line = macLine?.invoke(mac) ?: mac
        return macInput + " $line\n".toByteArray(Charsets.ISO_8859_1) + payload
    }

    private fun v1(vararg lines: String) = "age-encryption.org/v1\n" + lines.joinToString("")

    private fun decryptWhole(ct: ByteArray, ids: List<AgeIdentity> = listOf(id)) = Age.decrypt(ct, ids)

    private fun decryptStreamed(ct: ByteArray, ids: List<AgeIdentity> = listOf(id)): ByteArray {
        val out = ByteArrayOutputStream()
        Age.decryptStream(ByteArrayInputStream(ct), ids, out)
        return out.toByteArray()
    }

    private fun <T : Throwable> rejects(type: Class<T>, ct: ByteArray, what: String, goToo: Boolean = true) {
        assertThrows(type, { decryptWhole(ct) }, "whole-buffer accepted: $what")
        assertThrows(type, { decryptStreamed(ct) }, "streaming accepted: $what")
        if (goToo) assertFalse(GoAge.decrypts(ct, id.toBech32()) == true, "Go age accepted: $what")
    }

    private fun opens(ct: ByteArray, expected: ByteArray = plaintext) {
        assertArrayEquals(expected, decryptWhole(ct))
        assertArrayEquals(expected, decryptStreamed(ct))
        val go = GoAge.decrypt(ct, id.toBech32())
        if (go != null) assertArrayEquals(expected, go, "Go age output differs")
    }

    /** The base64 alphabet index trick: same top bits, different unused low bits. */
    private fun flipTrailingBits(b64: String): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val last = alphabet.indexOf(b64.last())
        return b64.dropLast(1) + alphabet[last xor 1]
    }

    // --- Positive controls ---

    @Test
    fun craftedCanonicalHeaderOpens() {
        val key = fileKey()
        opens(craft(key, v1(recipient.wrap(key).serialize(), "---")))
    }

    @Test
    fun agePonySerializerOutputIsAcceptedHereAndByGo() {
        // Unknown stanzas of every body-length shape (empty, short, exactly one and two full
        // lines, and just past them) ride along with the real recipient. Go re-serializes the
        // header to check the MAC, so Go opening these proves the byte format matches.
        for (n in listOf(0, 1, 2, 3, 47, 48, 49, 95, 96, 97, 150)) {
            val body = ByteArray(n).also { rng.nextBytes(it) }
            val ct = Age.encrypt(plaintext, listOf(recipient)) { listOf(Stanza("grease-test", listOf("a", "b~!"), body)) }
            val parsed = AgeHeader.parse(ct)
            assertEquals(2, parsed.stanzas.size)
            assertArrayEquals(body, parsed.stanzas[1].body, "body of $n bytes did not round-trip")
            opens(ct)
        }
    }

    @Test
    fun goOutputOfEveryChunkShapeOpens() {
        if (GoAge.bin == null) return
        for (n in listOf(0, 1, AgePayload.CHUNK_SIZE - 1, AgePayload.CHUNK_SIZE, AgePayload.CHUNK_SIZE + 1, 2 * AgePayload.CHUNK_SIZE)) {
            val pt = ByteArray(n).also { rng.nextBytes(it) }
            for (armor in listOf(false, true)) {
                val ct = GoAge.encrypt(pt, recipient.toBech32(), armor)!!
                val binary = if (armor) Armor.decode(String(ct, Charsets.US_ASCII)) else ct
                assertArrayEquals(pt, decryptWhole(binary), "Go file of $n bytes (armor=$armor)")
                if (armor) {
                    val out = ByteArrayOutputStream()
                    Age.decryptStream(Armor.decodingSource(ByteArrayInputStream(ct)), listOf(id), out)
                    assertArrayEquals(pt, out.toByteArray(), "Go armored stream of $n bytes")
                } else {
                    assertArrayEquals(pt, decryptStreamed(binary))
                }
            }
        }
    }

    // --- L-1: header and stanza encoding ---

    @Test
    fun rejectsNonCanonicalMacTrailingBits() {
        val ct = Age.encrypt(plaintext, listOf(recipient))
        val s = String(ct, Charsets.ISO_8859_1)
        val at = s.indexOf("\n--- ") + 5
        val mac = s.substring(at, at + 43)
        val bad = (s.substring(0, at) + flipTrailingBits(mac) + s.substring(at + 43)).toByteArray(Charsets.ISO_8859_1)
        // Decodes to the same 32 bytes, so a lenient decoder would still open the file.
        assertArrayEquals(Base64Lenient.decode(mac), Base64Lenient.decode(flipTrailingBits(mac)))
        rejects(AgeHeader.HeaderException::class.java, bad, "MAC with non-zero trailing bits")
    }

    @Test
    fun rejectsPaddedMacAndMacLineJunk() {
        val key = fileKey()
        val h = v1(recipient.wrap(key).serialize(), "---")
        rejects(AgeHeader.HeaderException::class.java, craft(key, h, macLine = { "$it=" }), "padded MAC")
        rejects(AgeHeader.HeaderException::class.java, craft(key, h, macLine = { "$it " }), "MAC with trailing space")
        rejects(AgeHeader.HeaderException::class.java, craft(key, h, macLine = { "$it\r" }), "MAC with CR")
        rejects(AgeHeader.HeaderException::class.java, craft(key, h, macLine = { it.dropLast(1) }), "short MAC")
        rejects(AgeHeader.HeaderException::class.java, craft(key, h, macLine = { " $it" }), "MAC after two spaces")
    }

    @Test
    fun rejectsNonCanonicalBodyEncodings() {
        val key = fileKey()
        val st = recipient.wrap(key)
        val b64 = Stanza.base64NoPad(st.body)   // 43 chars: one short line
        val arg = st.args[0]
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1("-> X25519 $arg\n", flipTrailingBits(b64), "\n---")), "body trailing bits")
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1("-> X25519 $arg\n", "$b64=", "\n---")), "padded body")
        // A non-canonical argument parses (arguments are opaque to the header grammar) but the
        // X25519 identity refuses to decode it, as Go's does.
        rejects(Age.NoMatchingIdentityException::class.java, craft(key, v1("-> X25519 ${flipTrailingBits(arg)}\n", b64, "\n---")), "arg trailing bits")
    }

    @Test
    fun rejectsBadBodyLineLengths() {
        val key = fileKey()
        val real = recipient.wrap(key).serialize()
        val body = ByteArray(60).also { rng.nextBytes(it) }
        val b64 = Stanza.base64NoPad(body)   // 80 chars, canonically 64 + 16
        val good = craft(key, v1(real, "-> grease\n", b64.substring(0, 64), "\n", b64.substring(64), "\n---"))
        opens(good)
        rejects(AgeHeader.HeaderException::class.java,
            craft(key, v1(real, "-> grease\n", b64.substring(0, 60), "\n", b64.substring(60), "\n---")), "60-column wrap")
        rejects(AgeHeader.HeaderException::class.java,
            craft(key, v1(real, "-> grease\n", b64, "\n---")), "80-column line")

        // A body that is exactly one full line must be followed by an empty line.
        val full = Stanza.base64NoPad(ByteArray(48).also { rng.nextBytes(it) })
        opens(craft(key, v1(real, "-> grease\n", full, "\n\n---")))
        rejects(AgeHeader.HeaderException::class.java,
            craft(key, v1(real, "-> grease\n", full, "\n---")), "full line without terminator")
        rejects(AgeHeader.HeaderException::class.java,
            craft(key, v1("-> grease\n", full, "\n", real, "---")), "full line straight into next stanza")
        // An empty body needs its empty line too.
        opens(craft(key, v1(real, "-> grease\n\n---")))
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1(real, "-> grease\n---")), "no body line at all")
    }

    @Test
    fun rejectsStrayLinesAndBadStanzaLines() {
        val key = fileKey()
        val st = recipient.wrap(key)
        val real = st.serialize()
        val bodyLine = Stanza.base64NoPad(st.body)
        val arg = st.args[0]
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1(real, "\n---")), "blank line before MAC")
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1("\n", real, "---")), "blank line after version")
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1("-> X25519  $arg\n$bodyLine\n---")), "double space")
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1("-> X25519 $arg \n$bodyLine\n---")), "trailing space")
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1(real, "-> grease a\tb\n\n---")), "tab in argument")
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1(real, "-> grease café\n\n---")), "non-ASCII argument")
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1(real, "-> grease \u007f\n\n---")), "DEL in argument")
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1(real, "->\n\n---")), "stanza with no type")
        rejects(AgeHeader.HeaderException::class.java, craft(key, "age-encryption.org/v1\r\n$real---"), "CRLF version line")
        rejects(AgeHeader.HeaderException::class.java, craft(key, v1(real.replace("\n", "\r\n"), "---")), "CRLF stanza")
        rejects(AgeHeader.HeaderException::class.java, craft(key, "age-encryption.org/v2\n$real---"), "wrong version")
    }

    // --- L-2: scrypt must be alone ---

    @Test
    fun rejectsScryptMixedWithAnotherStanzaBeforeAnyKdf() {
        val key = fileKey()
        // The second scrypt stanza claims work factor 22: if anything ran the KDF on it the
        // test would take seconds and gigabytes, which is the attack.
        val cheap = ScryptRecipient("pw", workFactor = 10).wrap(key)
        val costly = Stanza("scrypt", listOf(cheap.args[0], "22"), cheap.body)
        var watched = false
        val watching = AgeIdentity { s -> if (s.type == "scrypt") watched = true; null }
        for (header in listOf(v1(recipient.wrap(key).serialize(), costly.serialize(), "---"),
                              v1(cheap.serialize(), costly.serialize(), "---"),
                              v1(costly.serialize(), recipient.wrap(key).serialize(), "---"))) {
            val ct = craft(key, header)
            val ids = listOf(watching, ScryptIdentity("pw"))
            assertThrows(AgeHeader.HeaderException::class.java) { Age.decrypt(ct, ids) }
            assertThrows(AgeHeader.HeaderException::class.java) {
                Age.decryptStream(ByteArrayInputStream(ct), ids, ByteArrayOutputStream())
            }
            assertThrows(AgeHeader.HeaderException::class.java) { Age.canDecryptStream(ByteArrayInputStream(ct), ids) }
            assertThrows(AgeHeader.HeaderException::class.java) { Age.decryptAndRecoverSignature(ct, ids) }
            assertFalse(watched, "an identity was shown a stanza of a mixed scrypt header")
        }
        // Go age puts this check in ScryptIdentity, so an X25519 key still opens a mixed file
        // (no KDF runs). AgePony matches that rather than refusing what Go accepts.
        val mixed = craft(key, v1(recipient.wrap(key).serialize(), costly.serialize(), "---"))
        opens(mixed)
        // Scrypt on its own still opens.
        val alone = Age.encrypt(plaintext, listOf(ScryptRecipient("pw", workFactor = 10)))
        assertArrayEquals(plaintext, Age.decrypt(alone, listOf(ScryptIdentity("pw"))))
    }

    @Test
    fun scryptWorkFactorParsingIsStrict() {
        val key = fileKey()
        val good = ScryptRecipient("pw", workFactor = 10).wrap(key)
        val ident = ScryptIdentity("pw")
        assertArrayEquals(key, ident.unwrap(good))
        for (wf in listOf("010", "+10", "-10", "1e1", "10 ", "", "0", "99999999999", "23")) {
            assertNull(ident.unwrap(Stanza("scrypt", listOf(good.args[0], wf), good.body)), "work factor '$wf'")
        }
    }

    // --- L-5: wrapped file-key sizes ---

    @Test
    fun rejectsWrongWrappedBodySizes() {
        val key = fileKey()
        val st = recipient.wrap(key)
        for (body in listOf(st.body + byteArrayOf(0), st.body.copyOf(31), ByteArray(0))) {
            assertNull(id.unwrap(Stanza(st.type, st.args, body)))
            val ct = craft(key, v1(Stanza(st.type, st.args, body).serialize(), "---"))
            rejects(Age.NoMatchingIdentityException::class.java, ct, "X25519 body of ${body.size} bytes")
        }
        val sc = ScryptRecipient("pw", workFactor = 10).wrap(key)
        assertNull(ScryptIdentity("pw").unwrap(Stanza(sc.type, sc.args, sc.body + byteArrayOf(0))))
    }

    @Test
    fun rejectsAnUnwrappedFileKeyThatIsNot16Bytes() {
        val key = fileKey()
        val ct = craft(key, v1(Stanza("custom", listOf("x"), ByteArray(4)).serialize(), "---"))
        val odd = AgeIdentity { ByteArray(15) }
        assertThrows(AgeHeader.HeaderException::class.java) { Age.decrypt(ct, listOf(odd)) }
        assertThrows(AgeHeader.HeaderException::class.java) {
            Age.decryptStream(ByteArrayInputStream(ct), listOf(odd), ByteArrayOutputStream())
        }
    }

    // --- Low-order X25519 ---

    @Test
    fun lowOrderEphemeralShareIsNotForUs() {
        val key = fileKey()
        val st = recipient.wrap(key)
        // u = 0 and u = 1 are low-order points; BC refuses the all-zero shared secret.
        for (u in listOf(ByteArray(32), ByteArray(32).also { it[0] = 1 })) {
            val bad = Stanza("X25519", listOf(Stanza.base64NoPad(u)), st.body)
            assertNull(id.unwrap(bad))
            rejects(Age.NoMatchingIdentityException::class.java, craft(key, v1(bad.serialize(), "---")), "low-order share", goToo = false)
        }
    }

    @Test
    fun refusesToEncryptToALowOrderRecipient() {
        val e = assertThrows(IllegalArgumentException::class.java) { X25519Recipient(ByteArray(32)).wrap(fileKey()) }
        assertTrue(e.message!!.contains("low-order"))
    }

    // --- L-3: header size cap ---

    @Test
    fun streamingHeaderReadIsCappedAtOneMiB() {
        var served = 0L
        val endless = object : InputStream() {
            private val pattern = "-> grease\nAAAA\n".toByteArray()
            private val intro = "age-encryption.org/v1\n".toByteArray()
            override fun read(): Int {
                val b = if (served < intro.size) intro[served.toInt()] else pattern[((served - intro.size) % pattern.size).toInt()]
                served++
                return b.toInt() and 0xff
            }
        }
        assertThrows(AgeHeader.HeaderException::class.java) {
            Age.decryptStream(endless, listOf(id), ByteArrayOutputStream())
        }
        assertTrue(served <= AgeHeader.MAX_HEADER_SIZE, "read $served bytes before giving up")

        val big = ByteArray(AgeHeader.MAX_HEADER_SIZE + 10) { 'A'.code.toByte() }
        assertThrows(AgeHeader.HeaderException::class.java) { AgeHeader.parse(big) }
        assertThrows(AgeHeader.HeaderException::class.java) { Age.parseHeaderStream(ByteArrayInputStream(big)) }
    }

    @Test
    fun headerJustUnderTheCapStillOpens() {
        val key = fileKey()
        val real = recipient.wrap(key).serialize()
        val filler = StringBuilder()
        val grease = "-> grease\n\n"
        while (filler.length + grease.length < 900 * 1024) filler.append(grease)
        opens(craft(key, v1(real, filler.toString(), "---")))
    }

    // --- STREAM payload ---

    private fun chunk(payloadKey: ByteArray, counter: Long, last: Boolean, pt: ByteArray): ByteArray {
        val nonce = ByteArray(12)
        var c = counter
        for (i in 10 downTo 0) { nonce[i] = (c and 0xff).toByte(); c = c ushr 8 }
        nonce[11] = if (last) 1 else 0
        return ChaChaPoly.encrypt(payloadKey, nonce, pt)
    }

    @Test
    fun rejectsAnEmptyFinalChunkAfterAFullOne() {
        val key = fileKey()
        val nonce = ByteArray(16).also { rng.nextBytes(it) }
        val pk = HKDF.derive(key, nonce, "payload".toByteArray(), 32)
        val full = ByteArray(AgePayload.CHUNK_SIZE).also { rng.nextBytes(it) }
        val payload = nonce + chunk(pk, 0, false, full) + chunk(pk, 1, true, ByteArray(0))
        assertThrows(AgePayload.PayloadException::class.java) { AgePayload.decrypt(key, payload) }
        assertThrows(AgePayload.PayloadException::class.java) {
            AgePayload.decryptStream(key, ByteArrayInputStream(payload), ByteArrayOutputStream())
        }
        rejects(AgePayload.PayloadException::class.java,
            craft(key, v1(recipient.wrap(key).serialize(), "---"), payload), "empty final chunk")
        // The canonical encoding of the same plaintext (full chunk flagged last) opens.
        val canonical = nonce + chunk(pk, 0, true, full)
        opens(craft(key, v1(recipient.wrap(key).serialize(), "---"), canonical), full)
    }

    @Test
    fun exactChunkMultiplesNeverEmitAnEmptyFinalChunk() {
        for (n in listOf(AgePayload.CHUNK_SIZE, 2 * AgePayload.CHUNK_SIZE, 3 * AgePayload.CHUNK_SIZE)) {
            val pt = ByteArray(n).also { rng.nextBytes(it) }
            val key = fileKey()
            val whole = AgePayload.encrypt(key, pt)
            val streamed = ByteArrayOutputStream().also { AgePayload.encryptStream(key, ByteArrayInputStream(pt), it) }.toByteArray()
            // 16-byte nonce plus n/64KiB full chunks and nothing else.
            val expected = 16 + (n / AgePayload.CHUNK_SIZE) * AgePayload.CT_CHUNK_SIZE
            assertEquals(expected, whole.size, "whole-buffer size at $n")
            assertEquals(expected, streamed.size, "streamed size at $n")
            assertArrayEquals(pt, AgePayload.decrypt(key, whole))
            assertArrayEquals(pt, AgePayload.decrypt(key, streamed))

            val file = Age.encrypt(pt, listOf(recipient))
            opens(file, pt)
            val fileStreamed = ByteArrayOutputStream().also { Age.encryptStream(ByteArrayInputStream(pt), listOf(recipient), it) }.toByteArray()
            opens(fileStreamed, pt)
        }
    }

    @Test
    fun rejectsTrailingDataAndTruncationAtAChunkBoundary() {
        val pt = ByteArray(2 * AgePayload.CHUNK_SIZE).also { rng.nextBytes(it) }
        val ct = Age.encrypt(pt, listOf(recipient))
        rejects(AgePayload.PayloadException::class.java, ct + byteArrayOf(0), "one trailing byte")
        rejects(AgePayload.PayloadException::class.java, ct + ByteArray(16), "trailing tag-sized block")
        val headerLen = AgeHeader.parse(ct).payloadStart
        val oneChunk = ct.copyOf(headerLen + 16 + AgePayload.CT_CHUNK_SIZE)
        rejects(AgePayload.PayloadException::class.java, oneChunk, "truncated at the first chunk boundary")
        rejects(AgePayload.PayloadException::class.java, ct.copyOf(headerLen + 16), "nonce only")
        rejects(AgePayload.PayloadException::class.java, ct.copyOf(ct.size - 1), "last byte missing")
    }

    // --- Armor (Go's armor rules, bounded line reads) ---

    private fun armorRejects(text: String, what: String, goToo: Boolean = true) {
        assertThrows(Armor.ArmorException::class.java, { Armor.decode(text) }, "decode accepted: $what")
        assertThrows(Armor.ArmorException::class.java, {
            Armor.decodingSource(ByteArrayInputStream(text.toByteArray(Charsets.ISO_8859_1))).readBytes()
        }, "stream accepted: $what")
        if (goToo) assertFalse(GoAge.decrypts(text.toByteArray(Charsets.ISO_8859_1), id.toBech32()) == true, "Go age accepted: $what")
    }

    private fun armorOpens(text: String, expected: ByteArray, goToo: Boolean = true) {
        assertArrayEquals(expected, Age.decrypt(Armor.decode(text), listOf(id)))
        val out = ByteArrayOutputStream()
        Age.decryptStream(Armor.decodingSource(ByteArrayInputStream(text.toByteArray(Charsets.ISO_8859_1))), listOf(id), out)
        assertArrayEquals(expected, out.toByteArray())
        if (goToo) GoAge.decrypt(text.toByteArray(Charsets.ISO_8859_1), id.toBech32())?.let { assertArrayEquals(expected, it) }
    }

    private fun armoredLines(ct: ByteArray): List<String> =
        Armor.encode(ct).trimEnd('\n').split('\n').drop(1).dropLast(1)

    @Test
    fun armorFollowsGoLineRules() {
        val ct = Age.encrypt(ByteArray(300).also { rng.nextBytes(it) }, listOf(recipient))
        val pt = Age.decrypt(ct, listOf(id))
        val lines = armoredLines(ct)
        val b = Armor.BEGIN_MARKER
        val e = Armor.END_MARKER
        fun join(body: List<String>) = "$b\n" + body.joinToString("\n") + "\n$e\n"

        armorOpens(join(lines), pt)
        armorOpens(join(lines).replace("\n", "\r\n"), pt)
        armorOpens("\n \n" + join(lines) + "\n\n", pt)
        // Whitespace at line ends is tolerated for pasted text (Go is stricter here).
        armorOpens(join(lines).replace("\n", " \t\n"), pt, goToo = false)

        val flat = lines.joinToString("")
        armorRejects(join(flat.chunked(76)), "76-column lines")
        armorRejects(join(flat.chunked(60)), "60-column lines")
        armorRejects(join(lines.take(2) + "" + lines.drop(2)), "blank line inside the body")
        val last = lines.last()
        val unpadded = last.trimEnd('=')
        if (unpadded != last) armorRejects(join(lines.dropLast(1) + unpadded), "missing padding")
        armorRejects(join(lines.dropLast(1) + (last + "==")), "extra padding")
        armorRejects(join(lines) + "junk\n", "junk after END")
        armorRejects(join(lines).replace(e, "-----END AGE ENCRYPTED FILE"), "bad END")
        armorRejects("$b\n" + lines.joinToString("\n") + "\n", "missing END")
    }

    @Test
    fun armorWithAFullFinalLineOpensHereAndInGo() {
        // One X25519 stanza gives a 168-byte header; 16 + 40 + 16 payload bytes make 240 = 5 * 48,
        // so the armored body is five full 64-column lines and no short one.
        val pt = ByteArray(40).also { rng.nextBytes(it) }
        val ct = Age.encrypt(pt, listOf(recipient))
        assertEquals(0, ct.size % 48)
        val lines = armoredLines(ct)
        assertTrue(lines.all { it.length == 64 })
        armorOpens(Armor.encode(ct), pt)
        // A short line (even an empty one) may only be followed by END.
        val b = Armor.BEGIN_MARKER
        val e = Armor.END_MARKER
        armorOpens("$b\n" + lines.joinToString("\n") + "\n\n$e\n", pt)
        armorRejects("$b\n" + lines.joinToString("\n") + "\n\n\n$e\n", "two blank lines before END")
    }

    @Test
    fun armorRejectsNonCanonicalFinalGroup() {
        // 301 bytes of age ciphertext is not a multiple of 3, so the last group has spare bits.
        var ct: ByteArray
        do { ct = Age.encrypt(ByteArray(rng.nextInt(64) + 1), listOf(recipient)) } while (ct.size % 3 == 0)
        val lines = armoredLines(ct)
        val last = lines.last()
        val data = last.trimEnd('=')
        val bad = flipTrailingBits(data) + last.substring(data.length)
        val text = Armor.BEGIN_MARKER + "\n" + (lines.dropLast(1) + bad).joinToString("\n") + "\n" + Armor.END_MARKER + "\n"
        armorRejects(text, "non-zero trailing bits in armor")
    }

    @Test
    fun armorLineReadsAreBounded() {
        var served = 0L
        val noNewlines = object : InputStream() {
            private val head = (Armor.BEGIN_MARKER + "\n").toByteArray()
            override fun read(): Int {
                val b = if (served < head.size) head[served.toInt()].toInt() else 'A'.code
                served++
                return b
            }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                for (i in 0 until len) b[off + i] = read().toByte()
                return len
            }
        }
        assertThrows(Armor.ArmorException::class.java) { Armor.decodingSource(noNewlines).readBytes() }
        assertTrue(served < 64 * 1024, "read $served bytes of a newline-free line")
    }
}

/** JDK base64 without the strictness, to show a vector really is only non-canonical. */
private object Base64Lenient {
    fun decode(s: String): ByteArray = java.util.Base64.getDecoder().decode(s)
}

/**
 * The reference Go `age` binary, when present (set AGE_BIN or put `age` on PATH). All calls
 * return null when it is missing, so the Go comparisons simply drop out.
 */
internal object GoAge {
    val bin: String? by lazy {
        val candidate = System.getenv("AGE_BIN") ?: "age"
        try {
            val p = ProcessBuilder(candidate, "--version").redirectErrorStream(true).start()
            p.inputStream.readBytes()
            if (p.waitFor() == 0) candidate else null
        } catch (_: Exception) {
            null
        }
    }

    private fun temp(bytes: ByteArray): File =
        Files.createTempFile("agepony-go", ".bin").toFile().apply { writeBytes(bytes); deleteOnExit() }

    /** A path that does not exist yet, so age never has to overwrite anything. */
    private fun outPath(): File =
        File(Files.createTempDirectory("agepony-go").toFile().apply { deleteOnExit() }, "out").apply { deleteOnExit() }

    /** Plaintext from Go age, or null if Go refused the file (or is not installed). */
    fun decrypt(ct: ByteArray, identity: String): ByteArray? {
        val b = bin ?: return null
        val idFile = temp((identity + "\n").toByteArray())
        val input = temp(ct)
        val output = outPath()
        val p = ProcessBuilder(b, "-d", "-i", idFile.path, "-o", output.path, input.path)
            .redirectErrorStream(true).start()
        p.inputStream.readBytes()
        return if (p.waitFor() == 0) output.readBytes() else null
    }

    /** True or false when Go is installed; null when it is not. */
    fun decrypts(ct: ByteArray, identity: String): Boolean? = bin?.let { decrypt(ct, identity) != null }

    fun encrypt(pt: ByteArray, recipient: String, armor: Boolean): ByteArray? {
        val b = bin ?: return null
        val input = temp(pt)
        val output = outPath()
        val args = mutableListOf(b, "-r", recipient, "-o", output.path)
        if (armor) args += "-a"
        args += input.path
        val p = ProcessBuilder(args).redirectErrorStream(true).start()
        val log = p.inputStream.readBytes()
        check(p.waitFor() == 0) { "age encrypt failed: ${String(log)}" }
        return output.readBytes()
    }
}
