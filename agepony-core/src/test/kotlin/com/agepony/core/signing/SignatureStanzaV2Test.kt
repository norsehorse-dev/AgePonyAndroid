package com.agepony.core.signing

import com.agepony.core.Age
import com.agepony.core.AgeHeader
import com.agepony.core.Stanza
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.ScryptRecipient
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * The v2 signature stanza binds the recipient stanzas (audit L-8), v1 keeps verifying as before,
 * and a stanza that is present but unreadable is reported as such, not as unsigned (audit L-9).
 */
class SignatureStanzaV2Test {
    private val rng = SecureRandom()
    private val seed = ByteArray(32).also { rng.nextBytes(it) }
    private val pub = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    private val plaintext = "signed and sealed".toByteArray()

    private fun sha512(b: ByteArray) = SSHSig.hashMessage(b, SSHSig.HASH_SHA512)

    /** What the app does: prepare, sign the v2 message hash, encrypt. */
    private fun signedV2(to: List<com.agepony.core.recipients.AgeRecipient>, data: ByteArray = plaintext): ByteArray {
        val enc = SignedEncryption.prepare(to)
        val sig = SSHSigner.signEd25519Hashed(seed, pub, enc.messageHash(sha512(data)), SignatureStanza.NAMESPACE_V2)
        return enc.encrypt(data, sig)
    }

    /** Decrypt the way Age.decryptAndRecoverSignature does, returning the file key and header too. */
    private class Opened(val fileKey: ByteArray, val header: AgeHeader.ParsedHeader, val plaintext: ByteArray)

    private fun open(ct: ByteArray, id: X25519Identity): Opened {
        val header = AgeHeader.parse(ct)
        val fk = header.stanzas.firstNotNullOf { id.unwrap(it) }
        AgeHeader.verifyMAC(header.macInputBytes, header.mac, fk)
        return Opened(fk, header, Age.decrypt(ct, listOf(id)))
    }

    private fun rebuild(fileKey: ByteArray, stanzas: List<Stanza>, original: ByteArray): ByteArray {
        val payload = original.copyOfRange(AgeHeader.parse(original).payloadStart, original.size)
        return AgeHeader.serialize(stanzas, fileKey) + payload
    }

    // --- plain age compatibility ---

    /** A v2-signed file is still an ordinary age file: Go age returns the bare plaintext. */
    @Test
    fun v2SignedFileDecryptsWithPlainAge() {
        val id = X25519Identity.generate()
        val ct = signedV2(listOf(X25519Recipient(id.publicKey)))
        org.junit.jupiter.api.Assumptions.assumeTrue(com.agepony.core.GoAge.bin != null, "Go age not installed")
        val fromGo = com.agepony.core.GoAge.decrypt(ct, id.toBech32())
        assertNotNull(fromGo, "Go age refused a v2-signed file")
        assertArrayEquals(plaintext, fromGo)
    }

    // --- v1 compatibility ---

    @Test
    fun v1StillVerifies() {
        val id = X25519Identity.generate()
        val sig = SSHSigner.signEd25519(seed, pub, plaintext) // namespace "agepony", over the plaintext
        val ct = Age.encrypt(plaintext, listOf(X25519Recipient(id.publicKey))) { fk -> listOf(SignatureStanza.build(fk, sig)) }
        val o = open(ct, id)
        val opening = SignatureStanza.openHeader(o.fileKey, o.header.stanzas) as SignatureStanza.Opening.Opened
        assertEquals(1, opening.version)
        assertFalse(opening.coversRecipients)
        assertEquals(SSHSig.NAMESPACE_AGEPONY, opening.namespace)
        assertEquals(sig, opening.signatureArmored)
        assertArrayEquals(plaintext, opening.signedMessage(plaintext))
        assertTrue(opening.verify(o.plaintext).valid)
        assertTrue(SSHSigVerifier.verifyHashed(sig.toByteArray(), opening.namespace) { alg ->
            opening.messageHash(alg) { a -> SSHSig.hashMessage(plaintext, a) }
        }.valid)
        // The old API still returns the same signature.
        assertEquals(sig, Age.decryptAndRecoverSignature(ct, listOf(id)).signatureArmored)
    }

    // --- v2 ---

    @Test
    fun v2RoundTrip() {
        val a = X25519Identity.generate()
        val b = X25519Identity.generate()
        val ct = signedV2(listOf(X25519Recipient(a.publicKey), X25519Recipient(b.publicKey)))
        // Plain age reads it: the sig stanza is just an unknown stanza.
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(b)))
        val o = open(ct, a)
        assertEquals(SignatureStanza.TYPE, o.header.stanzas.last().type)
        assertEquals(listOf(SignatureStanza.VERSION_V2), o.header.stanzas.last().args)
        val opening = SignatureStanza.openHeader(o.fileKey, o.header.stanzas) as SignatureStanza.Opening.Opened
        assertEquals(2, opening.version)
        assertTrue(opening.coversRecipients)
        assertEquals(SignatureStanza.NAMESPACE_V2, opening.namespace)
        val r = opening.verify(o.plaintext)
        assertTrue(r.valid, r.reason)
        assertArrayEquals(SSHSig.ed25519PublicWire(pub), r.signerPublicWire)
        // Streaming form agrees.
        assertTrue(SSHSigVerifier.verifyHashed(opening.signatureArmored.toByteArray(), opening.namespace) { alg ->
            opening.messageHash(alg) { a2 -> SSHSig.hashMessage(o.plaintext, a2) }
        }.valid)
        // The old nullable API hands back the v2 signature, which fails a v1-style check.
        val legacy = Age.decryptAndRecoverSignature(ct, listOf(a)).signatureArmored
        assertEquals(opening.signatureArmored, legacy)
        assertFalse(SSHSigVerifier.verify(legacy!!.toByteArray(), plaintext).valid)
    }

    @Test
    fun v2WorksWithPostQuantumRecipients() {
        val id = HybridIdentity.generate()
        val ct = signedV2(listOf(id.recipient()))
        val header = AgeHeader.parse(ct)
        val fk = header.stanzas.firstNotNullOf { id.unwrap(it) }
        val opening = SignatureStanza.openHeader(fk, header.stanzas) as SignatureStanza.Opening.Opened
        assertTrue(opening.verify(Age.decrypt(ct, listOf(id))).valid)
    }

    @Test
    fun v2FailsWhenARecipientIsAdded() {
        val a = X25519Identity.generate()
        val ct = signedV2(listOf(X25519Recipient(a.publicKey)))
        val o = open(ct, a)
        // A recipient re-wraps the file key to someone new and keeps the signature stanza.
        val eve = X25519Identity.generate()
        val sig = o.header.stanzas.last()
        val forged = rebuild(o.fileKey, o.header.stanzas.dropLast(1) + X25519Recipient(eve.publicKey).wrap(o.fileKey) + sig, ct)
        val fo = open(forged, eve)
        assertArrayEquals(plaintext, fo.plaintext)
        val opening = SignatureStanza.openHeader(fo.fileKey, fo.header.stanzas) as SignatureStanza.Opening.Opened
        assertFalse(opening.verify(fo.plaintext).valid)
    }

    @Test
    fun v2FailsWhenRecipientsAreReplaced() {
        val a = X25519Identity.generate()
        val ct = signedV2(listOf(X25519Recipient(a.publicKey)))
        val o = open(ct, a)
        val eve = X25519Identity.generate()
        val forged = rebuild(o.fileKey, listOf(X25519Recipient(eve.publicKey).wrap(o.fileKey), o.header.stanzas.last()), ct)
        val fo = open(forged, eve)
        val opening = SignatureStanza.openHeader(fo.fileKey, fo.header.stanzas) as SignatureStanza.Opening.Opened
        assertFalse(opening.verify(fo.plaintext).valid)
    }

    @Test
    fun v2FailsForADifferentPlaintext() {
        val a = X25519Identity.generate()
        val o = open(signedV2(listOf(X25519Recipient(a.publicKey))), a)
        val opening = SignatureStanza.openHeader(o.fileKey, o.header.stanzas) as SignatureStanza.Opening.Opened
        assertFalse(opening.verify("something else".toByteArray()).valid)
    }

    @Test
    fun v2SignatureCannotBeDowngradedToV1() {
        val a = X25519Identity.generate()
        val ct = signedV2(listOf(X25519Recipient(a.publicKey)))
        val o = open(ct, a)
        val armored = (SignatureStanza.openHeader(o.fileKey, o.header.stanzas) as SignatureStanza.Opening.Opened).signatureArmored
        // Re-seal the same SSHSIG as a v1 stanza: the v1 check runs under "agepony" and fails.
        val forged = rebuild(o.fileKey, o.header.stanzas.dropLast(1) + SignatureStanza.build(o.fileKey, armored), ct)
        val fo = open(forged, a)
        val opening = SignatureStanza.openHeader(fo.fileKey, fo.header.stanzas) as SignatureStanza.Opening.Opened
        assertEquals(1, opening.version)
        val r = opening.verify(fo.plaintext)
        assertFalse(r.valid)
        assertTrue(r.reason!!.contains("namespace"))
    }

    @Test
    fun v2RejectsTheWrongNamespace() {
        val a = X25519Identity.generate()
        val enc = SignedEncryption.prepare(listOf(X25519Recipient(a.publicKey)))
        val hash = enc.messageHash(sha512(plaintext))
        val wrongNs = SSHSigner.signEd25519Hashed(seed, pub, hash, SSHSig.NAMESPACE_AGEPONY)
        assertThrows(IllegalArgumentException::class.java) { enc.encrypt(plaintext, wrongNs) }
        val overPlaintext = SSHSigner.signEd25519Hashed(seed, pub, sha512(plaintext), SignatureStanza.NAMESPACE_V2)
        assertThrows(IllegalArgumentException::class.java) { enc.encrypt(plaintext, overPlaintext) }

        // Built by hand, a v2 stanza holding an "agepony" signature fails verification.
        val ct = Age.encrypt(plaintext, listOf(X25519Recipient(a.publicKey))) { fk ->
            listOf(SignatureStanza.buildV2(fk, SSHSigner.signEd25519(seed, pub, plaintext)))
        }
        val o = open(ct, a)
        val opening = SignatureStanza.openHeader(o.fileKey, o.header.stanzas) as SignatureStanza.Opening.Opened
        val r = opening.verify(o.plaintext)
        assertFalse(r.valid)
        assertTrue(r.reason!!.contains("namespace"))
    }

    @Test
    fun v2StreamMatchesAndCatchesAChangedStream() {
        val a = X25519Identity.generate()
        val enc = SignedEncryption.prepare(listOf(X25519Recipient(a.publicKey)))
        val big = ByteArray(200_000).also { rng.nextBytes(it) }
        val h = sha512(big)
        val sig = SSHSigner.signEd25519Hashed(seed, pub, enc.messageHash(h), SignatureStanza.NAMESPACE_V2)
        val out = ByteArrayOutputStream()
        enc.encryptStream(ByteArrayInputStream(big), h, sig, out)
        val o = open(out.toByteArray(), a)
        assertArrayEquals(big, o.plaintext)
        assertTrue((SignatureStanza.openHeader(o.fileKey, o.header.stanzas) as SignatureStanza.Opening.Opened).verify(o.plaintext).valid)

        val changed = big.copyOf().also { it[5] = (it[5] + 1).toByte() }
        assertThrows(IllegalStateException::class.java) {
            enc.encryptStream(ByteArrayInputStream(changed), h, sig, ByteArrayOutputStream())
        }
    }

    @Test
    fun prepareRefusesPassphraseAndMixedLabels() {
        assertThrows(IllegalArgumentException::class.java) { SignedEncryption.prepare(listOf(ScryptRecipient("pw", 1))) }
        assertThrows(IllegalArgumentException::class.java) {
            SignedEncryption.prepare(listOf(HybridIdentity.generate().recipient(), X25519Recipient(X25519Identity.generate().publicKey)))
        }
        assertThrows(IllegalArgumentException::class.java) { SignedEncryption.prepare(emptyList()) }
    }

    /** Pins the v2 message layout; docs/SIGNATURE_FORMATS_v2.md quotes this vector for the iOS port. */
    @Test
    fun v2MessageVector() {
        val stanzas = listOf(
            Stanza("X25519", listOf("AAAA"), ByteArray(32) { it.toByte() }),
            Stanza(SignatureStanza.TYPE, listOf("v2"), ByteArray(40)), // skipped
            Stanza("mlkem768x25519", emptyList(), ByteArray(3) { 0x7f }),
        )
        val r = SignatureStanza.recipientsDigest(stanzas)
        val m = SignatureStanza.v2Message(ByteArray(64) { 0x11 }, stanzas)
        assertEquals(4 + 18 + 4 + 64 + 4 + 64 + 4, m.size)
        assertEquals(
            "00000012" + "agepony.com/sig v2".toByteArray().toHex() + "00000040" + "11".repeat(64) + "00000040",
            m.copyOfRange(0, 4 + 18 + 4 + 64 + 4).toHex(),
        )
        assertArrayEquals(r, m.copyOfRange(4 + 18 + 4 + 64 + 4, m.size - 4))
        assertEquals("00000000", m.copyOfRange(m.size - 4, m.size).toHex())
        // R itself, spelled out.
        val expectedR = "00000002" +
            "00000006" + "X25519".toByteArray().toHex() + "00000001" + "00000004" + "AAAA".toByteArray().toHex() +
            "00000020" + ByteArray(32) { it.toByte() }.toHex() +
            "0000000e" + "mlkem768x25519".toByteArray().toHex() + "00000000" + "00000003" + "7f7f7f"
        assertArrayEquals(sha512(hex(expectedR)), r)
        assertEquals(V2_MESSAGE_SHA256, MessageDigest.getInstance("SHA-256").digest(m).toHex())
    }

    // --- L-9: three-way result ---

    @Test
    fun absentWhenThereIsNoSignatureStanza() {
        val stanzas = listOf(Stanza("X25519", listOf("abc"), ByteArray(32)))
        assertTrue(SignatureStanza.openHeader(ByteArray(16), stanzas) === SignatureStanza.Opening.Absent)
    }

    @Test
    fun unreadableCases() {
        val fk = ByteArray(16).also { rng.nextBytes(it) }
        val good = SignatureStanza.buildV2(fk, "sig")
        val x = Stanza("X25519", listOf("abc"), ByteArray(32))
        val cases = mapOf(
            "unknown version" to Stanza(SignatureStanza.TYPE, listOf("v3"), good.body),
            "no version" to Stanza(SignatureStanza.TYPE, emptyList(), good.body),
            "extra v2 argument" to Stanza(SignatureStanza.TYPE, listOf("v2", "x"), good.body),
            "short body" to Stanza(SignatureStanza.TYPE, listOf("v2"), good.body.copyOf(20)),
            "empty body" to Stanza(SignatureStanza.TYPE, listOf("v1"), ByteArray(0)),
            "wrong key" to SignatureStanza.buildV2(ByteArray(16), "sig"),
            "v1 label on v2 body" to Stanza(SignatureStanza.TYPE, listOf("v1"), good.body),
            "tampered" to Stanza(SignatureStanza.TYPE, listOf("v2"), good.body.copyOf().also { it[20] = (it[20] + 1).toByte() }),
        )
        for ((what, stanza) in cases) {
            val o = SignatureStanza.openHeader(fk, listOf(x, stanza))
            assertTrue(o is SignatureStanza.Opening.Unreadable, "$what should be unreadable, got $o")
            assertNull(SignatureStanza.open(fk, stanza), what)
        }
        val two = SignatureStanza.openHeader(fk, listOf(x, good, SignatureStanza.build(fk, "sig")))
        assertTrue(two is SignatureStanza.Opening.Unreadable)
        assertNotNull((two as SignatureStanza.Opening.Unreadable).reason)
        assertTrue(SignatureStanza.openHeader(fk, listOf(x, good)) is SignatureStanza.Opening.Opened)
    }

    @Test
    fun keysForV1AndV2Differ() {
        val fk = ByteArray(16).also { rng.nextBytes(it) }
        val v1 = SignatureStanza.build(fk, "sig")
        // A v1 body relabelled as v2 does not open: each version has its own HKDF label.
        val relabelled = Stanza(SignatureStanza.TYPE, listOf("v2"), v1.body)
        assertTrue(SignatureStanza.openHeader(fk, listOf(relabelled)) is SignatureStanza.Opening.Unreadable)
        assertEquals("sig", SignatureStanza.open(fk, v1))
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private companion object {
        const val V2_MESSAGE_SHA256 = "8c7f506293ca9e956acaa380e6ee07f3d613e56e8b181158dbc98a97ed65524f"
    }
}
