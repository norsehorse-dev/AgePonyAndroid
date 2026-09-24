package com.agepony.core.archive

import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Random

/** v2 bundles sign the manifest (so the name) plus the payload hash; v1 keeps working (audit L-8). */
class SignedBundleV2Tests {
    private val seed = ByteArray(32).also { Random(3).nextBytes(it) }
    private val pub = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    private val payload = ByteArray(150_000).also { Random(9).nextBytes(it) }

    private fun sha512(b: ByteArray) = SSHSig.hashMessage(b, SSHSig.HASH_SHA512)

    private fun signV2(name: String, data: ByteArray = payload) =
        SSHSigner.signEd25519Hashed(seed, pub, SignedBundle.v2MessageHash(name, sha512(data)), SignedBundle.NAMESPACE_V2)

    private fun tar(manifest: String, data: ByteArray, sig: String) = TarArchive.create(
        listOf(
            TarArchive.Entry(SignedBundle.MARKER, manifest.toByteArray()),
            TarArchive.Entry("payload", data),
            TarArchive.Entry("payload.sig", sig.toByteArray()),
        )
    )

    @Test
    fun v1StillParsesAndVerifies() {
        val sig = SSHSigner.signEd25519(seed, pub, payload)
        val p = SignedBundle.parse(SignedBundle.build("old.txt", payload, sig))!!
        assertEquals(1, p.version)
        assertFalse(p.nameCovered)
        assertEquals(SSHSig.NAMESPACE_AGEPONY, p.namespace)
        assertTrue(p.verify().valid)
        val sink = SignedBundle.UnwrappingSink(ByteArrayOutputStream())
        sink.write(SignedBundle.build("old.txt", payload, sig))
        sink.finish()
        val s = sink.result()!!
        assertEquals(1, s.version)
        assertTrue(s.verify().valid)
    }

    @Test
    fun v2RoundTrip() {
        val sig = signV2("report.pdf")
        val bytes = SignedBundle.buildV2("report.pdf", payload, sig)
        val p = SignedBundle.parse(bytes)!!
        assertEquals(2, p.version)
        assertTrue(p.nameCovered)
        assertEquals("report.pdf", p.name)
        assertEquals(SignedBundle.NAMESPACE_V2, p.namespace)
        assertArrayEquals("agepony-signed/2\nname=report.pdf\n".toByteArray(), p.manifest)
        assertTrue(p.verify().valid, p.verify().reason)
    }

    @Test
    fun v2StreamingFormsAgree() {
        val sig = signV2("report.pdf")
        val built = SignedBundle.buildV2("report.pdf", payload, sig)
        val streamed = ByteArrayOutputStream().also {
            SignedBundle.buildStreamV2(it, "report.pdf", payload.size.toLong(), ByteArrayInputStream(payload), sig)
        }.toByteArray()
        assertArrayEquals(built, streamed)
        assertArrayEquals(built, SignedBundle.bundleSourceV2("report.pdf", payload.size.toLong(), ByteArrayInputStream(payload), sig).readBytes())

        val out = ByteArrayOutputStream()
        val sp = SignedBundle.parseStream(BufferedInputStream(ByteArrayInputStream(built)), out)!!
        assertArrayEquals(payload, out.toByteArray())
        assertEquals(2, sp.version)
        assertTrue(sp.nameCovered)
        assertTrue(sp.verify().valid)

        val sinkOut = ByteArrayOutputStream()
        val sink = SignedBundle.UnwrappingSink(sinkOut)
        built.toList().chunked(777).forEach { sink.write(it.toByteArray()) }
        sink.finish()
        val r = sink.result()!!
        assertArrayEquals(payload, sinkOut.toByteArray())
        assertEquals(2, r.version)
        assertTrue(r.verify().valid)
        assertEquals(SignedBundle.NAMESPACE_V2, r.namespace)
    }

    @Test
    fun v2FailsWhenTheNameChanges() {
        val sig = signV2("report.pdf")
        val renamed = SignedBundle.parse(tar("agepony-signed/2\nname=invoice.exe\n", payload, sig))!!
        assertEquals("invoice.exe", renamed.name)
        assertFalse(renamed.verify().valid)
        val sp = SignedBundle.parseStream(
            BufferedInputStream(ByteArrayInputStream(tar("agepony-signed/2\nname=invoice.exe\n", payload, sig))),
            ByteArrayOutputStream(),
        )!!
        assertFalse(sp.verify().valid)
    }

    @Test
    fun v2FailsWhenAManifestLineIsAdded() {
        val sig = signV2("report.pdf")
        assertFalse(SignedBundle.parse(tar("agepony-signed/2\nname=report.pdf\nx=1\n", payload, sig))!!.verify().valid)
    }

    @Test
    fun v2FailsWhenThePayloadChanges() {
        val sig = signV2("report.pdf")
        val other = payload.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(SignedBundle.parse(SignedBundle.buildV2("report.pdf", other, sig))!!.verify().valid)
    }

    @Test
    fun v2CannotBeDowngradedToV1() {
        val sig = signV2("report.pdf")
        val p = SignedBundle.parse(tar("agepony-signed/1\nname=renamed.txt\n", payload, sig))!!
        assertEquals(1, p.version)
        val r = p.verify()
        assertFalse(r.valid)
        assertTrue(r.reason!!.contains("namespace"))
    }

    @Test
    fun v2RejectsAPlainAgePonySignature() {
        // Namespace mismatch: a detached "agepony" signature over the payload is not a v2 bundle signature.
        val p = SignedBundle.parse(SignedBundle.buildV2("report.pdf", payload, SSHSigner.signEd25519(seed, pub, payload)))!!
        assertFalse(p.verify().valid)
    }

    @Test
    fun v2MessageLayout() {
        val manifest = SignedBundle.manifestV2("a\nb.txt")
        assertArrayEquals("agepony-signed/2\nname=a_b.txt\n".toByteArray(), manifest)
        val h = ByteArray(64) { 0x22 }
        val m = SignedBundle.v2Message(manifest, h)
        val expected = ByteArrayOutputStream().apply {
            fun str(b: ByteArray) { write(byteArrayOf(0, 0, (b.size shr 8).toByte(), b.size.toByte())); write(b) }
            str("agepony.com/bundle v2".toByteArray())
            str(manifest)
            str(h)
        }.toByteArray()
        assertArrayEquals(expected, m)
        assertArrayEquals(MessageDigest.getInstance("SHA-512").digest(m), SignedBundle.v2MessageHash("a\nb.txt", h))
        assertNotNull(SignedBundle.parse(SignedBundle.buildV2("x", payload, "sig")))
        // Pinned vector, quoted in docs/SIGNATURE_FORMATS_v2.md for the iOS port.
        val vector = SignedBundle.v2Message(SignedBundle.manifestV2("report.pdf"), h)
        assertEquals(
            "f1e944ee38ee10dac9cbf6601f0dd110e826244d8dc01aa0662104433386d0b7",
            MessageDigest.getInstance("SHA-256").digest(vector).joinToString("") { "%02x".format(it) },
        )
    }
}
