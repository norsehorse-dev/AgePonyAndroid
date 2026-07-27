package com.agepony.core.archive

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Random

/**
 * The streaming bundle pair has to interoperate with the whole-buffer pair in both directions,
 * and must not claim ordinary files as signed bundles: the decrypt path probes every output.
 */
class SignedBundleStreamTests {

    private val payload = ByteArray(200_000).also { Random(7).nextBytes(it) }
    private val signature =
        "-----BEGIN SSH SIGNATURE-----\nZmFrZSBzaWduYXR1cmU=\n-----END SSH SIGNATURE-----\n"

    private fun streamedBundle(name: String = "report.pdf"): ByteArray {
        val out = ByteArrayOutputStream()
        SignedBundle.buildStream(out, name, payload.size.toLong(), ByteArrayInputStream(payload), signature)
        return out.toByteArray()
    }

    @Test
    fun buildStream_matchesBuild() {
        assertArrayEquals(SignedBundle.build("report.pdf", payload, signature), streamedBundle())
    }

    @Test
    fun parseStream_recoversNameSignatureAndHashes() {
        val out = ByteArrayOutputStream()
        val parsed = SignedBundle.parseStream(
            BufferedInputStream(ByteArrayInputStream(SignedBundle.build("report.pdf", payload, signature))),
            out,
        )
        assertNotNull(parsed)
        parsed!!
        assertEquals("report.pdf", parsed.name)
        assertEquals(signature, parsed.signatureArmored)
        assertEquals(payload.size.toLong(), parsed.payloadSize)
        assertArrayEquals(payload, out.toByteArray())
        assertArrayEquals(MessageDigest.getInstance("SHA-512").digest(payload), parsed.hash("sha512"))
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(payload), parsed.hash("sha256"))
    }

    @Test
    fun wholeBufferParse_readsAStreamedBundle() {
        val parsed = SignedBundle.parse(streamedBundle())
        assertNotNull(parsed)
        parsed!!
        assertEquals("report.pdf", parsed.name)
        assertArrayEquals(payload, parsed.payload)
        assertEquals(signature, parsed.signatureArmored)
    }

    @Test
    fun parseStream_returnsNullAndRewindsForNonBundles() {
        val plainTar = TarArchive.create(listOf(TarArchive.Entry("a.txt", "hello".toByteArray())))
        val tarSource = BufferedInputStream(ByteArrayInputStream(plainTar))
        val sink = ByteArrayOutputStream()
        assertNull(SignedBundle.parseStream(tarSource, sink))
        assertEquals(0, sink.size(), "a rejected input must not write payload bytes")
        assertArrayEquals(plainTar, tarSource.readBytes(), "the stream must be rewound for the caller")

        val junk = ByteArray(4096).also { Random(9).nextBytes(it) }
        val junkSource = BufferedInputStream(ByteArrayInputStream(junk))
        assertNull(SignedBundle.parseStream(junkSource, ByteArrayOutputStream()))
        assertArrayEquals(junk, junkSource.readBytes())

        val empty = BufferedInputStream(ByteArrayInputStream(ByteArray(0)))
        assertNull(SignedBundle.parseStream(empty, ByteArrayOutputStream()))
    }

    @Test
    fun parseStream_reportsDamageOnceTheMarkerMatched() {
        val noSignature = ByteArrayOutputStream()
        TarArchive.writeEntry(noSignature, SignedBundle.MARKER, "agepony-signed/1\nname=x\n".toByteArray())
        TarArchive.writeEntry(noSignature, "payload", ByteArray(50))
        TarArchive.finish(noSignature)

        assertThrows(SignedBundle.BundleException::class.java) {
            SignedBundle.parseStream(
                BufferedInputStream(ByteArrayInputStream(noSignature.toByteArray())),
                ByteArrayOutputStream(),
            )
        }
    }
}
