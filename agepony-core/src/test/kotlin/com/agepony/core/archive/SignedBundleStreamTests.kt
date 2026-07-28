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

    @Test
    fun bundleSource_matchesBuild() {
        val source = SignedBundle.bundleSource(
            "report.pdf",
            payload.size.toLong(),
            ByteArrayInputStream(payload),
            signature,
        )
        assertArrayEquals(SignedBundle.build("report.pdf", payload, signature), source.readBytes())
    }

    @Test
    fun bundleSource_roundTripsThroughParseStream() {
        val bundle = SignedBundle.bundleSource(
            "a b.txt",
            payload.size.toLong(),
            ByteArrayInputStream(payload),
            signature,
        ).readBytes()
        val out = ByteArrayOutputStream()
        val parsed = SignedBundle.parseStream(BufferedInputStream(ByteArrayInputStream(bundle)), out)
        assertNotNull(parsed)
        assertEquals("a b.txt", parsed!!.name)
        assertArrayEquals(payload, out.toByteArray())
    }


    /** Write [data] into a fresh sink in [chunk]-sized pieces, the way a decrypt stream would. */
    private fun unwrap(data: ByteArray, chunk: Int): Pair<ByteArray, SignedBundle.StreamParsed?> {
        val out = ByteArrayOutputStream()
        val sink = SignedBundle.UnwrappingSink(out)
        var i = 0
        while (i < data.size) {
            val take = minOf(chunk, data.size - i)
            sink.write(data, i, take)
            i += take
        }
        sink.finish()
        return out.toByteArray() to sink.result()
    }

    @Test
    fun unwrappingSink_stripsTheWrapperAtEveryWriteBoundary() {
        val bundle = SignedBundle.build("report.pdf", payload, signature)
        for (chunk in listOf(1, 3, 511, 512, 513, 4096, 65536, bundle.size)) {
            val (out, parsed) = unwrap(bundle, chunk)
            assertNotNull(parsed, "not recognized as a bundle with $chunk-byte writes")
            assertEquals("report.pdf", parsed!!.name)
            assertEquals(signature, parsed.signatureArmored)
            assertEquals(payload.size.toLong(), parsed.payloadSize)
            assertArrayEquals(payload, out, "payload differs with $chunk-byte writes")
            assertArrayEquals(MessageDigest.getInstance("SHA-512").digest(payload), parsed.hash("sha512"))
        }
    }

    @Test
    fun unwrappingSink_passesNonBundlesThroughUntouched() {
        // A multi-file bundle: a plain tar whose first entry is a user file, not the marker.
        val plainTar = TarArchive.create(
            listOf(
                TarArchive.Entry("a.txt", "A".toByteArray()),
                TarArchive.Entry("b.bin", ByteArray(700) { it.toByte() }),
            )
        )
        for (chunk in listOf(1, 512, 4096)) {
            val (out, parsed) = unwrap(plainTar, chunk)
            assertNull(parsed)
            assertArrayEquals(plainTar, out)
        }

        val notATar = ByteArray(5000).also { Random(3).nextBytes(it) }
        val (junkOut, junkParsed) = unwrap(notATar, 777)
        assertNull(junkParsed)
        assertArrayEquals(notATar, junkOut)

        // Shorter than a single header block: never enough to be a tar.
        val tiny = "hello".toByteArray()
        val (tinyOut, tinyParsed) = unwrap(tiny, 2)
        assertNull(tinyParsed)
        assertArrayEquals(tiny, tinyOut)

        val (emptyOut, emptyParsed) = unwrap(ByteArray(0), 16)
        assertNull(emptyParsed)
        assertEquals(0, emptyOut.size)
    }

    @Test
    fun unwrappingSink_reportsATruncatedBundle() {
        val bundle = SignedBundle.build("report.pdf", payload, signature)
        val truncated = bundle.copyOfRange(0, bundle.size - 3000)
        val out = ByteArrayOutputStream()
        val sink = SignedBundle.UnwrappingSink(out)
        sink.write(truncated)
        sink.finish()
        assertThrows(SignedBundle.BundleException::class.java) { sink.result() }
    }

    @Test
    fun unwrappingSink_agreesWithParseStream() {
        val bundle = SignedBundle.build("a b.txt", payload, signature)
        val pushOut = ByteArrayOutputStream()
        val sink = SignedBundle.UnwrappingSink(pushOut)
        sink.write(bundle)
        sink.finish()
        val push = sink.result()

        val pullOut = ByteArrayOutputStream()
        val pull = SignedBundle.parseStream(BufferedInputStream(ByteArrayInputStream(bundle)), pullOut)

        assertNotNull(push)
        assertNotNull(pull)
        assertEquals(pull!!.name, push!!.name)
        assertEquals(pull.signatureArmored, push.signatureArmored)
        assertEquals(pull.payloadSize, push.payloadSize)
        assertArrayEquals(pullOut.toByteArray(), pushOut.toByteArray())
        assertArrayEquals(pull.hash("sha512"), push.hash("sha512"))
    }
}
