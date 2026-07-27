package com.agepony.core.archive

import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

/**
 * AgePony "signed bundle": a small USTAR archive that carries a payload together with a
 * detached SSHSIG over that payload, so an encrypt-and-sign operation produces a single
 * `.age` file. The whole bundle is age-encrypted (sign-then-encrypt), which keeps the
 * signer's identity hidden inside the ciphertext.
 *
 * Entry order:
 *   `.agepony-signed`  — marker + manifest (`agepony-signed/1\nname=<original>\n`)
 *   `payload`          — the original file bytes (what was signed)
 *   `payload.sig`      — the armored SSHSIG over `payload`
 *
 * [parse] returns null for anything that isn't a signed bundle — plain files (not a tar),
 * and ordinary multi-file bundles (a tar whose first entry isn't the marker) — so the
 * decrypt path can safely probe every decrypted output.
 *
 * [build] / [parse] hold the payload in memory. [buildStream] / [parseStream] are the
 * bounded-memory equivalents for files, and produce and accept exactly the same bytes.
 */
object SignedBundle {
    const val MARKER = ".agepony-signed"
    private const val PAYLOAD = "payload"
    private const val SIGNATURE = "payload.sig"
    private const val VERSION_LINE = "agepony-signed/1"

    class Parsed(val name: String, val payload: ByteArray, val signatureArmored: String)

    /** Build the bundle tar from a payload and its armored SSHSIG. */
    fun build(originalName: String, payload: ByteArray, signatureArmored: String): ByteArray {
        val manifest = "$VERSION_LINE\nname=${sanitizeName(originalName)}\n".toByteArray(Charsets.UTF_8)
        return TarArchive.create(
            listOf(
                TarArchive.Entry(MARKER, manifest),
                TarArchive.Entry(PAYLOAD, payload),
                TarArchive.Entry(SIGNATURE, signatureArmored.toByteArray(Charsets.UTF_8)),
            )
        )
    }

    /** Parse [bytes] as a signed bundle, or return null if it isn't one. */
    fun parse(bytes: ByteArray): Parsed? {
        val entries = try {
            TarArchive.extract(bytes)
        } catch (e: Exception) {
            return null // not a valid tar (or failed checksum) -> not a signed bundle
        }
        if (entries.isEmpty() || entries[0].name != MARKER) return null
        val manifest = String(entries[0].data, Charsets.UTF_8)
        if (!manifest.startsWith("agepony-signed/")) return null
        val payload = entries.firstOrNull { it.name == PAYLOAD } ?: return null
        val sig = entries.firstOrNull { it.name == SIGNATURE } ?: return null
        val name = manifest.lineSequence()
            .firstOrNull { it.startsWith("name=") }
            ?.removePrefix("name=")
            ?.ifBlank { "file" }
            ?: "file"
        return Parsed(name, payload.data, String(sig.data, Charsets.UTF_8))
    }

    // --- Streaming ---

    /** Hash algorithms computed over the payload while it streams past, named as SSHSIG names them. */
    private val HASH_ALGS = mapOf("sha512" to "SHA-512", "sha256" to "SHA-256")

    /**
     * What [parseStream] recovers: the original name, the armored signature, and the payload's
     * hashes. The payload itself went to the caller's output stream, so verification uses
     * [hash] rather than the bytes.
     */
    class StreamParsed(
        val name: String,
        val signatureArmored: String,
        val payloadSize: Long,
        private val hashes: Map<String, ByteArray>,
    ) {
        /** The payload hash under an SSHSIG hash-algorithm name ("sha512", "sha256"). */
        fun hash(sshsigHashAlg: String): ByteArray =
            hashes[sshsigHashAlg]
                ?: throw IllegalArgumentException("payload was not hashed with '$sshsigHashAlg'")
    }

    /**
     * Build the bundle straight into [out], streaming the payload from [payload] rather than
     * buffering it. [payloadSize] must be the payload's exact byte count. Byte-identical to
     * [build] for the same inputs.
     */
    fun buildStream(
        out: OutputStream,
        originalName: String,
        payloadSize: Long,
        payload: InputStream,
        signatureArmored: String,
    ) {
        val manifest = "$VERSION_LINE\nname=${sanitizeName(originalName)}\n".toByteArray(Charsets.UTF_8)
        TarArchive.writeEntry(out, MARKER, manifest)
        TarArchive.writeEntry(out, PAYLOAD, payloadSize, payload)
        TarArchive.writeEntry(out, SIGNATURE, signatureArmored.toByteArray(Charsets.UTF_8))
        TarArchive.finish(out)
    }

    /**
     * Streaming counterpart of [parse]: writes the payload to [payloadOut] as it is read and
     * returns the metadata needed to verify it, or null if [input] isn't a signed bundle.
     *
     * [input] must support mark/reset (wrap it in a `BufferedInputStream`): when the input turns
     * out not to be a signed bundle, the stream is reset to where it started and nothing is
     * written to [payloadOut], so the caller can fall back to treating it as an ordinary file.
     */
    fun parseStream(input: InputStream, payloadOut: OutputStream): StreamParsed? {
        require(input.markSupported()) { "parseStream needs a mark-supporting stream (use BufferedInputStream)" }
        input.mark(MARK_LIMIT)

        var manifest: ByteArray? = null
        var signature: String? = null
        var payloadSize = -1L
        var committed = false // past the marker entry: this is a bundle, so errors are errors
        val digests = HASH_ALGS.mapValues { (_, jce) -> MessageDigest.getInstance(jce) }

        try {
            TarArchive.forEachEntry(input) { name, size, data ->
                if (manifest == null) {
                    if (name != MARKER || size > MAX_MANIFEST) throw NotABundleException()
                    val m = data.readBytes()
                    if (!String(m, Charsets.UTF_8).startsWith("agepony-signed/")) throw NotABundleException()
                    manifest = m
                    committed = true
                } else when (name) {
                    PAYLOAD -> {
                        payloadSize = size
                        val buf = ByteArray(COPY_BUFFER)
                        while (true) {
                            val r = data.read(buf)
                            if (r < 0) break
                            payloadOut.write(buf, 0, r)
                            for (d in digests.values) d.update(buf, 0, r)
                        }
                    }
                    SIGNATURE -> signature = String(data.readBytes(), Charsets.UTF_8)
                    else -> { /* ignore unknown entries so the format can grow */ }
                }
            }
        } catch (e: NotABundleException) {
            input.reset()
            return null
        } catch (e: TarArchive.TarException) {
            if (committed) throw BundleException("signed bundle is damaged: ${e.message}", e)
            input.reset()
            return null // not a valid tar -> not a signed bundle
        }

        val m = manifest ?: run { input.reset(); return null }
        val sig = signature ?: throw BundleException("signed bundle has no '$SIGNATURE' entry")
        if (payloadSize < 0) throw BundleException("signed bundle has no '$PAYLOAD' entry")

        val name = String(m, Charsets.UTF_8).lineSequence()
            .firstOrNull { it.startsWith("name=") }
            ?.removePrefix("name=")
            ?.ifBlank { "file" }
            ?: "file"
        return StreamParsed(name, sig, payloadSize, digests.mapValues { (_, d) -> d.digest() })
    }

    /**
     * Reset budget for [parseStream]: the marker entry is one header block plus one data block,
     * so a rejection is decided well inside this.
     */
    private const val MARK_LIMIT = 4096
    private const val MAX_MANIFEST = 4096L
    private const val COPY_BUFFER = 64 * 1024

    /** A bundle that identified itself with the marker entry but is malformed after it. */
    class BundleException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private class NotABundleException : Exception("not a signed bundle")

    private fun sanitizeName(name: String): String =
        name.replace('\n', '_').replace('\r', '_').trim().ifBlank { "file" }
}
