package com.agepony.core.archive

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
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
     * The bundle as something readable, for the encrypt path: `Age.encryptStream` pulls its
     * plaintext from an `InputStream`, so sign-and-encrypt needs the bundle in pull shape rather
     * than the push shape [buildStream] offers. [payload] is read once, when it is reached.
     * Produces exactly the bytes [build] would.
     */
    fun bundleSource(
        originalName: String,
        payloadSize: Long,
        payload: InputStream,
        signatureArmored: String,
    ): InputStream {
        val manifest = "$VERSION_LINE\nname=${sanitizeName(originalName)}\n".toByteArray(Charsets.UTF_8)
        val signature = signatureArmored.toByteArray(Charsets.UTF_8)
        return TarArchive.source(
            listOf(
                TarArchive.StreamEntry(MARKER, manifest.size.toLong()) { ByteArrayInputStream(manifest) },
                TarArchive.StreamEntry(PAYLOAD, payloadSize) { payload },
                TarArchive.StreamEntry(SIGNATURE, signature.size.toLong()) { ByteArrayInputStream(signature) },
            )
        )
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
     * An [OutputStream] that takes decrypted plaintext and writes the payload to [payloadOut].
     *
     * This is the shape the decrypt path needs. `Age.decryptStream` pushes plaintext into an
     * `OutputStream`, and whether that plaintext is a signed bundle is not known until its first
     * block has arrived, so the decision has to be made mid-stream: a bundle has its wrapper
     * stripped as it goes and [result] returns what verification needs, and anything else passes
     * through byte for byte with a null [result].
     *
     * The signature is the last entry, after the payload, so verification can only be reported
     * once the payload has already been written. The caller must show a failed verdict loudly
     * rather than assume a saved file is a verified one.
     *
     * Call [finish] (or [close], which calls it) before [result].
     */
    class UnwrappingSink(private val payloadOut: OutputStream) : OutputStream() {

        private enum class Phase { SNIFF, HEADER, DATA, PAD, TRAILING, PASSTHROUGH }
        private enum class Target { MANIFEST, PAYLOAD, SIGNATURE, SKIP }

        private var phase = Phase.SNIFF
        private val block = ByteArray(TarArchive.BLOCK_SIZE)
        private var blockLen = 0

        private var target = Target.SKIP
        private var dataLeft = 0L
        private var padLeft = 0
        private var payloadSize = -1L
        private val manifest = ByteArrayOutputStream()
        private val signature = ByteArrayOutputStream()
        private val digests = HASH_ALGS.mapValues { (_, jce) -> MessageDigest.getInstance(jce) }
        private var damage: String? = null
        private var finished = false

        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            check(!finished) { "unwrapping sink is already finished" }
            var pos = off
            var left = len
            while (left > 0) {
                when (phase) {
                    Phase.PASSTHROUGH -> {
                        payloadOut.write(b, pos, left)
                        return
                    }
                    Phase.TRAILING -> return // past end-of-archive: nothing left to route
                    Phase.SNIFF, Phase.HEADER -> {
                        val take = minOf(block.size - blockLen, left)
                        System.arraycopy(b, pos, block, blockLen, take)
                        blockLen += take
                        pos += take
                        left -= take
                        if (blockLen == block.size) consumeHeaderBlock()
                    }
                    Phase.DATA -> {
                        val take = minOf(left.toLong(), dataLeft).toInt()
                        route(b, pos, take)
                        pos += take
                        left -= take
                        dataLeft -= take
                        if (dataLeft == 0L) startPadding()
                    }
                    Phase.PAD -> {
                        val take = minOf(left, padLeft)
                        pos += take
                        left -= take
                        padLeft -= take
                        if (padLeft == 0) { phase = Phase.HEADER; blockLen = 0 }
                    }
                }
            }
        }

        override fun flush() = payloadOut.flush()

        /** Settle the final state. Idempotent, and does not close [payloadOut]. */
        fun finish() {
            if (finished) return
            finished = true
            when (phase) {
                // Fewer bytes than one header block ever arrived: it was never a tar.
                Phase.SNIFF -> if (blockLen > 0) {
                    payloadOut.write(block, 0, blockLen)
                    blockLen = 0
                    phase = Phase.PASSTHROUGH
                }
                Phase.HEADER -> if (blockLen > 0) damage = damage ?: "truncated header block"
                Phase.DATA, Phase.PAD -> damage = damage ?: "ended in the middle of an entry"
                else -> {}
            }
        }

        override fun close() = finish()

        /**
         * What the bundle carried, or null if the plaintext was not a signed bundle (in which
         * case every byte written reached [payloadOut] unchanged). Throws [BundleException] if it
         * was a bundle but a damaged one.
         */
        fun result(): StreamParsed? {
            check(finished) { "call finish() before result()" }
            if (phase == Phase.PASSTHROUGH || phase == Phase.SNIFF) return null
            damage?.let { throw BundleException("signed bundle is damaged: $it") }

            val manifestText = String(manifest.toByteArray(), Charsets.UTF_8)
            if (!manifestText.startsWith("agepony-signed/")) {
                throw BundleException("signed bundle has an unreadable manifest")
            }
            if (payloadSize < 0) throw BundleException("signed bundle has no '$PAYLOAD' entry")
            if (signature.size() == 0) throw BundleException("signed bundle has no '$SIGNATURE' entry")

            val name = manifestText.lineSequence()
                .firstOrNull { it.startsWith("name=") }
                ?.removePrefix("name=")
                ?.ifBlank { "file" }
                ?: "file"
            return StreamParsed(
                name,
                String(signature.toByteArray(), Charsets.UTF_8),
                payloadSize,
                digests.mapValues { (_, d) -> d.digest() },
            )
        }

        private fun consumeHeaderBlock() {
            val first = phase == Phase.SNIFF
            val info = try {
                TarArchive.parseHeaderBlock(block)
            } catch (e: TarArchive.TarException) {
                if (first) { becomePassthrough(); return }
                damage = e.message
                phase = Phase.TRAILING
                return
            }
            if (info == null) { // end-of-archive marker
                blockLen = 0
                phase = Phase.TRAILING
                return
            }
            if (first && (info.name != MARKER || info.size > MAX_MANIFEST)) {
                becomePassthrough()
                return
            }
            blockLen = 0
            target = when (info.name) {
                MARKER -> Target.MANIFEST
                PAYLOAD -> { payloadSize = info.size; Target.PAYLOAD }
                SIGNATURE -> Target.SIGNATURE
                else -> Target.SKIP // unknown entries are ignored so the format can grow
            }
            dataLeft = info.size
            padLeft = ((TarArchive.BLOCK_SIZE - info.size % TarArchive.BLOCK_SIZE) % TarArchive.BLOCK_SIZE).toInt()
            if (dataLeft > 0) phase = Phase.DATA else startPadding()
        }

        private fun startPadding() {
            if (padLeft > 0) {
                phase = Phase.PAD
            } else {
                phase = Phase.HEADER
                blockLen = 0
            }
        }

        private fun becomePassthrough() {
            phase = Phase.PASSTHROUGH
            if (blockLen > 0) {
                payloadOut.write(block, 0, blockLen)
                blockLen = 0
            }
        }

        private fun route(b: ByteArray, off: Int, len: Int) {
            when (target) {
                Target.PAYLOAD -> {
                    payloadOut.write(b, off, len)
                    for (d in digests.values) d.update(b, off, len)
                }
                Target.MANIFEST -> if (manifest.size() + len <= MAX_MANIFEST) manifest.write(b, off, len)
                Target.SIGNATURE -> if (signature.size() + len <= MAX_SIGNATURE) signature.write(b, off, len)
                Target.SKIP -> {}
            }
        }
    }

    /**
     * Reset budget for [parseStream]: the marker entry is one header block plus one data block,
     * so a rejection is decided well inside this.
     */
    private const val MARK_LIMIT = 4096
    private const val MAX_MANIFEST = 4096L
    private const val MAX_SIGNATURE = 8192
    private const val COPY_BUFFER = 64 * 1024

    /** A bundle that identified itself with the marker entry but is malformed after it. */
    class BundleException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private class NotABundleException : Exception("not a signed bundle")

    private fun sanitizeName(name: String): String =
        name.replace('\n', '_').replace('\r', '_').trim().ifBlank { "file" }
}
