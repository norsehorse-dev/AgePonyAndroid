package com.agepony.core.archive

import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigVerifier
import com.agepony.core.ssh.SSHWire
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
 *
 * Versions (audit L-8). Both are read; new bundles should be written as v2 ([buildV2],
 * [buildStreamV2], [bundleSourceV2]):
 *
 *  - v1, manifest `agepony-signed/1\nname=<name>\n`: `payload.sig` is an SSHSIG over the payload
 *    bytes, namespace "agepony". The name is not covered, so anyone who can re-encrypt the bundle
 *    (for a passphrase file, anyone with the passphrase) can rename it without breaking the
 *    signature. [Parsed.nameCovered] is false.
 *
 *  - v2, manifest `agepony-signed/2\nname=<name>\n` (first line exactly `agepony-signed/2`):
 *    `payload.sig` is an SSHSIG under namespace [NAMESPACE_V2] over the message
 *
 *    ```
 *    M = string  "agepony.com/bundle v2"    (MESSAGE_DOMAIN_V2, ASCII, 21 bytes)
 *        string  manifest                    (the exact bytes of the `.agepony-signed` entry)
 *        string  SHA-512(payload)            (64 bytes)
 *    ```
 *
 *    where `string` is SSH wire framing (big-endian uint32 length, then the bytes). The manifest
 *    goes in byte for byte, so the name and any line a later version adds are covered. Rewriting
 *    the first line back to `/1` does not downgrade it: the v1 check uses namespace "agepony",
 *    which a v2 signature does not carry. [Parsed.nameCovered] is true.
 *
 * Mirrored by the iOS app; docs/SIGNATURE_FORMATS_v2.md carries the same layout.
 */
object SignedBundle {
    const val MARKER = ".agepony-signed"
    private const val PAYLOAD = "payload"
    private const val SIGNATURE = "payload.sig"
    private const val VERSION_LINE = "agepony-signed/1"
    private const val VERSION_LINE_V2 = "agepony-signed/2"

    /** SSHSIG namespace of a v2 bundle signature. */
    const val NAMESPACE_V2 = "agepony-bundle-v2"

    /** First field of the v2 signed message. */
    const val MESSAGE_DOMAIN_V2 = "agepony.com/bundle v2"

    /**
     * A parsed bundle. [version] is 1 or 2, and [manifest] is the marker entry's exact bytes
     * (what a v2 signature covers).
     */
    class Parsed(
        val name: String,
        val payload: ByteArray,
        val signatureArmored: String,
        val version: Int = 1,
        val manifest: ByteArray = ByteArray(0),
    ) {
        /** True for v2: [name] is covered by the signature. For v1 the UI should call it unsigned. */
        val nameCovered: Boolean get() = version >= 2

        /** SSHSIG namespace this version signs under. */
        val namespace: String get() = namespaceFor(version)

        /** The exact message the SSHSIG covers. */
        fun signedMessage(): ByteArray =
            if (version >= 2) v2Message(manifest, SSHSig.hashMessage(payload, SSHSig.HASH_SHA512)) else payload

        /** Verify [signatureArmored] under this version's namespace and message. */
        fun verify(allowNoTouch: Boolean = false): SSHSigVerifier.Result =
            SSHSigVerifier.verify(signatureArmored.toByteArray(Charsets.UTF_8), signedMessage(), namespace, allowNoTouch)
    }

    /** The v2 signed message for a bundle whose marker entry holds [manifest]. See the object KDoc. */
    fun v2Message(manifest: ByteArray, payloadSha512: ByteArray): ByteArray {
        require(payloadSha512.size == 64) { "payload hash must be SHA-512 (64 bytes)" }
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, MESSAGE_DOMAIN_V2.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, manifest)
        SSHWire.writeString(out, payloadSha512)
        return out.toByteArray()
    }

    /** The manifest [buildV2] writes for [originalName]. */
    fun manifestV2(originalName: String): ByteArray =
        "$VERSION_LINE_V2\nname=${sanitizeName(originalName)}\n".toByteArray(Charsets.UTF_8)

    /**
     * What to sign for a v2 bundle: SHA-512 of [v2Message] for [originalName] and a payload whose
     * SHA-512 is [payloadSha512]. Hand it to a hashed signer with namespace [NAMESPACE_V2] and hash
     * algorithm sha512, then pass the same [originalName] to [buildV2], [buildStreamV2] or
     * [bundleSourceV2].
     */
    fun v2MessageHash(originalName: String, payloadSha512: ByteArray): ByteArray =
        SSHSig.hashMessage(v2Message(manifestV2(originalName), payloadSha512), SSHSig.HASH_SHA512)

    /** [build] for a v2 bundle; [signatureArmored] must be over [v2MessageHash]'s message. */
    fun buildV2(originalName: String, payload: ByteArray, signatureArmored: String): ByteArray =
        TarArchive.create(
            listOf(
                TarArchive.Entry(MARKER, manifestV2(originalName)),
                TarArchive.Entry(PAYLOAD, payload),
                TarArchive.Entry(SIGNATURE, signatureArmored.toByteArray(Charsets.UTF_8)),
            )
        )

    /** [buildStream] for a v2 bundle. Byte-identical to [buildV2] for the same inputs. */
    fun buildStreamV2(
        out: OutputStream,
        originalName: String,
        payloadSize: Long,
        payload: InputStream,
        signatureArmored: String,
    ) {
        TarArchive.writeEntry(out, MARKER, manifestV2(originalName))
        TarArchive.writeEntry(out, PAYLOAD, payloadSize, payload)
        TarArchive.writeEntry(out, SIGNATURE, signatureArmored.toByteArray(Charsets.UTF_8))
        TarArchive.finish(out)
    }

    /** [bundleSource] for a v2 bundle. Produces exactly the bytes [buildV2] would. */
    fun bundleSourceV2(
        originalName: String,
        payloadSize: Long,
        payload: InputStream,
        signatureArmored: String,
    ): InputStream = sourceOf(manifestV2(originalName), payloadSize, payload, signatureArmored)

    private fun versionOf(manifest: ByteArray): Int {
        val first = String(manifest, Charsets.UTF_8).lineSequence().firstOrNull()
        return if (first == VERSION_LINE_V2) 2 else 1
    }

    private fun namespaceFor(version: Int): String =
        if (version >= 2) NAMESPACE_V2 else SSHSig.NAMESPACE_AGEPONY

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
        val manifestBytes = entries[0].data
        return Parsed(name, payload.data, String(sig.data, Charsets.UTF_8), versionOf(manifestBytes), manifestBytes)
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
        /** 1 or 2; see [SignedBundle]. */
        val version: Int = 1,
        /** The marker entry's exact bytes (what a v2 signature covers). */
        val manifest: ByteArray = ByteArray(0),
    ) {
        /** The payload hash under an SSHSIG hash-algorithm name ("sha512", "sha256"). */
        fun hash(sshsigHashAlg: String): ByteArray =
            hashes[sshsigHashAlg]
                ?: throw IllegalArgumentException("payload was not hashed with '$sshsigHashAlg'")

        /** True for v2: [name] is covered by the signature. */
        val nameCovered: Boolean get() = version >= 2

        /** SSHSIG namespace this version signs under. */
        val namespace: String get() = namespaceFor(version)

        /**
         * H(signed message) under the SSHSIG hash algorithm [alg]: the payload hash for v1, the
         * hash of the v2 message for v2. This is the `messageHashFor` a hashed verifier takes.
         */
        fun messageHash(alg: String): ByteArray =
            if (version >= 2) SSHSig.hashMessage(v2Message(manifest, hash(SSHSig.HASH_SHA512)), alg) else hash(alg)

        /** Verify [signatureArmored] under this version's namespace and message. */
        fun verify(allowNoTouch: Boolean = false): SSHSigVerifier.Result =
            SSHSigVerifier.verifyHashed(
                signatureArmored.toByteArray(Charsets.UTF_8),
                namespace,
                allowNoTouch,
            ) { alg -> messageHash(alg) }
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
        return sourceOf(manifest, payloadSize, payload, signatureArmored)
    }

    private fun sourceOf(
        manifest: ByteArray,
        payloadSize: Long,
        payload: InputStream,
        signatureArmored: String,
    ): InputStream {
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
        return StreamParsed(name, sig, payloadSize, digests.mapValues { (_, d) -> d.digest() }, versionOf(m), m)
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
            val manifestBytes = manifest.toByteArray()
            return StreamParsed(
                name,
                String(signature.toByteArray(), Charsets.UTF_8),
                payloadSize,
                digests.mapValues { (_, d) -> d.digest() },
                versionOf(manifestBytes),
                manifestBytes,
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
