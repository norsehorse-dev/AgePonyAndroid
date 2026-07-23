package com.agepony.core.archive

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

    private fun sanitizeName(name: String): String =
        name.replace('\n', '_').replace('\r', '_').trim().ifBlank { "file" }
}
