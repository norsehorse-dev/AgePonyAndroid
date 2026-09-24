package com.agepony.core.portability

import com.agepony.core.Age
import com.agepony.core.Armor
import com.agepony.core.archive.TarArchive
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.HybridRecipient
import com.agepony.core.recipients.X25519Recipient
import java.security.MessageDigest

/**
 * Moving identities between devices (AgePony 5.0.0, format `agepony.com/transfer v1`).
 *
 * The receiving device makes a one-time post-quantum identity and shows its recipient. The
 * sending device encrypts a small tar to that recipient. The result is an ordinary age file, so
 * the transfer never depends on AgePony being at both ends:
 *
 *   identities.txt   a standard age identity file (`AGE-SECRET-KEY-1...`, `AGE-SECRET-KEY-PQ-1...`
 *                    with `# created` / `# public key` comments). `age -d` on the transfer file,
 *                    then `tar x`, gives a file that works with `age -i` as it is.
 *   ssh/<name>       OpenSSH private keys, when any were sent.
 *   agepony.json     AgePony's own metadata (names, types, recipients, trusted signers). The core
 *                    treats it as opaque bytes; the app owns its schema.
 *   FORMAT           the literal `agepony.com/transfer v1`.
 *
 * Nothing here decides what may be sent. Keys bound to one device's secure hardware cannot be
 * exported at all, and the app filters them out before packing.
 */
object KeyTransfer {
    const val FORMAT_LINE = "agepony.com/transfer v1"

    private const val FORMAT_FILE = "FORMAT"
    private const val IDENTITIES_FILE = "identities.txt"
    private const val METADATA_FILE = "agepony.json"
    private const val SSH_DIR = "ssh/"
    private const val MAX_ENTRIES = 512

    class TransferException(message: String, cause: Throwable? = null) : Exception(message, cause)

    class Bundle(
        /** Contents of identities.txt (may be empty if only SSH keys were sent). */
        val identitiesTxt: String,
        /** OpenSSH private keys, file name to PEM text. */
        val sshKeys: Map<String, String>,
        /** App metadata JSON, opaque to the core. */
        val metadataJson: String,
    )

    /** One entry of an age identity file. */
    class IdentityLine(val name: String?, val publicKey: String, val secretKey: String, val createdIso: String?)

    /**
     * Render entries as a standard age identity file. [includePublicKey] off leaves out the
     * `# public key:` comment, which for a post-quantum key is ~2000 characters: too much for a
     * paper backup's QR code, and derivable from the secret key anyway.
     */
    fun identityFile(lines: List<IdentityLine>, includePublicKey: Boolean = true): String = buildString {
        for (l in lines) {
            l.name?.takeIf { it.isNotBlank() }?.let { append("# name: ").append(oneLine(it)).append('\n') }
            l.createdIso?.let { append("# created: ").append(it).append('\n') }
            if (includePublicKey) append("# public key: ").append(l.publicKey).append('\n')
            append(l.secretKey).append("\n\n")
        }
    }

    fun pack(bundle: Bundle): ByteArray {
        val entries = ArrayList<TarArchive.Entry>()
        entries += TarArchive.Entry(FORMAT_FILE, (FORMAT_LINE + "\n").toByteArray(Charsets.UTF_8))
        entries += TarArchive.Entry(IDENTITIES_FILE, bundle.identitiesTxt.toByteArray(Charsets.UTF_8))
        val used = HashSet<String>()
        for ((name, pem) in bundle.sshKeys) {
            val base = safeName(name)
            var unique = base
            var n = 2
            while (!used.add(unique)) unique = "$base-${n++}"
            entries += TarArchive.Entry(SSH_DIR + unique, pem.toByteArray(Charsets.UTF_8))
        }
        entries += TarArchive.Entry(METADATA_FILE, bundle.metadataJson.toByteArray(Charsets.UTF_8))
        return TarArchive.create(entries)
    }

    fun unpack(tar: ByteArray): Bundle {
        val entries = try {
            TarArchive.extract(tar)
        } catch (e: Exception) {
            throw TransferException("This isn't an AgePony key transfer (not a valid archive).", e)
        }
        if (entries.size > MAX_ENTRIES) throw TransferException("Transfer has too many entries.")
        val byName = entries.associateBy { it.name }
        val format = byName[FORMAT_FILE]?.data?.toString(Charsets.UTF_8)?.trim()
            ?: throw TransferException("This isn't an AgePony key transfer (no FORMAT entry).")
        if (format != FORMAT_LINE) throw TransferException("Unsupported transfer format: $format")
        val ssh = entries.filter { it.name.startsWith(SSH_DIR) && it.name.length > SSH_DIR.length }
            .associate { it.name.removePrefix(SSH_DIR) to it.data.toString(Charsets.UTF_8) }
        return Bundle(
            identitiesTxt = byName[IDENTITIES_FILE]?.data?.toString(Charsets.UTF_8).orEmpty(),
            sshKeys = ssh,
            metadataJson = byName[METADATA_FILE]?.data?.toString(Charsets.UTF_8).orEmpty(),
        )
    }

    /** Encrypt [bundle] to the receiving device's one-time recipient. Binary age output. */
    fun seal(bundle: Bundle, to: AgeRecipient): ByteArray = Age.encrypt(pack(bundle), listOf(to))

    /** Decrypt a transfer (binary or armored) with the receiving device's one-time identity. */
    fun open(ciphertext: ByteArray, with: HybridIdentity): Bundle {
        val binary = if (looksArmored(ciphertext)) Armor.decode(String(ciphertext, Charsets.UTF_8)) else ciphertext
        val tar = try {
            Age.decrypt(binary, listOf(with))
        } catch (e: Age.NoMatchingIdentityException) {
            throw TransferException("This transfer was made for a different receive session.", e)
        }
        return unpack(tar)
    }

    /** Parse a transfer recipient as shown by the receiver: `age1pq1...` preferred, `age1...` accepted. */
    fun parseRecipient(s: String): AgeRecipient {
        // QR codes carry the recipient upper-cased (QR alphanumeric mode is far denser), and
        // Bech32 accepts either case, so normalise before routing on the prefix.
        val t = s.trim().lowercase()
        return when {
            t.startsWith("age1pq1") -> HybridRecipient(t)
            t.startsWith("age1") -> X25519Recipient(t)
            else -> throw TransferException("That isn't an age recipient.")
        }
    }

    /**
     * Short code both screens show so the user can confirm the sender scanned the right
     * receiver: 60 bits of SHA-256 over the recipient string, Crockford base32, `XXXX-XXXX-XXXX`.
     */
    fun confirmationCode(recipient: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(recipient.trim().lowercase().toByteArray(Charsets.US_ASCII))
        return code60(digest)
    }

    /**
     * The first 60 bits of [digest] as 12 Crockford base32 characters, `XXXX-XXXX-XXXX`. Shared by
     * [confirmationCode] and [TransferCode] so both codes look alike on screen.
     */
    internal fun code60(digest: ByteArray): String {
        val alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        var acc = 0L
        for (i in 0 until 8) acc = (acc shl 8) or (digest[i].toLong() and 0xff)
        val chars = CharArray(12) { i -> alphabet[((acc ushr (64 - 5 * (i + 1))) and 31).toInt()] }
        return String(chars).chunked(4).joinToString("-")
    }

    internal fun looksArmored(b: ByteArray): Boolean =
        String(b, 0, minOf(b.size, 64), Charsets.ISO_8859_1).trimStart().startsWith("-----BEGIN AGE ENCRYPTED FILE-----")

    private fun safeName(name: String): String {
        val cleaned = name.replace(Regex("[^A-Za-z0-9._-]"), "_").trim('.', '_').take(60)
        return cleaned.ifEmpty { "key" }
    }

    private fun oneLine(s: String): String = s.replace('\n', ' ').replace('\r', ' ').trim()
}
