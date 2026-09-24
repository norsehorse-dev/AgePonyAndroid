package com.agepony.core.portability

import com.agepony.core.Age
import com.agepony.core.Armor
import com.agepony.core.recipients.ScryptIdentity
import com.agepony.core.recipients.ScryptRecipient

/**
 * Paper backups of age identities (AgePony 5.0.0).
 *
 * The default protects the page with a passphrase: the identity file is encrypted with an age
 * scrypt recipient and armored, so the QR code and the printed text are an ordinary age file.
 * Restoring needs AgePony or plain `age -d`, so the paper outlives the app.
 *
 * The plain form is the bare identity file. Whoever reads that page holds the key.
 */
object PaperBackup {
    /** age's own default work factor; about 256 MB and a second or so to restore on a phone. */
    const val DEFAULT_WORK_FACTOR = 18

    class PaperBackupException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** Passphrase-protected, armored age text of [identityFile]. */
    fun seal(identityFile: String, passphrase: String, workFactor: Int = DEFAULT_WORK_FACTOR): String {
        require(passphrase.isNotEmpty()) { "passphrase must not be empty" }
        val ct = Age.encrypt(identityFile.toByteArray(Charsets.UTF_8), listOf(ScryptRecipient(passphrase, workFactor)))
        return Armor.encode(ct)
    }

    /** True if [scanned] is a passphrase-protected page rather than a plain identity file. */
    fun isSealed(scanned: String): Boolean = scanned.contains("-----BEGIN AGE ENCRYPTED FILE-----")

    /** Recover the identity file text from a sealed page. */
    fun open(armored: String, passphrase: String): String {
        val start = armored.indexOf("-----BEGIN AGE ENCRYPTED FILE-----")
        if (start < 0) throw PaperBackupException("This isn't a passphrase-protected AgePony backup.")
        val binary = try {
            Armor.decode(armored.substring(start))
        } catch (e: Exception) {
            throw PaperBackupException("The backup text is damaged or incomplete.", e)
        }
        val plain = try {
            Age.decrypt(binary, listOf(ScryptIdentity(passphrase)))
        } catch (e: Age.NoMatchingIdentityException) {
            throw PaperBackupException("Wrong passphrase.", e)
        }
        return String(plain, Charsets.UTF_8)
    }

    /**
     * Secret-key lines in an identity file, in order. Accepts age identity files with comments,
     * or a bare pasted key.
     */
    fun secretKeys(identityFile: String): List<String> =
        identityFile.lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("AGE-SECRET-KEY-", ignoreCase = true) }
            .map { it.uppercase() }
            .toList()

    /** The `# name:` comment preceding each secret key, when the file carries one. */
    fun namesByKey(identityFile: String): Map<String, String> {
        val out = HashMap<String, String>()
        var pendingName: String? = null
        for (raw in identityFile.lineSequence()) {
            val line = raw.trim()
            when {
                line.startsWith("# name:") -> pendingName = line.removePrefix("# name:").trim()
                line.startsWith("AGE-SECRET-KEY-", ignoreCase = true) -> {
                    pendingName?.let { out[line.uppercase()] = it }
                    pendingName = null
                }
            }
        }
        return out
    }

    /** Split [text] into groups for hand transcription: 4-char groups, [perLine] groups per line. */
    fun transcriptionGroups(text: String, perLine: Int = 6): List<String> =
        text.chunked(4).chunked(perLine).map { it.joinToString(" ") }
}
