package com.agepony.app.vault

import com.agepony.core.Age
import com.agepony.core.Armor
import com.agepony.core.crypto.Scrypt
import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.ScryptIdentity
import com.agepony.core.recipients.ScryptRecipient
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream

//
// High-level wrap/unwrap used by the Files flows. Two shapes:
//
//   - ByteArray in/out, for small payloads (notes, pasted text, the share sheet).
//   - Stream in/out, for files: the Compose layer hands over a SAF input stream and a SAF
//     output stream and nothing larger than a 64 KiB chunk is ever held. This is what keeps
//     a 1 GB file from needing 1 GB of heap.
//
// The Compose layer owns the SAF (Storage Access Framework) plumbing either way. Android
// counterpart of iOS's FileEncryptor.
//
// Passphrase mode maps to a single scrypt recipient (work factor 2^18), which the age spec
// requires to be the only recipient — enforced here and again in Age.encrypt.
//

class FileEncryptorException(message: String) : Exception(message)

/** The file is valid age, but no identity in the vault can unwrap it (try a passphrase). */
class NoMatchingVaultIdentityException : Exception("No matching identity in your vault for this file.")

/** Passphrase decrypt failed: wrong passphrase, or the file isn't passphrase-encrypted. */
class WrongPassphraseException : Exception("Wrong passphrase, or this file isn't passphrase-encrypted.")

/**
 * scrypt would need more memory than this device has free. Raised before any work starts, so the
 * user gets an accurate explanation instead of an OutOfMemoryError halfway through a file.
 */
class ScryptMemoryException(val workFactor: Int, val needed: Long, val available: Long) : Exception(
    "Deriving a key at work factor 2^" + workFactor + " needs about " + (needed shr 20) +
        " MB, and only about " + (available shr 20) + " MB is free on this device. Lower the " +
        "passphrase work factor in Settings, or encrypt to a recipient key instead."
)

object FileEncryptor {

    /** age's default scrypt work factor, and what the age CLI uses. N = 2^18, so 256 MiB. */
    const val DEFAULT_SCRYPT_WORK_FACTOR = 18

    /** 2^16 costs 64 MiB, which fits on modest devices. */
    const val MIN_SCRYPT_WORK_FACTOR = 16

    /** 2^20 costs 1 GiB. Above this nothing on a phone can open the file, including this app. */
    const val MAX_SCRYPT_WORK_FACTOR = 20

    /** Room left for everything else while scrypt holds its block. */
    private const val SCRYPT_HEADROOM = 32L * 1024 * 1024

    /** What scrypt will allocate, in one block, at [workFactor]. Independent of file size. */
    fun scryptMemoryBytes(workFactor: Int): Long = Scrypt.memoryBytes(1 shl workFactor, 8)

    /** Free heap right now, as the JVM sees it. */
    fun freeHeapBytes(): Long {
        val runtime = Runtime.getRuntime()
        return runtime.maxMemory() - (runtime.totalMemory() - runtime.freeMemory())
    }

    /** Whether scrypt at [workFactor] should fit in what is left, with headroom to spare. */
    fun scryptFitsInMemory(workFactor: Int): Boolean =
        scryptMemoryBytes(workFactor) + SCRYPT_HEADROOM <= freeHeapBytes()

    /**
     * Encrypt [plaintext] to [recipients] (or, when [passphrase] is non-empty,
     * to a passphrase). Returns binary age bytes, or ASCII-armored text bytes
     * when [armor] is true.
     */
    fun encrypt(
        plaintext: ByteArray,
        recipients: List<AgeRecipient>,
        passphrase: String?,
        armor: Boolean,
        workFactor: Int = DEFAULT_SCRYPT_WORK_FACTOR,
    ): ByteArray {
        val to = recipientsFor(recipients, passphrase, workFactor)

        val ciphertext = try {
            Age.encrypt(plaintext, to)
        } catch (e: Exception) {
            throw FileEncryptorException("Encrypt failed: ${e.message}")
        }

        return if (armor) Armor.encode(ciphertext).toByteArray(Charsets.UTF_8) else ciphertext
    }

    /**
     * Streaming counterpart of [encrypt]: read plaintext from [plaintext] and write age (or
     * armored age) to [out], holding only one chunk at a time. Neither stream is closed.
     *
     * An [OutOfMemoryError] is deliberately not caught here. The passphrase path allocates
     * 128 * 2^workFactor * 8 bytes inside scrypt (256 MiB at the default work factor 18), which
     * has nothing to do with the file's size, so only the caller can say what actually failed.
     */
    fun encryptStream(
        plaintext: InputStream,
        recipients: List<AgeRecipient>,
        passphrase: String?,
        armor: Boolean,
        out: OutputStream,
        workFactor: Int = DEFAULT_SCRYPT_WORK_FACTOR,
    ) {
        val to = recipientsFor(recipients, passphrase, workFactor)
        try {
            if (armor) {
                val sink = Armor.encodingSink(out)
                Age.encryptStream(plaintext, to, sink)
                sink.finish()
            } else {
                Age.encryptStream(plaintext, to, out)
            }
        } catch (e: Exception) {
            throw FileEncryptorException("Encrypt failed: ${e.message}")
        }
    }

    /** Suggested output name for an encrypt: `secrets.txt` -> `secrets.txt.age`. */
    fun encryptedName(inputName: String): String = "$inputName.age"

    // ---- Decrypt ----

    /** True if [raw] is ASCII-armored age (starts with the BEGIN marker). */
    fun isArmored(raw: ByteArray): Boolean {
        val text = try { String(raw, Charsets.UTF_8) } catch (_: Exception) { return false }
        return text.trimStart().startsWith(Armor.BEGIN_MARKER)
    }

    /** Normalize input to binary age bytes, decoding ASCII armor if present. */
    fun toBinary(raw: ByteArray): ByteArray =
        if (isArmored(raw)) {
            try {
                Armor.decode(String(raw, Charsets.UTF_8))
            } catch (e: Exception) {
                throw FileEncryptorException("Couldn't read the armored file: ${e.message}")
            }
        } else {
            raw
        }

    /**
     * Peek at the head of [input] to decide whether it is armored, and hand back a stream that
     * still yields those bytes. Lets the streaming decrypt path make the armor decision without
     * reading the file twice or buffering it.
     */
    fun sniffArmored(input: InputStream): Pair<Boolean, InputStream> {
        val pushback = PushbackInputStream(input, Armor.SNIFF_LEN)
        val head = ByteArray(Armor.SNIFF_LEN)
        var read = 0
        while (read < head.size) {
            val r = pushback.read(head, read, head.size - read)
            if (r < 0) break
            read += r
        }
        if (read > 0) pushback.unread(head, 0, read)
        return Armor.looksArmored(head.copyOfRange(0, read)) to pushback
    }

    /**
     * Try to decrypt [binary] with the given [identities]. Throws
     * [NoMatchingVaultIdentityException] if the file is valid age but no identity
     * matches (the caller should then offer a passphrase).
     */
    fun decryptWithIdentities(binary: ByteArray, identities: List<AgeIdentity>): ByteArray {
        if (identities.isEmpty()) throw NoMatchingVaultIdentityException()
        return try {
            Age.decrypt(binary, identities)
        } catch (e: Age.NoMatchingIdentityException) {
            throw NoMatchingVaultIdentityException()
        } catch (e: Exception) {
            throw FileEncryptorException("Decrypt failed: ${e.message}")
        }
    }

    /** Decrypt [binary] with a passphrase (scrypt). Throws [WrongPassphraseException] on mismatch. */
    fun decryptWithPassphrase(binary: ByteArray, passphrase: String): ByteArray {
        return try {
            Age.decrypt(binary, listOf(ScryptIdentity(passphrase)))
        } catch (e: Age.NoMatchingIdentityException) {
            throw WrongPassphraseException()
        } catch (e: Exception) {
            throw FileEncryptorException("Decrypt failed: ${e.message}")
        }
    }

    /**
     * Streaming counterpart of [decryptWithIdentities]. [armored] comes from [sniffArmored].
     * Neither stream is closed.
     */
    fun decryptStreamWithIdentities(
        ciphertext: InputStream,
        armored: Boolean,
        identities: List<AgeIdentity>,
        out: OutputStream,
    ) {
        if (identities.isEmpty()) throw NoMatchingVaultIdentityException()
        try {
            Age.decryptStream(binarySource(ciphertext, armored), identities, out)
        } catch (e: Age.NoMatchingIdentityException) {
            throw NoMatchingVaultIdentityException()
        } catch (e: Exception) {
            throw FileEncryptorException("Decrypt failed: ${e.message}")
        }
    }

    /** Streaming counterpart of [decryptWithPassphrase]. [armored] comes from [sniffArmored]. */
    fun decryptStreamWithPassphrase(
        ciphertext: InputStream,
        armored: Boolean,
        passphrase: String,
        out: OutputStream,
    ) {
        try {
            Age.decryptStream(binarySource(ciphertext, armored), listOf(ScryptIdentity(passphrase)), out)
        } catch (e: Age.NoMatchingIdentityException) {
            throw WrongPassphraseException()
        } catch (e: Exception) {
            throw FileEncryptorException("Decrypt failed: ${e.message}")
        }
    }

    /**
     * Suggested output name for a decrypt: strip every trailing `.age` (case-insensitive),
     * so `notes.txt.age` — or a doubled `notes.txt.age.age` — becomes `notes.txt`. A decrypted
     * file should never keep a `.age` suffix. If the input had no `.age` at all, append
     * `.decrypted` so we still propose a distinct name.
     */
    fun decryptedName(inputName: String): String {
        var name = inputName
        while (name.length > 4 && name.lowercase().endsWith(".age")) {
            name = name.dropLast(4)
        }
        return if (name == inputName) "$inputName.decrypted" else name
    }

    // ---- Internals ----

    /** Resolve the recipient list, enforcing the age rule that scrypt stands alone. */
    private fun recipientsFor(
        recipients: List<AgeRecipient>,
        passphrase: String?,
        workFactor: Int,
    ): List<AgeRecipient> {
        val usingPassphrase = !passphrase.isNullOrEmpty()
        if (!usingPassphrase && recipients.isEmpty()) {
            throw FileEncryptorException("No recipients selected.")
        }
        if (usingPassphrase && recipients.isNotEmpty()) {
            throw FileEncryptorException(
                "Passphrase mode can't be combined with recipients (age spec)."
            )
        }
        if (!usingPassphrase) return recipients

        val factor = workFactor.coerceIn(MIN_SCRYPT_WORK_FACTOR, MAX_SCRYPT_WORK_FACTOR)
        if (!scryptFitsInMemory(factor)) {
            throw ScryptMemoryException(factor, scryptMemoryBytes(factor), freeHeapBytes())
        }
        return listOf(ScryptRecipient(passphrase!!, factor))
    }

    private fun binarySource(ciphertext: InputStream, armored: Boolean): InputStream =
        if (armored) Armor.decodingSource(ciphertext) else ciphertext
}
