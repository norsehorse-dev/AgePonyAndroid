package com.agepony.app.vault

import com.agepony.core.Age
import com.agepony.core.Armor
import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.ScryptIdentity
import com.agepony.core.recipients.ScryptRecipient

//
// High-level wrap/unwrap used by the Files flows. Pure ByteArray in/out — the
// Compose layer owns the SAF (Storage Access Framework) plumbing for reading
// the input and writing the output. Android counterpart of iOS's FileEncryptor.
//
// Passphrase mode maps to a single scrypt recipient (work factor 2^18), which
// the age spec requires to be the only recipient — enforced here and again in
// Age.encrypt.
//

class FileEncryptorException(message: String) : Exception(message)

/** The file is valid age, but no identity in the vault can unwrap it (try a passphrase). */
class NoMatchingVaultIdentityException : Exception("No matching identity in your vault for this file.")

/** Passphrase decrypt failed: wrong passphrase, or the file isn't passphrase-encrypted. */
class WrongPassphraseException : Exception("Wrong passphrase, or this file isn't passphrase-encrypted.")

object FileEncryptor {

    private const val SCRYPT_WORK_FACTOR = 18

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
    ): ByteArray {
        val usingPassphrase = !passphrase.isNullOrEmpty()
        if (!usingPassphrase && recipients.isEmpty()) {
            throw FileEncryptorException("No recipients selected.")
        }
        if (usingPassphrase && recipients.isNotEmpty()) {
            throw FileEncryptorException(
                "Passphrase mode can't be combined with recipients (age spec)."
            )
        }

        val ciphertext = try {
            if (usingPassphrase) {
                Age.encrypt(plaintext, listOf(ScryptRecipient(passphrase!!, SCRYPT_WORK_FACTOR)))
            } else {
                Age.encrypt(plaintext, recipients)
            }
        } catch (e: Exception) {
            throw FileEncryptorException("Encrypt failed: ${e.message}")
        }

        return if (armor) Armor.encode(ciphertext).toByteArray(Charsets.UTF_8) else ciphertext
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

    /** Suggested output name for a decrypt: strip a trailing `.age`, else append `.decrypted`. */
    fun decryptedName(inputName: String): String =
        if (inputName.length > 4 && inputName.lowercase().endsWith(".age")) {
            inputName.dropLast(4)
        } else {
            "$inputName.decrypted"
        }
}
