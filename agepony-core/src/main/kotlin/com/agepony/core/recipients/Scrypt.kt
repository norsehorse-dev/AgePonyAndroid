package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.Scrypt
import java.security.SecureRandom

private const val SCRYPT_STANZA_TYPE = "scrypt"
private const val SCRYPT_LABEL = "age-encryption.org/v1/scrypt"
private const val SCRYPT_SALT_LEN = 16
private val ZERO_NONCE_12 = ByteArray(12)

/**
 * Passphrase recipient via scrypt.
 *
 * Wrap: random 16-byte salt; wrapKey = scrypt(passphrase, LABEL||salt, N=2^workfactor, r=8, p=1, L=32);
 *   body = ChaCha20Poly1305(wrapKey, 0-nonce, fileKey).
 *
 * Stanza: type="scrypt", args=[base64NoPad(salt), workfactor].
 *
 * Per the age spec, when a scrypt recipient is present it MUST be the only recipient
 * in the file. This class doesn't enforce that constraint at wrap time (one stanza
 * is produced per recipient); callers should not mix `ScryptRecipient` with other types.
 */
class ScryptRecipient(
    val passphrase: String,
    val workFactor: Int = 18,
) : AgeRecipient {
    init {
        require(workFactor in 1..30) { "workFactor must be 1..30, got $workFactor" }
    }

    override fun wrap(fileKey: ByteArray): Stanza {
        val salt = ByteArray(SCRYPT_SALT_LEN).also { SecureRandom().nextBytes(it) }
        val fullSalt = SCRYPT_LABEL.toByteArray() + salt
        val n = 1 shl workFactor
        val wrapKey = Scrypt.derive(passphrase.toByteArray(Charsets.UTF_8), fullSalt, n, 8, 1, 32)
        val body = ChaChaPoly.encrypt(wrapKey, ZERO_NONCE_12, fileKey)
        return Stanza(
            SCRYPT_STANZA_TYPE,
            listOf(Stanza.base64NoPad(salt), workFactor.toString()),
            body
        )
    }
}

/**
 * Passphrase identity via scrypt. `maxWorkFactor` caps the work an attacker can force
 * us to spend on a malicious file. Default 22 (N = 4194304, several seconds of work).
 */
class ScryptIdentity(
    val passphrase: String,
    val maxWorkFactor: Int = 22,
) : AgeIdentity {
    init {
        require(maxWorkFactor in 1..30) { "maxWorkFactor must be 1..30" }
    }

    override fun unwrap(stanza: Stanza): ByteArray? {
        if (stanza.type != SCRYPT_STANZA_TYPE) return null
        if (stanza.args.size != 2) return null

        val salt = try { Stanza.base64Decode(stanza.args[0]) } catch (_: Exception) { return null }
        if (salt.size != SCRYPT_SALT_LEN) return null

        // Workfactor format: pure decimal digits, no leading zero (unless the value is "0"
        // itself which we reject below anyway), no sign.
        val wfStr = stanza.args[1]
        if (wfStr.isEmpty() || wfStr.any { it !in '0'..'9' }) return null
        if (wfStr.length > 1 && wfStr[0] == '0') return null
        val workFactor = wfStr.toIntOrNull() ?: return null
        if (workFactor < 1 || workFactor > maxWorkFactor) return null

        val fullSalt = SCRYPT_LABEL.toByteArray() + salt
        val n = 1 shl workFactor
        val wrapKey = Scrypt.derive(passphrase.toByteArray(Charsets.UTF_8), fullSalt, n, 8, 1, 32)
        return try {
            ChaChaPoly.decrypt(wrapKey, ZERO_NONCE_12, stanza.body)
        } catch (_: Exception) {
            null
        }
    }
}
