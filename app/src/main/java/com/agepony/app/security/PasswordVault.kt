package com.agepony.app.security

import com.agepony.app.vault.VaultCrypto
import com.agepony.core.crypto.Scrypt
import java.security.SecureRandom

/**
 * The app-owned password/PIN unlock path (4.0.0, Feature B), and the duress check that
 * rides on it. Pure blob logic: the Vault owns the files (vault.key.pw and
 * vault.key.duress); this object only makes and opens their contents.
 *
 * Blob layout, both files: `version(1) ‖ logN(1) ‖ salt(16) ‖ sealed`, where `sealed` is
 * [VaultCrypto]'s `iv ‖ ciphertext ‖ tag` under the scrypt-derived KEK.
 *   - The real blob seals the 32-byte vault key (VK).
 *   - The duress blob seals 32 random bytes. Its content is never used; a successful
 *     open IS the duress signal.
 *
 * Duress design (settled in the 4.0.0 plan): entering the decoy wipes everything and
 * silently re-bootstraps an empty vault whose real password is the decoy just entered.
 * The orchestration lives in VaultViewModel; the contract here is only [tryUnlock]'s
 * three-way answer.
 *
 * Timing discipline: [tryUnlock] runs the same work regardless of which (if either)
 * secret matched — both scrypt derivations always run, against a dummy salt when a blob
 * is absent, and both AEAD opens are always attempted. The scrypt runs dominate (tens of
 * milliseconds each at 2^15); the branch itself is on AEAD results over 48-byte blobs.
 * The acceptance test for this is statistical, on-device (see the plan's B4).
 *
 * A PIN is just a password with a numeric keyboard; the Vault stores which kind the user
 * chose so the unlock screen shows the right input, and nothing else differs.
 */
object PasswordVault {
    class PasswordVaultException(message: String) : Exception(message)

    private const val VERSION: Byte = 1

    /**
     * 2^15 with r=8 is 32 MiB and tens of milliseconds per derivation. Unlock pays two
     * derivations (real + duress) by design, so the work factor here is deliberately
     * below the age-file default of 2^18; the KEK protects a locally-stored blob behind
     * the platform's own storage isolation, not a file that travels.
     */
    private const val LOG_N: Int = 15
    private const val R: Int = 8
    private const val P: Int = 1
    private const val SALT_LEN = 16
    private const val KEY_LEN = 32

    private val rng = SecureRandom()

    sealed class Outcome {
        /** The real secret: here is the vault key. */
        class Real(val vaultKey: ByteArray) : Outcome()
        /** The decoy secret: the caller wipes and re-bootstraps. */
        object Duress : Outcome()
        object Wrong : Outcome()
    }

    /** Build the real blob: [vaultKey] sealed under a KEK derived from [secret]. */
    fun wrapVaultKey(secret: CharArray, vaultKey: ByteArray): ByteArray =
        buildBlob(secret) { kek -> VaultCrypto.seal(kek, vaultKey) }

    /** Build the duress blob: random filler sealed under the decoy-derived KEK. */
    fun duressBlob(secret: CharArray): ByteArray =
        buildBlob(secret) { kek -> VaultCrypto.seal(kek, ByteArray(KEY_LEN).also { rng.nextBytes(it) }) }

    /**
     * Check [secret] against both blobs, constant-shape. Pass null for a blob that is
     * not set; the corresponding derivation still runs against a dummy salt so absence
     * doesn't change the work done. Real wins over duress by fixed order (enrollment
     * refuses a duress secret equal to the real one, so the case shouldn't exist).
     */
    fun tryUnlock(secret: CharArray, realBlob: ByteArray?, duressBlob: ByteArray?): Outcome {
        val realOpened = attemptOpen(secret, realBlob)
        val duressOpened = attemptOpen(secret, duressBlob)
        return when {
            realOpened != null -> Outcome.Real(realOpened)
            duressOpened != null -> Outcome.Duress
            else -> Outcome.Wrong
        }
    }

    // --- internals ---

    private fun buildBlob(secret: CharArray, seal: (ByteArray) -> ByteArray): ByteArray {
        val salt = ByteArray(SALT_LEN).also { rng.nextBytes(it) }
        val kek = derive(secret, salt, LOG_N)
        try {
            return byteArrayOf(VERSION, LOG_N.toByte()) + salt + seal(kek)
        } finally {
            kek.fill(0)
        }
    }

    /**
     * Derive against [blob]'s salt and try to open it; null on any mismatch. When [blob]
     * is null the derivation runs against a dummy salt and the open is skipped, which
     * keeps the dominant cost (scrypt) identical for present and absent blobs.
     */
    private fun attemptOpen(secret: CharArray, blob: ByteArray?): ByteArray? {
        if (blob == null) {
            derive(secret, ByteArray(SALT_LEN), LOG_N).fill(0)
            return null
        }
        if (blob.size < 2 + SALT_LEN + 12 + 16) throw PasswordVaultException("key blob too short")
        if (blob[0] != VERSION) throw PasswordVaultException("unknown key blob version ${blob[0]}")
        val logN = blob[1].toInt()
        if (logN < 10 || logN > 22) throw PasswordVaultException("implausible work factor $logN")
        val salt = blob.copyOfRange(2, 2 + SALT_LEN)
        val sealed = blob.copyOfRange(2 + SALT_LEN, blob.size)
        val kek = derive(secret, salt, logN)
        return try {
            VaultCrypto.open(kek, sealed)
        } catch (_: Exception) {
            null
        } finally {
            kek.fill(0)
        }
    }

    private fun derive(secret: CharArray, salt: ByteArray, logN: Int): ByteArray {
        val bytes = String(secret).toByteArray(Charsets.UTF_8)
        try {
            return Scrypt.derive(bytes, salt, 1 shl logN, R, P, KEY_LEN)
        } finally {
            bytes.fill(0)
        }
    }
}
