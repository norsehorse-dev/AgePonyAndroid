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
 * [VaultCrypto]'s `iv ‖ ciphertext ‖ tag` under the KEK.
 *   - The real blob seals the 32-byte vault key (VK).
 *   - The duress blob seals 32 random bytes. Its content is never used; a successful
 *     open IS the duress signal.
 *
 * KEK by version:
 *   - v1 (4.0.0 to 5.0.0): KEK = scrypt(secret, salt, 2^logN). Software only, so a copy of
 *     the blob could be guessed offline (audit M-2). Still opened, and re-wrapped as v2 by
 *     the caller after the next successful unlock ([Outcome.Real.needsRewrap]).
 *   - v2 (5.0.1): KEK = HMAC-SHA256 under a non-exportable AndroidKeyStore key
 *     ([DeviceBinding], see PasswordDeviceKey) over `label ‖ scrypt(secret, salt, 2^logN)`.
 *     Every guess needs this device's Keystore, so a copied blob is useless elsewhere.
 *
 * Duress design (settled in the 4.0.0 plan): entering the decoy wipes everything and
 * silently re-bootstraps an empty vault whose real password is the decoy just entered.
 * The orchestration lives in VaultViewModel; the contract here is only [tryUnlock]'s
 * three-way answer.
 *
 * Timing discipline: [tryUnlock] runs the same work regardless of which (if either)
 * secret matched, and whether either blob exists: one Keystore key check, then for each
 * slot one scrypt worth 2^[LOG_N] and one Keystore HMAC, against a dummy salt when a blob
 * is absent, with both AEAD opens attempted. A legacy blob at a lower work factor is padded
 * with dummy scrypt runs up to the same cost. The branch itself is on AEAD results over
 * 48-byte blobs. The acceptance test for this is statistical, on-device (see the plan's B4).
 *
 * A PIN is just a password with a numeric keyboard; the Vault stores which kind the user
 * chose so the unlock screen shows the right input, and nothing else differs.
 */
object PasswordVault {
    class PasswordVaultException(message: String) : Exception(message)

    /**
     * The device-held secret mixed into the v2 KEK (audit M-2). Production uses
     * [PasswordDeviceKey]; unit tests pass a software stand-in.
     */
    interface DeviceBinding {
        /** Make sure the key exists. Returns true if it had to be created just now. */
        fun ensureKey(): Boolean

        /** HMAC-SHA256 of [data] under the device key. Throws if the key is unusable. */
        fun mac(data: ByteArray): ByteArray
    }

    private const val VERSION_V1: Byte = 1
    private const val VERSION_V2: Byte = 2

    /**
     * Work factor for new blobs. 2^16 with r=8 is 64 MiB and a few hundred milliseconds per
     * derivation on a mid-range phone. Unlock pays two derivations (real + duress) by design,
     * so this stays below the age-file default of 2^18; since 5.0.1 the KEK also needs this
     * device's Keystore, so the work factor only has to slow on-device guessing, which the
     * failed-attempt backoff (UnlockAttempts) limits as well. 4.0.0 to 5.0.0 used 2^15.
     */
    private const val LOG_N: Int = 16
    private const val R: Int = 8
    private const val P: Int = 1
    private const val SALT_LEN = 16
    private const val KEY_LEN = 32
    private const val HEADER_LEN = 2 + SALT_LEN

    /** Minimum lengths for a new or changed secret (audit M-1). Existing shorter ones still unlock. */
    const val MIN_PIN_LENGTH = 6
    const val MIN_PASSWORD_LENGTH = 8

    private val BIND_LABEL = "AgePony password KEK v2".toByteArray(Charsets.US_ASCII)

    private val rng = SecureRandom()

    sealed class Outcome {
        /** Zero whatever key material this outcome holds. Safe to call more than once. */
        open fun wipe() {}

        /**
         * The real secret: here is the vault key. [needsRewrap] is true for a v1 blob or one
         * below the current work factor; the caller should re-wrap it with [wrapVaultKey] while
         * it still has the secret.
         */
        class Real(val vaultKey: ByteArray, val needsRewrap: Boolean = false) : Outcome() {
            override fun wipe() { vaultKey.fill(0) }
        }

        /**
         * The decoy secret: the caller wipes and re-bootstraps. Holds the scrypt output
         * [tryUnlock] already computed for the decoy, so [wrapNewVaultKey] can seal the new
         * vault's key under the decoy without another scrypt run. That keeps the duress path
         * close to a wrong-password attempt in time (audit M-8).
         */
        class Duress internal constructor(
            private val stretched: ByteArray,
            private val salt: ByteArray,
            private val logN: Int,
        ) : Outcome() {
            private var wiped = false

            /**
             * Build a real blob (v2) sealing [vaultKey] under the decoy secret, reusing the
             * decoy's salt and scrypt output with a fresh device key. Usable once; wipes the
             * held material afterwards.
             */
            fun wrapNewVaultKey(vaultKey: ByteArray, binding: DeviceBinding = PasswordDeviceKey): ByteArray {
                check(!wiped) { "duress material already used" }
                try {
                    binding.ensureKey()
                    val kek = bind(binding, stretched)
                    try {
                        return byteArrayOf(VERSION_V2, logN.toByte()) + salt + VaultCrypto.seal(kek, vaultKey)
                    } finally {
                        kek.fill(0)
                    }
                } finally {
                    wipe()
                }
            }

            override fun wipe() {
                stretched.fill(0)
                wiped = true
            }
        }

        object Wrong : Outcome()
    }

    /** Build the real blob (v2): [vaultKey] sealed under a KEK derived from [secret]. */
    fun wrapVaultKey(
        secret: CharArray,
        vaultKey: ByteArray,
        binding: DeviceBinding = PasswordDeviceKey,
    ): ByteArray = buildBlob(secret, binding) { kek -> VaultCrypto.seal(kek, vaultKey) }

    /** Build the duress blob (v2): random filler sealed under the decoy-derived KEK. */
    fun duressBlob(secret: CharArray, binding: DeviceBinding = PasswordDeviceKey): ByteArray =
        buildBlob(secret, binding) { kek -> VaultCrypto.seal(kek, ByteArray(KEY_LEN).also { rng.nextBytes(it) }) }

    /**
     * Check [secret] against both blobs, constant-shape. Pass null for a blob that is
     * not set; the corresponding derivation still runs against a dummy salt so absence
     * doesn't change the work done. Real wins over duress by fixed order (enrollment
     * refuses a duress secret equal to the real one, so the case shouldn't exist).
     *
     * The caller owns the returned outcome's key material: call [Outcome.wipe] when done.
     */
    fun tryUnlock(
        secret: CharArray,
        realBlob: ByteArray?,
        duressBlob: ByteArray?,
        binding: DeviceBinding = PasswordDeviceKey,
    ): Outcome {
        // One key check up front whatever blobs exist, so the Keystore call pattern doesn't
        // depend on them. A failure here only matters to v2 blobs (their HMAC fails below).
        val keyCreated = runCatching { binding.ensureKey() }.getOrDefault(false)
        val real = attempt(secret, realBlob, binding)
        val duress = attempt(secret, duressBlob, binding)
        try {
            return when {
                real.opened != null -> Outcome.Real(real.opened, needsRewrap = real.legacy)
                duress.opened != null -> Outcome.Duress(duress.stretched.copyOf(), duress.salt, duress.logN)
                // A v2 real blob whose device key is gone (or was just recreated) can never open
                // again. Say so instead of reporting a wrong password forever.
                real.version == 2 && (real.bindingFailed || keyCreated) ->
                    throw PasswordVaultException(
                        "This device's key for the app password is missing, so the password can't open the vault."
                    )
                else -> Outcome.Wrong
            }
        } finally {
            real.stretched.fill(0)
            duress.stretched.fill(0)
        }
    }

    /**
     * Why [secret] can't be used as a new or changed secret of [kind] ("pin" or "password"),
     * or null if it's acceptable (audit M-1). A PIN must be digits only, since the unlock
     * screen shows a number pad for it.
     */
    fun secretPolicyError(secret: CharSequence, kind: String): String? =
        if (kind == "pin") {
            when {
                secret.any { it !in '0'..'9' } -> "A PIN can only contain digits."
                secret.length < MIN_PIN_LENGTH -> "Use at least $MIN_PIN_LENGTH digits."
                else -> null
            }
        } else {
            if (secret.length < MIN_PASSWORD_LENGTH) "Use at least $MIN_PASSWORD_LENGTH characters." else null
        }

    // --- internals ---

    private class Attempt(
        val opened: ByteArray?,
        val stretched: ByteArray,
        val salt: ByteArray,
        val logN: Int,
        val version: Int,
        val legacy: Boolean,
        val bindingFailed: Boolean,
    )

    private fun buildBlob(secret: CharArray, binding: DeviceBinding, seal: (ByteArray) -> ByteArray): ByteArray {
        binding.ensureKey()
        val salt = ByteArray(SALT_LEN).also { rng.nextBytes(it) }
        val stretched = derive(secret, salt, LOG_N)
        try {
            val kek = bind(binding, stretched)
            try {
                return byteArrayOf(VERSION_V2, LOG_N.toByte()) + salt + seal(kek)
            } finally {
                kek.fill(0)
            }
        } finally {
            stretched.fill(0)
        }
    }

    /**
     * Derive against [blob]'s salt and try to open it. When [blob] is null the derivation
     * runs against a dummy salt and the open is skipped, which keeps the dominant costs
     * (scrypt and the Keystore HMAC) identical for present and absent blobs.
     */
    private fun attempt(secret: CharArray, blob: ByteArray?, binding: DeviceBinding): Attempt {
        if (blob == null) {
            val dummySalt = ByteArray(SALT_LEN)
            val stretched = derive(secret, dummySalt, LOG_N)
            runCatching { bind(binding, stretched).fill(0) }
            return Attempt(null, stretched, dummySalt, LOG_N, 0, legacy = false, bindingFailed = false)
        }
        if (blob.size < HEADER_LEN + 12 + 16) throw PasswordVaultException("key blob too short")
        val version = blob[0].toInt()
        if (version != VERSION_V1.toInt() && version != VERSION_V2.toInt()) {
            throw PasswordVaultException("unknown key blob version $version")
        }
        val logN = blob[1].toInt()
        if (logN < 10 || logN > 22) throw PasswordVaultException("implausible work factor $logN")
        val salt = blob.copyOfRange(2, HEADER_LEN)
        val sealed = blob.copyOfRange(HEADER_LEN, blob.size)
        val stretched = derive(secret, salt, logN)
        padWork(secret, logN)
        // Always one HMAC, so a v1 blob costs the same Keystore work as a v2 one.
        val bound = runCatching { bind(binding, stretched) }.getOrNull()
        val kek: ByteArray? = if (version == VERSION_V2.toInt()) {
            bound
        } else {
            bound?.fill(0)
            stretched.copyOf()
        }
        val opened = if (kek == null) {
            null
        } else {
            try {
                VaultCrypto.open(kek, sealed)
            } catch (_: Exception) {
                null
            } finally {
                kek.fill(0)
            }
        }
        return Attempt(
            opened = opened,
            stretched = stretched,
            salt = salt,
            logN = logN,
            version = version,
            legacy = version == VERSION_V1.toInt() || logN < LOG_N,
            bindingFailed = version == VERSION_V2.toInt() && bound == null,
        )
    }

    /**
     * Bring a blob below [LOG_N] up to the same scrypt cost with dummy runs at its own work
     * factor (scrypt time is linear in N), so an old 2^15 duress blob next to a new 2^16 real
     * one doesn't show in unlock timing.
     */
    private fun padWork(secret: CharArray, logN: Int) {
        if (logN >= LOG_N) return
        repeat((1 shl (LOG_N - logN)) - 1) {
            derive(secret, ByteArray(SALT_LEN), logN).fill(0)
        }
    }

    private fun bind(binding: DeviceBinding, stretched: ByteArray): ByteArray {
        val input = BIND_LABEL + stretched
        try {
            val out = binding.mac(input)
            if (out.size < KEY_LEN) throw PasswordVaultException("device key returned a short MAC")
            if (out.size == KEY_LEN) return out
            val kek = out.copyOf(KEY_LEN)
            out.fill(0)
            return kek
        } finally {
            input.fill(0)
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
