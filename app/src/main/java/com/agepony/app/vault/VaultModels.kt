package com.agepony.app.vault

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

//
// Persisted records held by the Vault. These are the Android counterparts of
// iOS's VaultModels.swift Codable structs. They are pure data: the raw key
// material is stored as Base64 strings, and the concrete crypto-layer types
// (X25519Identity, SSHEd25519Identity, SSHRSAIdentity, HybridIdentity, and their
// recipients) are re-instantiated on demand by hydration helpers — this keeps
// the vault/model layer entirely above the crypto layer.
//
// StoredSigner (the trusted-signers list) lives in its own file, mirroring
// iOS's Vault/StoredSigner.swift.
//
// Serialization: kotlinx.serialization (compiler-plugin codegen, no reflection).
// On the AGP 9 built-in-Kotlin toolchain, KSP — and therefore Moshi codegen —
// is unavailable, so kotlinx.serialization (same plugin mechanism as the
// Compose compiler plugin) is the codegen path used here.
//

@Serializable
enum class StoredIdentityType {
    @SerialName("x25519") X25519,
    @SerialName("mlkem768x25519") MLKEM768X25519,
    @SerialName("sshEd25519") SSH_ED25519,
    @SerialName("sshRSA") SSH_RSA,
    @SerialName("hardwareKey") HARDWARE_KEY,
    @SerialName("skEd25519") SK_ED25519,
    @SerialName("skEcdsaP256") SK_ECDSA_P256,
    // 5.0.0: hardware-bound age decryption keys (age v1.3 tag recipients). The P-256 private key
    // lives in the Android Keystore under keystoreAlias. HARDWARE_TAG_PQ also holds a 64-byte
    // ML-KEM-768 seed in privateKeyB64.
    @SerialName("hardwareTag") HARDWARE_TAG,
    @SerialName("hardwareTagPQ") HARDWARE_TAG_PQ,
    // 5.0.0: an age-plugin-yubikey key in a YubiKey PIV slot. publicKeyB64 = 33-byte compressed
    // point, privateKeyB64 = the 9-byte AGE-PLUGIN-YUBIKEY stub (a pointer, not a secret).
    @SerialName("yubikeyPiv") YUBIKEY_PIV
}

/**
 * Signing-only identity types cannot decrypt or be used as encryption recipients. A
 * hardware key holds a non-exportable EC P-256 signing key in the Keystore; it has no
 * decryption capability. Kept as an extension so every recipient/decrypt path can filter
 * on it, and so new signing-only types (the sk-* security keys in P3) join here.
 */
val StoredIdentityType.isSigningOnly: Boolean
    get() = when (this) {
        StoredIdentityType.X25519 -> false
        StoredIdentityType.MLKEM768X25519 -> false
        StoredIdentityType.SSH_ED25519 -> false
        StoredIdentityType.SSH_RSA -> false
        StoredIdentityType.HARDWARE_KEY -> true
        StoredIdentityType.SK_ED25519 -> true
        StoredIdentityType.SK_ECDSA_P256 -> true
        StoredIdentityType.HARDWARE_TAG -> false
        StoredIdentityType.HARDWARE_TAG_PQ -> false
        StoredIdentityType.YUBIKEY_PIV -> false
    }

/** True for identities whose private key is bound to this device's Keystore (cannot be moved or backed up). */
val StoredIdentityType.isDeviceBound: Boolean
    get() = this == StoredIdentityType.HARDWARE_KEY ||
        this == StoredIdentityType.HARDWARE_TAG ||
        this == StoredIdentityType.HARDWARE_TAG_PQ

/** True for post-quantum (hybrid ML-KEM-768) identity types. */
val StoredIdentityType.isPostQuantum: Boolean
    get() = this == StoredIdentityType.MLKEM768X25519 || this == StoredIdentityType.HARDWARE_TAG_PQ

@Serializable
enum class StoredRecipientType {
    @SerialName("x25519") X25519,
    @SerialName("mlkem768x25519") MLKEM768X25519,
    @SerialName("sshEd25519") SSH_ED25519,
    @SerialName("sshRSA") SSH_RSA,
    @SerialName("yubikeyP256") YUBIKEY_P256,
    // 5.0.0: age v1.3 tag recipients (age1tag1 / age1tagpq1), usually hardware keys elsewhere.
    @SerialName("tag") TAG,
    @SerialName("tagPQ") TAG_PQ
}

/** True for post-quantum (hybrid ML-KEM-768) recipient types. */
val StoredRecipientType.isPostQuantum: Boolean
    get() = this == StoredRecipientType.MLKEM768X25519 || this == StoredRecipientType.TAG_PQ

@Serializable
enum class StoredRecipientSource {
    @SerialName("pasteAge") PASTE_AGE,
    @SerialName("pasteSSH") PASTE_SSH,
    @SerialName("qrScan") QR_SCAN,
    @SerialName("github") GITHUB,
    @SerialName("derivedFromIdentity") DERIVED_FROM_IDENTITY
}

/**
 * A stored identity (private key). Public/private material is Base64; the
 * type-appropriate raw forms mirror iOS:
 *   x25519:          pub = 32-byte raw X25519 public key; priv = 32-byte scalar
 *   mlkem768x25519:  pub = 1216-byte hybrid public key;   priv = 32-byte seed
 *   sshEd25519:      pub = SSH wire blob; priv = 32-byte ed25519 seed
 *                    (Android's SSHEd25519Identity derives the public half from the
 *                     seed, so unlike iOS we store the 32-byte seed alone, not 64)
 *   sshRSA:          pub = `ssh-rsa ...` line bytes; priv = decrypted OpenSSH PEM bytes
 */
@Serializable
data class StoredIdentity(
    val id: String,
    val name: String,
    val type: StoredIdentityType,
    val publicKeyB64: String,
    val privateKeyB64: String,
    val sshComment: String? = null,
    /**
     * For HARDWARE_KEY identities: the AndroidKeyStore alias holding the non-exportable
     * private key. Null for software identities whose private material is in privateKeyB64.
     */
    val keystoreAlias: String? = null,
    val createdAt: Long
)

@Serializable
data class StoredRecipient(
    val id: String,
    val name: String,
    val type: StoredRecipientType,
    val publicKeyB64: String,
    val sshComment: String? = null,
    val source: StoredRecipientSource,
    val sourceMetadata: String? = null,
    val createdAt: Long
)

@Serializable
data class StoredNote(
    val id: String,
    val title: String,
    /** scrypt-armored age payload (.age bytes wrapping the note body), Base64. */
    val bodyCiphertextB64: String,
    val createdAt: Long,
    val updatedAt: Long
)

/**
 * A soft-deleted identity or recipient, held in the recycle bin until restored,
 * purged by hand, or aged out (Vault.TRASH_RETENTION_DAYS). Deleting an identity
 * destroys a private key, which cannot be recovered once gone for good, so the bin
 * gives a window to undo an accidental delete. Both are new in 4.2.0 and default to
 * empty in the snapshot, so old vault.dat files load and old apps ignore them.
 */
@Serializable
data class TrashedIdentity(val identity: StoredIdentity, val deletedAt: Long)

@Serializable
data class TrashedRecipient(val recipient: StoredRecipient, val deletedAt: Long)

/**
 * Full vault contents — the unit that is serialized and sealed to vault.dat.
 *
 * `signers` was added in 4.0.0. The default keeps both directions safe: an older
 * vault.dat decodes with an empty list, and an older app reading a newer vault.dat
 * drops the unknown field (ignoreUnknownKeys) rather than failing to unlock.
 */
@Serializable
data class VaultSnapshot(
    val identities: List<StoredIdentity> = emptyList(),
    val recipients: List<StoredRecipient> = emptyList(),
    val notes: List<StoredNote> = emptyList(),
    val signers: List<StoredSigner> = emptyList(),
    val trashedIdentities: List<TrashedIdentity> = emptyList(),
    val trashedRecipients: List<TrashedRecipient> = emptyList()
)
