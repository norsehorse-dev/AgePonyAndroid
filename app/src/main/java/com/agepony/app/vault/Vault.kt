package com.agepony.app.vault

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.agepony.app.security.keystore.HardwareKeyService
import com.agepony.app.security.keystore.HardwareTagKeyService
import kotlinx.serialization.json.Json
import java.io.File

//
// The Android counterpart of iOS's Vault.swift: the single source of truth for
// identities, recipients, notes, and trusted signers, plus the
// persistence/crypto plumbing. SwiftUI binds to the iOS @Observable Vault
// directly; here the equivalent Compose-observable state lives on this class
// (mutableStateOf / state lists), and a VaultViewModel owns one instance across
// configuration changes and drives the biometric flow.
//
// Files (app-private, filesDir/vault/):
//   vault.key — iv(12) ‖ KEK-wrapped VK         (written once at bootstrap)
//   vault.dat — iv(12) ‖ AES-256-GCM(VK, snapshot)   (rewritten on every change)
//
// The VK is held only while unlocked and is dropped by lock().
//
/** The process-wide [Vault]. Every activity's view model uses this one instance. */
object SharedVault {
    @Volatile private var instance: Vault? = null

    fun get(context: Context): Vault =
        instance ?: synchronized(this) {
            instance ?: Vault(context.applicationContext).also { instance = it }
        }
}

class Vault(context: Context) {

    // Compose-observable state (mirrors the iOS @Observable arrays + isUnlocked).
    var isUnlocked by mutableStateOf(false)
        private set

    // Set true right before launching a system UI (e.g. the SAF file picker) so
    // the lock-on-background handler doesn't drop the vault for an in-app round
    // trip. Reset to false when the app returns to the foreground (ON_START).
    var autoLockSuppressed: Boolean = false

    val identities = mutableStateListOf<StoredIdentity>()
    val recipients = mutableStateListOf<StoredRecipient>()
    val notes = mutableStateListOf<StoredNote>()
    val signers = mutableStateListOf<StoredSigner>()
    // 4.2.0 recycle bin: soft-deleted identities/recipients, newest first.
    val trashedIdentities = mutableStateListOf<TrashedIdentity>()
    val trashedRecipients = mutableStateListOf<TrashedRecipient>()

    // Settings surfaced for binding (UserDefaults on iOS -> SharedPreferences here).
    private val prefs = context.getSharedPreferences("agepony_vault_settings", Context.MODE_PRIVATE)

    var activeIdentityId: String?
        get() = prefs.getString(KEY_ACTIVE_IDENTITY, null)
        set(value) { prefs.edit().putString(KEY_ACTIVE_IDENTITY, value).apply() }

    // The Keystore/OS gate mode (4.1.0), replacing the pre-4.1.0 biometricEnabled
    // boolean. Migrated on first read: legacy true -> BIOMETRIC, false -> OFF, which
    // preserves the exact behavior each existing user already had. New installs get
    // BIOMETRIC by default (unchanged from the old boolean's default of true).
    var lockMode: LockMode
        get() {
            prefs.getString(KEY_LOCK_MODE, null)?.let { return LockMode.fromKey(it) }
            val migrated =
                if (prefs.getBoolean(KEY_BIOMETRIC_ENABLED, true)) LockMode.BIOMETRIC else LockMode.OFF
            prefs.edit().putString(KEY_LOCK_MODE, migrated.key).apply()
            return migrated
        }
        set(value) { prefs.edit().putString(KEY_LOCK_MODE, value.key).apply() }

    // Compat shim for call sites still phrased in terms of the old boolean. "On"
    // means BIOMETRIC; turning it off means OFF. DEVICE_CREDENTIAL is not
    // expressible here, so it reads as false; never round-trip a DEVICE_CREDENTIAL
    // vault through this setter.
    var biometricEnabled: Boolean
        get() = lockMode == LockMode.BIOMETRIC
        set(value) { lockMode = if (value) LockMode.BIOMETRIC else LockMode.OFF }

    var encryptToSelfDefault: Boolean
        get() = prefs.getBoolean(KEY_ENCRYPT_TO_SELF, true)
        set(value) { prefs.edit().putBoolean(KEY_ENCRYPT_TO_SELF, value).apply() }

    var hasCompletedOnboarding: Boolean
        get() = prefs.getBoolean(KEY_ONBOARDED, false)
        set(value) { prefs.edit().putBoolean(KEY_ONBOARDED, value).apply() }

    // Last selected bottom-nav tab. The vault re-locks whenever the app is
    // backgrounded (see VaultGate), which tears down the app shell, so the tab
    // is persisted here rather than kept only in composition. Restoring it on
    // unlock keeps the user on the same tab instead of snapping back to Files,
    // and because it's on disk it also survives the process death that
    // aggressive OEM battery managers (e.g. MIUI) inflict on backgrounded apps.
    var lastTab: String?
        get() = prefs.getString(KEY_LAST_TAB, null)
        set(value) { prefs.edit().putString(KEY_LAST_TAB, value).apply() }

    /**
     * Which kind of app-owned unlock secret the user chose: "password" or "pin", null
     * when none is set. Cosmetic only (keyboard type on the unlock screen); the crypto
     * treats both identically.
     */
    var unlockSecretKind: String?
        get() = prefs.getString(KEY_UNLOCK_SECRET_KIND, null)
        set(value) { prefs.edit().putString(KEY_UNLOCK_SECRET_KIND, value).apply() }

    // Phase 2f — engagement counters for the in-app review nudge. launchCount is
    // bumped once per fresh process start (see MainActivity); reviewPromptShown
    // latches true the first time the Play in-app review flow is requested so the
    // nudge fires at most once. Neither touches the encrypted vault.
    var launchCount: Int
        get() = prefs.getInt(KEY_LAUNCH_COUNT, 0)
        set(value) { prefs.edit().putInt(KEY_LAUNCH_COUNT, value).apply() }

    /**
     * Work factor for passphrase (scrypt) encryption, as the exponent in N = 2^workFactor.
     *
     * age's default is 18, which costs 256 MiB of RAM while the key is derived, independent of
     * file size; a device with less headroom can drop to 16 (64 MiB). The chosen factor is written
     * into the file's scrypt stanza, so every value stays readable by any age implementation.
     */
    var scryptWorkFactor: Int
        get() = prefs.getInt(KEY_SCRYPT_WORK_FACTOR, FileEncryptor.DEFAULT_SCRYPT_WORK_FACTOR)
            .coerceIn(FileEncryptor.MIN_SCRYPT_WORK_FACTOR, FileEncryptor.MAX_SCRYPT_WORK_FACTOR)
        set(value) {
            val clamped = value.coerceIn(
                FileEncryptor.MIN_SCRYPT_WORK_FACTOR,
                FileEncryptor.MAX_SCRYPT_WORK_FACTOR,
            )
            prefs.edit().putInt(KEY_SCRYPT_WORK_FACTOR, clamped).apply()
        }

    var reviewPromptShown: Boolean
        get() = prefs.getBoolean(KEY_REVIEW_PROMPT_SHOWN, false)
        set(value) { prefs.edit().putBoolean(KEY_REVIEW_PROMPT_SHOWN, value).apply() }

    // Phase 3.2 — encrypt-flow stickiness (GitHub issue #2). The encrypt screen used to start
    // from the same defaults every time, so anyone who always wants binary output, or always
    // encrypts to a passphrase, re-set the same two switches on every file. These remember the
    // last choice. Both are mirrored into Compose state as well as prefs, because Settings and
    // the encrypt screen can each write them and neither should show a stale switch.

    private var armorDefaultState by mutableStateOf(prefs.getBoolean(KEY_ARMOR_DEFAULT, true))

    /** Whether the encrypt screen starts with ASCII armor on. age's own default here is armored. */
    var armorDefault: Boolean
        get() = armorDefaultState
        set(value) {
            armorDefaultState = value
            prefs.edit().putBoolean(KEY_ARMOR_DEFAULT, value).apply()
        }

    private var passphraseModeDefaultState by
        mutableStateOf(prefs.getBoolean(KEY_PASSPHRASE_MODE_DEFAULT, false))

    /** Whether the recipient picker opens in passphrase (scrypt) mode rather than key selection. */
    var passphraseModeDefault: Boolean
        get() = passphraseModeDefaultState
        set(value) {
            passphraseModeDefaultState = value
            prefs.edit().putBoolean(KEY_PASSPHRASE_MODE_DEFAULT, value).apply()
        }

    // Background auto-lock grace period, in seconds. How long the vault stays
    // unlocked after the app is backgrounded before it locks. 30s default; 0 means
    // lock immediately on leaving the app. User-configurable in Settings (issue #3).
    private var autoLockGraceState by mutableStateOf(prefs.getInt(KEY_AUTO_LOCK_GRACE_SECONDS, 30))
    var autoLockGraceSeconds: Int
        get() = autoLockGraceState
        set(value) {
            autoLockGraceState = value
            prefs.edit().putInt(KEY_AUTO_LOCK_GRACE_SECONDS, value).apply()
        }

    // 4.2.0 — optional proxy for the one network key lookup (RecipientImport's
    // GitHub .keys fetch). Mirrored into Compose state like the defaults above so
    // Settings never shows a stale value. NONE (the default) is a direct
    // connection and behaves exactly as before.
    private var proxyTypeState by mutableStateOf(ProxyType.fromKey(prefs.getString(KEY_PROXY_TYPE, null)))
    var proxyType: ProxyType
        get() = proxyTypeState
        set(value) {
            proxyTypeState = value
            prefs.edit().putString(KEY_PROXY_TYPE, value.key).apply()
        }

    private var proxyHostState by mutableStateOf(prefs.getString(KEY_PROXY_HOST, "").orEmpty())
    var proxyHost: String
        get() = proxyHostState
        set(value) {
            proxyHostState = value
            prefs.edit().putString(KEY_PROXY_HOST, value).apply()
        }

    private var proxyPortState by mutableStateOf(prefs.getInt(KEY_PROXY_PORT, 0))
    var proxyPort: Int
        get() = proxyPortState
        set(value) {
            proxyPortState = value
            prefs.edit().putInt(KEY_PROXY_PORT, value).apply()
        }

    // Optional SOCKS5 / proxy credentials. For Tor/Orbot these are the stream
    // isolation token (distinct pairs -> distinct circuits); for a real proxy
    // they are ordinary auth. Blank by default.
    private var proxyUsernameState by mutableStateOf(prefs.getString(KEY_PROXY_USERNAME, "").orEmpty())
    var proxyUsername: String
        get() = proxyUsernameState
        set(value) {
            proxyUsernameState = value
            prefs.edit().putString(KEY_PROXY_USERNAME, value).apply()
        }

    private var proxyPasswordState by mutableStateOf(prefs.getString(KEY_PROXY_PASSWORD, "").orEmpty())
    var proxyPassword: String
        get() = proxyPasswordState
        set(value) {
            proxyPasswordState = value
            prefs.edit().putString(KEY_PROXY_PASSWORD, value).apply()
        }

    /** The full proxy config for the one network key fetch. */
    val proxyConfig: ProxyConfig
        get() = ProxyConfig(proxyType, proxyHost, proxyPort, proxyUsername, proxyPassword)

    /**
     * The passphrase last confirmed in the encrypt flow, so encrypting a run of files asks for it
     * once instead of once per file.
     *
     * Memory only. It is never written to prefs and never enters the vault snapshot, and [lock]
     * drops it alongside the vault key — and VaultGate locks the vault whenever the app is
     * backgrounded, so a remembered passphrase does not outlive a visible session. Choosing
     * recipients instead of a passphrase clears it, so a non-null value always means the last
     * choice was passphrase mode.
     */
    var sessionPassphrase: String? by mutableStateOf<String?>(null)
        private set

    /** Hold [value] for the rest of this unlocked session; blank or null forgets instead. */
    fun rememberSessionPassphrase(value: String?) {
        sessionPassphrase = value?.takeIf { it.isNotEmpty() }
    }

    /** Drop the remembered passphrase now, without locking the vault. */
    fun forgetSessionPassphrase() {
        sessionPassphrase = null
    }

    /** Bump the fresh-launch counter by one and return the new value. */
    fun incrementLaunchCount(): Int {
        val next = launchCount + 1
        launchCount = next
        return next
    }

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    private val vaultDir: File = File(context.filesDir, "vault")
    private val keyFile: File get() = File(vaultDir, "vault.key")
    private val plainKeyFile: File get() = File(vaultDir, "vault.key.plain")
    private val passwordKeyFile: File get() = File(vaultDir, "vault.key.pw")
    private val duressKeyFile: File get() = File(vaultDir, "vault.key.duress")
    private val dataFile: File get() = File(vaultDir, "vault.dat")

    // The in-memory vault key. Non-null only while unlocked.
    private var vk: ByteArray? = null

    // MARK: - Provisioning state

    /**
     * True once a vault has been created on this device (any unlock blob present). The
     * password blob counts: a vault created with a password and no biometric (4.0.0) has
     * only `vault.key.pw`, and must still read as provisioned.
     */
    fun isProvisioned(): Boolean =
        keyFile.exists() || plainKeyFile.exists() || passwordKeyFile.exists()

    fun keyBlobExists(): Boolean = keyFile.exists()

    /** Persist the KEK-wrapped VK blob (iv ‖ wrapped). Called once at bootstrap. */
    fun writeKeyBlob(blob: ByteArray) {
        ensureDir()
        keyFile.writeBytes(blob)
    }

    /** Read back the stored key blob for unwrapping. */
    fun readKeyBlob(): ByteArray = keyFile.readBytes()

    // Plain (non-biometric) key blob, present only while biometric is disabled.
    fun plainKeyBlobExists(): Boolean = plainKeyFile.exists()

    fun writePlainKeyBlob(blob: ByteArray) {
        ensureDir()
        plainKeyFile.writeBytes(blob)
    }

    fun readPlainKeyBlob(): ByteArray = plainKeyFile.readBytes()

    fun deletePlainKeyBlob() {
        plainKeyFile.delete()
    }

    // App-owned password/PIN unlock (4.0.0). The blobs are made and opened by
    // PasswordVault; the Vault only stores them. vault.key.pw wraps the VK under
    // the password-derived KEK; vault.key.duress is the decoy verifier.

    fun passwordKeyBlobExists(): Boolean = passwordKeyFile.exists()

    fun writePasswordKeyBlob(blob: ByteArray) {
        ensureDir()
        passwordKeyFile.writeBytes(blob)
    }

    fun readPasswordKeyBlob(): ByteArray = passwordKeyFile.readBytes()

    fun deletePasswordKeyBlob() {
        passwordKeyFile.delete()
    }

    fun duressBlobExists(): Boolean = duressKeyFile.exists()

    fun writeDuressBlob(blob: ByteArray) {
        ensureDir()
        duressKeyFile.writeBytes(blob)
    }

    fun readDuressBlob(): ByteArray = duressKeyFile.readBytes()

    fun deleteDuressBlob() {
        duressKeyFile.delete()
    }

    /** A copy of the in-memory vault key, or null if locked. Used to re-wrap under a different KEK. */
    fun snapshotVaultKey(): ByteArray? = vk?.copyOf()

    // MARK: - Lifecycle

    /** Bootstrap a fresh, empty vault with a freshly-generated VK and persist it. */
    fun bootstrap(vaultKey: ByteArray) {
        // Copy: bootstrap callers wipe their transient VK buffer right after this
        // returns, so the vault must not alias it or persist() would later seal
        // vault.dat under a zeroed key.
        vk = vaultKey.copyOf()
        identities.clear()
        recipients.clear()
        notes.clear()
        signers.clear()
        trashedIdentities.clear()
        trashedRecipients.clear()
        persist()
        isUnlocked = true
    }

    /** Unlock an existing vault: open vault.dat with the (already-unwrapped) VK. */
    fun unlock(vaultKey: ByteArray) {
        val snapshot = loadSnapshot(vaultKey)
        // Copy so the vault owns its key independently of the caller's buffer.
        vk = vaultKey.copyOf()
        identities.clear(); identities.addAll(snapshot.identities)
        recipients.clear(); recipients.addAll(snapshot.recipients)
        notes.clear(); notes.addAll(snapshot.notes)
        signers.clear(); signers.addAll(snapshot.signers)
        trashedIdentities.clear(); trashedIdentities.addAll(snapshot.trashedIdentities)
        trashedRecipients.clear(); trashedRecipients.addAll(snapshot.trashedRecipients)
        isUnlocked = true
        purgeExpiredTrash()
    }

    /** Drop the VK and all decrypted state from memory (called on background). */
    fun lock() {
        vk?.fill(0)
        vk = null
        sessionPassphrase = null
        identities.clear()
        recipients.clear()
        notes.clear()
        signers.clear()
        trashedIdentities.clear()
        trashedRecipients.clear()
        isUnlocked = false
    }

    // MARK: - Identity CRUD

    fun addIdentity(identity: StoredIdentity) {
        identities.add(identity)
        if (activeIdentityId == null) activeIdentityId = identity.id
        persist()
    }

    fun renameIdentity(id: String, newName: String) {
        val idx = identities.indexOfFirst { it.id == id }
        if (idx < 0) return
        identities[idx] = identities[idx].copy(name = newName)
        persist()
    }

    fun deleteIdentity(id: String) {
        val idx = identities.indexOfFirst { it.id == id }
        if (idx < 0) return
        val removed = identities.removeAt(idx)
        trashedIdentities.add(0, TrashedIdentity(removed, System.currentTimeMillis()))
        if (activeIdentityId == id) activeIdentityId = identities.firstOrNull()?.id
        persist()
    }

    fun activeIdentity(): StoredIdentity? {
        val id = activeIdentityId ?: return identities.firstOrNull()
        return identities.firstOrNull { it.id == id } ?: identities.firstOrNull()
    }

    // MARK: - Recipient CRUD

    fun addRecipient(recipient: StoredRecipient) {
        recipients.add(recipient)
        persist()
    }

    /**
     * Rename a saved recipient. Names are the whole point of saving a public key rather than
     * pasting it each time, and until now one could only be set at the moment of adding.
     * A blank name is ignored rather than accepted, since it would leave an unidentifiable row.
     */
    fun renameRecipient(id: String, newName: String) {
        val trimmed = newName.trim()
        if (trimmed.isEmpty()) return
        val idx = recipients.indexOfFirst { it.id == id }
        if (idx < 0) return
        recipients[idx] = recipients[idx].copy(name = trimmed)
        persist()
    }

    fun deleteRecipient(id: String) {
        val idx = recipients.indexOfFirst { it.id == id }
        if (idx < 0) return
        val removed = recipients.removeAt(idx)
        trashedRecipients.add(0, TrashedRecipient(removed, System.currentTimeMillis()))
        persist()
    }

    // MARK: - Recycle bin (4.2.0)

    /** Move a soft-deleted identity back into the active list. */
    fun restoreIdentity(id: String) {
        val idx = trashedIdentities.indexOfFirst { it.identity.id == id }
        if (idx < 0) return
        val restored = trashedIdentities.removeAt(idx).identity
        identities.add(restored)
        if (activeIdentityId == null) activeIdentityId = restored.id
        persist()
    }

    /** Permanently remove one identity from the recycle bin. */
    fun purgeIdentity(id: String) {
        val gone = trashedIdentities.filter { it.identity.id == id }.map { it.identity }
        if (trashedIdentities.removeAll { it.identity.id == id }) {
            persist()
            releaseDeviceKeys(gone)
        }
    }

    /**
     * Delete the Keystore entries behind identities that are gone for good. Only called after
     * the vault without them has been persisted, so a failed write never strands a vault entry
     * whose key was already destroyed.
     */
    private fun releaseDeviceKeys(gone: List<StoredIdentity>) {
        for (identity in gone) {
            val alias = identity.keystoreAlias ?: continue
            runCatching {
                when (identity.type) {
                    StoredIdentityType.HARDWARE_KEY -> HardwareKeyService.delete(alias)
                    StoredIdentityType.HARDWARE_TAG, StoredIdentityType.HARDWARE_TAG_PQ ->
                        HardwareTagKeyService.delete(alias)
                    else -> Unit
                }
            }
        }
    }

    /** Move a soft-deleted recipient back into the active list. */
    fun restoreRecipient(id: String) {
        val idx = trashedRecipients.indexOfFirst { it.recipient.id == id }
        if (idx < 0) return
        recipients.add(trashedRecipients.removeAt(idx).recipient)
        persist()
    }

    /** Permanently remove one recipient from the recycle bin. */
    fun purgeRecipient(id: String) {
        if (trashedRecipients.removeAll { it.recipient.id == id }) persist()
    }

    /** Empty the whole recycle bin now. */
    fun emptyTrash() {
        if (trashedIdentities.isEmpty() && trashedRecipients.isEmpty()) return
        val gone = trashedIdentities.map { it.identity }
        trashedIdentities.clear()
        trashedRecipients.clear()
        persist()
        releaseDeviceKeys(gone)
    }

    /** Drop bin entries older than TRASH_RETENTION_DAYS. Persists only if something changed. */
    fun purgeExpiredTrash() {
        val cutoff = System.currentTimeMillis() - TRASH_RETENTION_DAYS * 24L * 60L * 60L * 1000L
        val gone = trashedIdentities.filter { it.deletedAt < cutoff }.map { it.identity }
        val a = trashedIdentities.removeAll { it.deletedAt < cutoff }
        val b = trashedRecipients.removeAll { it.deletedAt < cutoff }
        if (a || b) persist()
        if (a) releaseDeviceKeys(gone)
    }

    // MARK: - Note CRUD

    fun addNote(note: StoredNote) {
        notes.add(note)
        persist()
    }

    fun deleteNote(id: String) {
        notes.removeAll { it.id == id }
        persist()
    }

    // MARK: - Signer CRUD

    /**
     * Add a trusted signer. Returns false (and stores nothing) if a signer with the same
     * public-key wire is already on the list — the key is the identity here, and two rows
     * for one key would let their names disagree.
     */
    fun addSigner(signer: StoredSigner): Boolean {
        if (signers.any { it.publicKeyWireB64 == signer.publicKeyWireB64 }) return false
        signers.add(signer)
        persist()
        return true
    }

    /** Rename a trusted signer. A blank name is ignored, same as recipients. */
    fun renameSigner(id: String, newName: String) {
        val trimmed = newName.trim()
        if (trimmed.isEmpty()) return
        val idx = signers.indexOfFirst { it.id == id }
        if (idx < 0) return
        signers[idx] = signers[idx].copy(name = trimmed)
        persist()
    }

    fun deleteSigner(id: String) {
        signers.removeAll { it.id == id }
        persist()
    }

    // MARK: - Reset

    /** Destroy the on-disk vault. The KEK is deleted by the caller (VaultViewModel). */
    fun reset() {
        lock()
        keyFile.delete()
        plainKeyFile.delete()
        passwordKeyFile.delete()
        duressKeyFile.delete()
        dataFile.delete()
        // Hardware keys outlive the vault file otherwise. A decryption key left in the Keystore
        // after a wipe (duress included) would still open files encrypted to it.
        deleteAllDeviceKeys()
        prefs.edit()
            .remove(KEY_ACTIVE_IDENTITY)
            .remove(KEY_ONBOARDED)
            .remove(KEY_LAST_TAB)
            .remove(KEY_UNLOCK_SECRET_KIND)
            .apply()
    }

    private fun deleteAllDeviceKeys() {
        runCatching {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val prefixes = listOf(HardwareKeyService.ALIAS_PREFIX, HardwareTagKeyService.ALIAS_PREFIX)
            ks.aliases().toList()
                .filter { alias -> prefixes.any { alias.startsWith(it) } }
                .forEach { alias -> runCatching { ks.deleteEntry(alias) } }
        }
    }

    // MARK: - Persistence

    private fun persist() {
        val key = vk ?: error("Vault is locked")
        val snapshot = VaultSnapshot(
            identities = identities.toList(),
            recipients = recipients.toList(),
            notes = notes.toList(),
            signers = signers.toList(),
            trashedIdentities = trashedIdentities.toList(),
            trashedRecipients = trashedRecipients.toList()
        )
        val plaintext = json.encodeToString(VaultSnapshot.serializer(), snapshot).toByteArray(Charsets.UTF_8)
        val sealed = VaultCrypto.seal(key, plaintext)
        ensureDir()
        // Write to a temp file then rename for an atomic-ish replace.
        val tmp = File(vaultDir, "vault.dat.tmp")
        tmp.writeBytes(sealed)
        if (!tmp.renameTo(dataFile)) {
            dataFile.writeBytes(sealed)
            tmp.delete()
        }
    }

    private fun loadSnapshot(key: ByteArray): VaultSnapshot {
        if (!dataFile.exists()) return VaultSnapshot()
        val sealed = dataFile.readBytes()
        val plaintext = VaultCrypto.open(key, sealed)
        return json.decodeFromString(VaultSnapshot.serializer(), String(plaintext, Charsets.UTF_8))
    }

    private fun ensureDir() {
        if (!vaultDir.exists()) vaultDir.mkdirs()
    }

    private companion object {
        // Recycle-bin retention: soft-deleted entries older than this are purged on unlock.
        const val TRASH_RETENTION_DAYS = 30L
        const val KEY_ACTIVE_IDENTITY = "activeIdentityId"
        const val KEY_BIOMETRIC_ENABLED = "biometricEnabled"
        const val KEY_LOCK_MODE = "lockMode"
        const val KEY_ENCRYPT_TO_SELF = "encryptToSelfDefault"
        const val KEY_ONBOARDED = "hasCompletedOnboarding"
        const val KEY_LAUNCH_COUNT = "launchCount"
        const val KEY_REVIEW_PROMPT_SHOWN = "reviewPromptShown"
        const val KEY_LAST_TAB = "lastTab"
        const val KEY_UNLOCK_SECRET_KIND = "unlockSecretKind"
        const val KEY_SCRYPT_WORK_FACTOR = "scryptWorkFactor"
        const val KEY_ARMOR_DEFAULT = "armorDefault"
        const val KEY_PASSPHRASE_MODE_DEFAULT = "passphraseModeDefault"
        const val KEY_PROXY_TYPE = "proxyType"
        const val KEY_PROXY_HOST = "proxyHost"
        const val KEY_PROXY_PORT = "proxyPort"
        const val KEY_PROXY_USERNAME = "proxyUsername"
        const val KEY_PROXY_PASSWORD = "proxyPassword"
        const val KEY_AUTO_LOCK_GRACE_SECONDS = "autoLockGraceSeconds"
    }
}
