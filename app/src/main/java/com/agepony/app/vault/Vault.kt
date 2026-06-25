package com.agepony.app.vault

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.serialization.json.Json
import java.io.File

//
// The Android counterpart of iOS's Vault.swift: the single source of truth for
// identities, recipients, and notes, plus the persistence/crypto plumbing.
// SwiftUI binds to the iOS @Observable Vault directly; here the equivalent
// Compose-observable state lives on this class (mutableStateOf / state lists),
// and a VaultViewModel owns one instance across configuration changes and
// drives the biometric flow.
//
// Files (app-private, filesDir/vault/):
//   vault.key — iv(12) ‖ KEK-wrapped VK         (written once at bootstrap)
//   vault.dat — iv(12) ‖ AES-256-GCM(VK, snapshot)   (rewritten on every change)
//
// The VK is held only while unlocked and is dropped by lock().
//
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

    // Settings surfaced for binding (UserDefaults on iOS -> SharedPreferences here).
    private val prefs = context.getSharedPreferences("agepony_vault_settings", Context.MODE_PRIVATE)

    var activeIdentityId: String?
        get() = prefs.getString(KEY_ACTIVE_IDENTITY, null)
        set(value) { prefs.edit().putString(KEY_ACTIVE_IDENTITY, value).apply() }

    var biometricEnabled: Boolean
        get() = prefs.getBoolean(KEY_BIOMETRIC_ENABLED, true)
        set(value) { prefs.edit().putBoolean(KEY_BIOMETRIC_ENABLED, value).apply() }

    var encryptToSelfDefault: Boolean
        get() = prefs.getBoolean(KEY_ENCRYPT_TO_SELF, true)
        set(value) { prefs.edit().putBoolean(KEY_ENCRYPT_TO_SELF, value).apply() }

    var hasCompletedOnboarding: Boolean
        get() = prefs.getBoolean(KEY_ONBOARDED, false)
        set(value) { prefs.edit().putBoolean(KEY_ONBOARDED, value).apply() }

    // Phase 2f — engagement counters for the in-app review nudge. launchCount is
    // bumped once per fresh process start (see MainActivity); reviewPromptShown
    // latches true the first time the Play in-app review flow is requested so the
    // nudge fires at most once. Neither touches the encrypted vault.
    var launchCount: Int
        get() = prefs.getInt(KEY_LAUNCH_COUNT, 0)
        set(value) { prefs.edit().putInt(KEY_LAUNCH_COUNT, value).apply() }

    var reviewPromptShown: Boolean
        get() = prefs.getBoolean(KEY_REVIEW_PROMPT_SHOWN, false)
        set(value) { prefs.edit().putBoolean(KEY_REVIEW_PROMPT_SHOWN, value).apply() }

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
    private val dataFile: File get() = File(vaultDir, "vault.dat")

    // The in-memory vault key. Non-null only while unlocked.
    private var vk: ByteArray? = null

    // MARK: - Provisioning state

    /** True once a vault has been created on this device (key blob present). */
    fun isProvisioned(): Boolean = keyFile.exists() || plainKeyFile.exists()

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

    /** A copy of the in-memory vault key, or null if locked. Used to re-wrap under a different KEK. */
    fun snapshotVaultKey(): ByteArray? = vk?.copyOf()

    // MARK: - Lifecycle

    /** Bootstrap a fresh, empty vault with a freshly-generated VK and persist it. */
    fun bootstrap(vaultKey: ByteArray) {
        vk = vaultKey
        identities.clear()
        recipients.clear()
        notes.clear()
        persist()
        isUnlocked = true
    }

    /** Unlock an existing vault: open vault.dat with the (already-unwrapped) VK. */
    fun unlock(vaultKey: ByteArray) {
        val snapshot = loadSnapshot(vaultKey)
        vk = vaultKey
        identities.clear(); identities.addAll(snapshot.identities)
        recipients.clear(); recipients.addAll(snapshot.recipients)
        notes.clear(); notes.addAll(snapshot.notes)
        isUnlocked = true
    }

    /** Drop the VK and all decrypted state from memory (called on background). */
    fun lock() {
        vk?.fill(0)
        vk = null
        identities.clear()
        recipients.clear()
        notes.clear()
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
        identities.removeAll { it.id == id }
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

    fun deleteRecipient(id: String) {
        recipients.removeAll { it.id == id }
        persist()
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

    // MARK: - Reset

    /** Destroy the on-disk vault. The KEK is deleted by the caller (VaultViewModel). */
    fun reset() {
        lock()
        keyFile.delete()
        plainKeyFile.delete()
        dataFile.delete()
        prefs.edit()
            .remove(KEY_ACTIVE_IDENTITY)
            .remove(KEY_ONBOARDED)
            .apply()
    }

    // MARK: - Persistence

    private fun persist() {
        val key = vk ?: error("Vault is locked")
        val snapshot = VaultSnapshot(
            identities = identities.toList(),
            recipients = recipients.toList(),
            notes = notes.toList()
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
        const val KEY_ACTIVE_IDENTITY = "activeIdentityId"
        const val KEY_BIOMETRIC_ENABLED = "biometricEnabled"
        const val KEY_ENCRYPT_TO_SELF = "encryptToSelfDefault"
        const val KEY_ONBOARDED = "hasCompletedOnboarding"
        const val KEY_LAUNCH_COUNT = "launchCount"
        const val KEY_REVIEW_PROMPT_SHOWN = "reviewPromptShown"
    }
}
