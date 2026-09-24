package com.agepony.app.vault

import com.agepony.core.portability.KeyTransfer
import com.agepony.core.portability.PaperBackup
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.P256Recipient
import com.agepony.core.recipients.YubiKeyStub
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonObject
import java.time.Instant
import java.util.UUID

//
// 5.0.0: moving keys between devices and on/off paper. The wire formats live in agepony-core
// (KeyTransfer, PaperBackup); this file decides what AgePony puts in them and how it merges what
// comes back into the vault.
//

/** The `agepony.json` entry of a key transfer. Full-fidelity vault records. */
@Serializable
data class TransferMetadata(
    val format: String = KeyTransfer.FORMAT_LINE,
    val app: String = "AgePony Android",
    val identities: List<StoredIdentity> = emptyList(),
    val recipients: List<StoredRecipient> = emptyList(),
    val signers: List<StoredSigner> = emptyList(),
)

object KeyPortability {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /** Identity kinds that can leave this device. Keystore-bound keys never can. */
    fun isTransferable(identity: StoredIdentity): Boolean = !identity.type.isDeviceBound

    /** Identity kinds a paper backup supports: the age keys, whose secret is a short Bech32 string. */
    fun isPaperBackable(identity: StoredIdentity): Boolean =
        identity.type == StoredIdentityType.X25519 || identity.type == StoredIdentityType.MLKEM768X25519

    /** The age identity-file line for an age identity, or null for other kinds. */
    fun identityLine(identity: StoredIdentity): KeyTransfer.IdentityLine? = when (identity.type) {
        StoredIdentityType.X25519 -> {
            val id = X25519Identity(b64d(identity.privateKeyB64))
            KeyTransfer.IdentityLine(identity.name, X25519Recipient(id.publicKey).toBech32(), id.toBech32(), iso(identity.createdAt))
        }
        StoredIdentityType.MLKEM768X25519 -> {
            val id = HybridIdentity(b64d(identity.privateKeyB64))
            KeyTransfer.IdentityLine(identity.name, id.recipient().toBech32(), id.toBech32(), iso(identity.createdAt))
        }
        // A plugin identity line; `age -i` uses it with age-plugin-yubikey installed.
        StoredIdentityType.YUBIKEY_PIV -> {
            val pub = b64d(identity.publicKeyB64)
            KeyTransfer.IdentityLine(
                identity.name,
                P256Recipient(pub).toBech32(),
                YubiKeyStub.fromBytes(b64d(identity.privateKeyB64)).encode(),
                iso(identity.createdAt),
            )
        }
        else -> null
    }

    fun buildBundle(
        identities: List<StoredIdentity>,
        recipients: List<StoredRecipient>,
        signers: List<StoredSigner>,
    ): KeyTransfer.Bundle {
        val movable = identities.filter(::isTransferable)
        val identitiesTxt = KeyTransfer.identityFile(movable.mapNotNull(::identityLine))
        val ssh = movable.filter { it.type == StoredIdentityType.SSH_RSA }
            .associate { it.name to String(b64d(it.privateKeyB64), Charsets.UTF_8) }
        val meta = TransferMetadata(identities = movable, recipients = recipients, signers = signers)
        return KeyTransfer.Bundle(identitiesTxt, ssh, json.encodeToString(TransferMetadata.serializer(), meta))
    }

    /** What an incoming transfer holds, before anything is written. */
    class Incoming(
        val identities: List<StoredIdentity>,
        val recipients: List<StoredRecipient>,
        val signers: List<StoredSigner>,
    )

    /**
     * Read what a transfer holds. Each record is decoded on its own, so one entry this version
     * doesn't understand (a newer key type, say) is skipped instead of discarding the rest.
     * Identities whose private key doesn't produce their stated public key are dropped.
     */
    fun readBundle(bundle: KeyTransfer.Bundle): Incoming {
        val root = runCatching { json.parseToJsonElement(bundle.metadataJson).jsonObject }.getOrNull()
        if (root != null) {
            fun <T> each(key: String, s: kotlinx.serialization.KSerializer<T>): List<T> =
                (root[key] as? JsonArray).orEmpty().mapNotNull { runCatching { json.decodeFromJsonElement(s, it) }.getOrNull() }
            val ids = each("identities", StoredIdentity.serializer()).filter { isTransferable(it) && isConsistent(it) }
            return Incoming(ids, each("recipients", StoredRecipient.serializer()), each("signers", StoredSigner.serializer()))
        }
        // No AgePony metadata (a hand-built transfer): use the plain identity file and SSH keys.
        val ssh = bundle.sshKeys.mapNotNull { (name, pem) ->
            runCatching { IdentityImport.fromOpenSSHPem(pem, null, name) }.getOrNull()
        }
        return Incoming(identitiesFromText(bundle.identitiesTxt) + ssh, emptyList(), emptyList())
    }

    /** For age keys, the stored public key must be the one the private key gives. */
    private fun isConsistent(identity: StoredIdentity): Boolean = runCatching {
        when (identity.type) {
            StoredIdentityType.X25519 ->
                X25519Identity(b64d(identity.privateKeyB64)).publicKey.contentEquals(b64d(identity.publicKeyB64))
            StoredIdentityType.MLKEM768X25519 ->
                HybridIdentity(b64d(identity.privateKeyB64)).publicKey.contentEquals(b64d(identity.publicKeyB64))
            else -> identity.publicKeyB64.isNotEmpty()
        }
    }.getOrDefault(false)

    /** Parse the age secret keys in an identity file into vault records, keeping `# name:` labels. */
    fun identitiesFromText(identityFile: String): List<StoredIdentity> {
        val names = PaperBackup.namesByKey(identityFile)
        return PaperBackup.secretKeys(identityFile).mapIndexedNotNull { i, secret ->
            runCatching {
                IdentityImport.fromAgeSecretKey(secret, names[secret] ?: "restored key ${i + 1}")
            }.getOrNull()
        }
    }

    class ImportSummary(val identitiesAdded: Int, val recipientsAdded: Int, val signersAdded: Int, val skipped: Int)

    /** Merge [incoming] into [vault], skipping anything already present (same type and public key). */
    fun import(vault: Vault, incoming: Incoming): ImportSummary {
        var skipped = 0
        var ids = 0
        for (identity in incoming.identities) {
            val known = vault.identities.asSequence() + vault.trashedIdentities.asSequence().map { it.identity }
            if (!isTransferable(identity) ||
                known.any { it.type == identity.type && it.publicKeyB64 == identity.publicKeyB64 }
            ) { skipped++; continue }
            vault.addIdentity(identity.copy(id = UUID.randomUUID().toString(), keystoreAlias = null))
            ids++
        }
        var recips = 0
        for (r in incoming.recipients) {
            if (vault.recipients.any { it.type == r.type && it.publicKeyB64 == r.publicKeyB64 }) { skipped++; continue }
            vault.addRecipient(r.copy(id = UUID.randomUUID().toString()))
            recips++
        }
        var signers = 0
        for (s in incoming.signers) {
            if (vault.addSigner(s.copy(id = UUID.randomUUID().toString()))) signers++ else skipped++
        }
        return ImportSummary(ids, recips, signers, skipped)
    }

    private fun iso(millis: Long): String = Instant.ofEpochMilli(millis).toString()
}
