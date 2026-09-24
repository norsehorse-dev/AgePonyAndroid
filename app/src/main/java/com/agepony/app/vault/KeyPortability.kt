package com.agepony.app.vault

import com.agepony.core.crypto.P256Curve
import com.agepony.core.portability.KeyTransfer
import com.agepony.core.portability.PaperBackup
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.P256Recipient
import com.agepony.core.recipients.SSHEd25519Identity
import com.agepony.core.recipients.YubiKeyStub
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.signing.SSHSig
import com.agepony.core.ssh.Ed25519Conversion
import com.agepony.core.ssh.OpenSSHPrivateKey
import com.agepony.core.ssh.OpenSSHPublicKey
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
     * Identities whose private key doesn't produce their stated public key are dropped, and so
     * are recipients and signers whose key doesn't parse.
     */
    fun readBundle(bundle: KeyTransfer.Bundle): Incoming {
        val root = runCatching { json.parseToJsonElement(bundle.metadataJson).jsonObject }.getOrNull()
        if (root != null) {
            fun <T> each(key: String, s: kotlinx.serialization.KSerializer<T>): List<T> =
                (root[key] as? JsonArray).orEmpty().mapNotNull { runCatching { json.decodeFromJsonElement(s, it) }.getOrNull() }
            val ids = each("identities", StoredIdentity.serializer()).filter { isTransferable(it) && isConsistent(it) }
            val recips = each("recipients", StoredRecipient.serializer()).filter { r -> runCatching { r.toAgeRecipient() }.isSuccess }
            val signers = each("signers", StoredSigner.serializer()).filter(::signerKeyReadable)
            return Incoming(ids, recips, signers)
        }
        // No AgePony metadata (a hand-built transfer): use the plain identity file and SSH keys.
        val ssh = bundle.sshKeys.mapNotNull { (name, pem) ->
            runCatching { IdentityImport.fromOpenSSHPem(pem, null, name) }.getOrNull()
        }
        return Incoming(identitiesFromText(bundle.identitiesTxt) + ssh, emptyList(), emptyList())
    }

    /**
     * The stored public key must be the one the private material gives (audit AS-2): otherwise
     * a transfer could pair someone else's public key with a private key, and the vault would
     * encrypt to (or trust signatures from) a key the user doesn't hold.
     */
    internal fun isConsistent(identity: StoredIdentity): Boolean = runCatching {
        when (identity.type) {
            StoredIdentityType.X25519 ->
                X25519Identity(b64d(identity.privateKeyB64)).publicKey.contentEquals(b64d(identity.publicKeyB64))
            StoredIdentityType.MLKEM768X25519 ->
                HybridIdentity(b64d(identity.privateKeyB64)).publicKey.contentEquals(b64d(identity.publicKeyB64))
            // The 32-byte seed derives the public key; stored is the raw 32-byte point.
            StoredIdentityType.SSH_ED25519 ->
                SSHEd25519Identity(b64d(identity.privateKeyB64)).edPublicKey.contentEquals(b64d(identity.publicKeyB64))
            // The PEM parser checks the key itself (p*q = n, e*d = 1 mod lambda, inner and outer
            // public halves agree); this ties it to the stored `ssh-rsa` line.
            StoredIdentityType.SSH_RSA -> {
                val priv = OpenSSHPrivateKey.parse(String(b64d(identity.privateKeyB64), Charsets.UTF_8))
                val pub = OpenSSHPublicKey.parse(String(b64d(identity.publicKeyB64), Charsets.UTF_8))
                priv is OpenSSHPrivateKey.RSA && pub is OpenSSHPublicKey.RSA &&
                    priv.n == pub.modulus && priv.e == pub.exponent
            }
            // No secret travels: the stub points at a YubiKey slot. Its tag is a hash of the
            // slot's public key, so the stored key must be a valid P-256 point with that hash.
            StoredIdentityType.YUBIKEY_PIV -> {
                val pub = b64d(identity.publicKeyB64)
                P256Recipient(pub)
                YubiKeyStub.fromBytes(b64d(identity.privateKeyB64)).matchesKey(pub)
            }
            // A security key's credential id is opaque, so nothing ties it to the public key
            // without the key itself. What can be checked is that the public key is a well-formed
            // sk key of the stated type on a valid point; the preview says the rest can't be.
            StoredIdentityType.SK_ED25519, StoredIdentityType.SK_ECDSA_P256 ->
                b64d(identity.privateKeyB64).size in 1..MAX_CREDENTIAL_ID &&
                    skPublicWireIsWellFormed(identity.type, b64d(identity.publicKeyB64))
            // Device-bound keys never travel (isTransferable filters them first).
            StoredIdentityType.HARDWARE_KEY, StoredIdentityType.HARDWARE_TAG, StoredIdentityType.HARDWARE_TAG_PQ -> false
        }
    }.getOrDefault(false)

    /** CTAP2 caps credential ids at 1023 bytes. */
    private const val MAX_CREDENTIAL_ID = 1023

    /** The sk public wire parses as [type], its point is valid, and it re-encodes to the same bytes. */
    private fun skPublicWireIsWellFormed(type: StoredIdentityType, wire: ByteArray): Boolean {
        val buf = SSHSig.reader(wire)
        val keyType = String(SSHSig.readString(buf, "type"), Charsets.US_ASCII)
        return when (type) {
            StoredIdentityType.SK_ED25519 -> {
                if (keyType != SSHSig.KEY_SK_ED25519) return false
                val pub = SSHSig.readString(buf, "sk-ed25519 pubkey")
                val app = String(SSHSig.readString(buf, "application"), Charsets.UTF_8)
                Ed25519Conversion.publicKeyToX25519(pub) // throws for a point off the curve
                SSHSig.skEd25519PublicWire(pub, app).contentEquals(wire)
            }
            StoredIdentityType.SK_ECDSA_P256 -> {
                if (keyType != SSHSig.KEY_SK_ECDSA_P256) return false
                SSHSig.readString(buf, "curve")
                val q = SSHSig.readString(buf, "sk-ecdsa point")
                val app = String(SSHSig.readString(buf, "application"), Charsets.UTF_8)
                P256Curve.toUncompressed(q) // throws for a point off the curve
                SSHSig.skEcdsaP256PublicWire(q, app).contentEquals(wire)
            }
            else -> false
        }
    }

    /** A signer's stored wire decodes and starts with its stated key type. */
    private fun signerKeyReadable(signer: StoredSigner): Boolean = runCatching {
        val wireType = String(SSHSig.readString(SSHSig.reader(b64d(signer.publicKeyWireB64)), "type"), Charsets.US_ASCII)
        wireType == signer.keyType || (wireType == SSHSig.KEY_RSA && signer.keyType.startsWith("rsa-sha2-"))
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

    /**
     * Merge [incoming] into [vault], skipping anything already present (same type and public key).
     * The caller passes only the entries the user chose; signers in particular must be ones the
     * user ticked (audit M-6). Imported identities never become the active identity unless
     * [activate] says so: a key that arrived from elsewhere must not quietly turn into the
     * encrypt-to-self key. Signers whose options AgePony can't enforce are skipped (audit L-6).
     */
    fun import(vault: Vault, incoming: Incoming, activate: Boolean = false): ImportSummary {
        var skipped = 0
        var ids = 0
        for (identity in incoming.identities) {
            if (!isTransferable(identity) || isKnown(vault, identity)) { skipped++; continue }
            vault.addIdentity(identity.copy(id = UUID.randomUUID().toString(), keystoreAlias = null), activate = activate)
            ids++
        }
        var recips = 0
        for (r in incoming.recipients) {
            if (isKnown(vault, r)) { skipped++; continue }
            vault.addRecipient(r.copy(id = UUID.randomUUID().toString()))
            recips++
        }
        var signers = 0
        for (s in incoming.signers) {
            if (s.unenforceableReason() != null) { skipped++; continue }
            if (vault.addSigner(s.copy(id = UUID.randomUUID().toString()))) signers++ else skipped++
        }
        return ImportSummary(ids, recips, signers, skipped)
    }

    // ---- Receive preview (audit M-6): what each entry is, and how it relates to the vault ----

    /** Already in the vault (or its recycle bin) with the same type and key: import skips it. */
    fun isKnown(vault: Vault, identity: StoredIdentity): Boolean {
        val known = vault.identities.asSequence() + vault.trashedIdentities.asSequence().map { it.identity }
        return known.any { it.type == identity.type && it.publicKeyB64 == identity.publicKeyB64 }
    }

    fun isKnown(vault: Vault, recipient: StoredRecipient): Boolean =
        vault.recipients.any { it.type == recipient.type && it.publicKeyB64 == recipient.publicKeyB64 }

    fun isKnown(vault: Vault, signer: StoredSigner): Boolean =
        vault.signers.any { it.publicKeyWireB64 == signer.publicKeyWireB64 }

    /**
     * An existing entry with the same name but a different key, or null. Two keys under one name
     * is how a planted key passes for a real one, so the preview warns.
     */
    fun nameClash(vault: Vault, identity: StoredIdentity): StoredIdentity? =
        if (isKnown(vault, identity)) null else vault.identities.firstOrNull { sameName(it.name, identity.name) }

    fun nameClash(vault: Vault, recipient: StoredRecipient): StoredRecipient? =
        if (isKnown(vault, recipient)) null else vault.recipients.firstOrNull { sameName(it.name, recipient.name) }

    /** A signer's name is what a verified file shows, so it may not reuse a signer's or an identity's name. */
    fun nameClash(vault: Vault, signer: StoredSigner): String? {
        if (isKnown(vault, signer)) return null
        vault.signers.firstOrNull { sameName(it.name, signer.name) }?.let { return "a trusted signer" }
        vault.identities.firstOrNull { sameName(it.name, signer.name) }?.let { return "one of your identities" }
        return null
    }

    private fun sameName(a: String, b: String): Boolean = a.trim().equals(b.trim(), ignoreCase = true)

    /** The key as the preview shows it: `SHA256:` fingerprint for SSH keys, the shortened key string otherwise. */
    fun keySummary(identity: StoredIdentity): String = runCatching {
        when (identity.type) {
            StoredIdentityType.SSH_ED25519 ->
                StoredSigner.sshFingerprint(SSHSig.ed25519PublicWire(b64d(identity.publicKeyB64)))
            StoredIdentityType.SSH_RSA -> sshLineFingerprint(String(b64d(identity.publicKeyB64), Charsets.UTF_8))
            StoredIdentityType.SK_ED25519, StoredIdentityType.SK_ECDSA_P256 ->
                StoredSigner.sshFingerprint(b64d(identity.publicKeyB64))
            else -> shorten(identity.publicDisplayString())
        }
    }.getOrDefault("(unreadable key)")

    fun keySummary(recipient: StoredRecipient): String = runCatching {
        when (recipient.type) {
            StoredRecipientType.SSH_ED25519 ->
                StoredSigner.sshFingerprint(SSHSig.ed25519PublicWire(b64d(recipient.publicKeyB64)))
            StoredRecipientType.SSH_RSA -> sshLineFingerprint(String(b64d(recipient.publicKeyB64), Charsets.UTF_8))
            else -> shorten(recipient.publicDisplayString())
        }
    }.getOrDefault("(unreadable key)")

    fun typeLabel(t: StoredIdentityType): String = when (t) {
        StoredIdentityType.X25519 -> "age X25519"
        StoredIdentityType.MLKEM768X25519 -> "Quantum-safe (ML-KEM-768 + X25519)"
        StoredIdentityType.SSH_ED25519 -> "SSH Ed25519"
        StoredIdentityType.SSH_RSA -> "SSH RSA"
        StoredIdentityType.HARDWARE_KEY -> "Hardware key"
        StoredIdentityType.SK_ED25519 -> "Security key (Ed25519)"
        StoredIdentityType.SK_ECDSA_P256 -> "Security key (P-256)"
        StoredIdentityType.HARDWARE_TAG -> "Hardware key (age1tag)"
        StoredIdentityType.HARDWARE_TAG_PQ -> "Hardware key, quantum-safe (age1tagpq)"
        StoredIdentityType.YUBIKEY_PIV -> "YubiKey (PIV)"
    }

    fun typeLabel(t: StoredRecipientType): String = when (t) {
        StoredRecipientType.X25519 -> "age X25519"
        StoredRecipientType.MLKEM768X25519 -> "Quantum-safe (ML-KEM-768 + X25519)"
        StoredRecipientType.SSH_ED25519 -> "SSH Ed25519"
        StoredRecipientType.SSH_RSA -> "SSH RSA"
        StoredRecipientType.YUBIKEY_P256 -> "YubiKey (P-256)"
        StoredRecipientType.TAG -> "Hardware key (age1tag)"
        StoredRecipientType.TAG_PQ -> "Hardware key, quantum-safe (age1tagpq)"
    }

    /**
     * A note for identities whose public key can't be fully checked here (audit AS-2): for a
     * security key or a YubiKey the private half stays on the device, so only the key itself can
     * prove the pairing. Null for the rest, which [isConsistent] checks in full.
     */
    fun unverifiableNote(identity: StoredIdentity): String? = when (identity.type) {
        StoredIdentityType.SK_ED25519, StoredIdentityType.SK_ECDSA_P256 ->
            "Lives on a security key: its public key can't be checked without that key."
        StoredIdentityType.YUBIKEY_PIV ->
            "Lives on a YubiKey: decrypting with it needs that YubiKey."
        else -> null
    }

    private fun sshLineFingerprint(line: String): String {
        val parts = line.trim().split(Regex("\\s+"))
        return StoredSigner.sshFingerprint(b64d(parts[1]))
    }

    private fun shorten(s: String): String = if (s.length <= 28) s else "${s.take(16)}…${s.takeLast(8)}"

    private fun iso(millis: Long): String = Instant.ofEpochMilli(millis).toString()
}
