package com.agepony.app.vault

import com.agepony.core.archive.SignedBundle
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigVerifier
import com.agepony.core.signing.SignatureStanza
import com.agepony.core.ssh.AllowedSigner
import com.agepony.core.ssh.AllowedSignerOptions
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Base64
import java.util.Locale
import java.util.UUID

//
// A trusted signer: an SSH public key the user recognizes, with a name
// (principal). When verifying a detached signature, FileVerifier matches the
// signature's key against this list to put a name on the signer. The list
// round-trips to and from the OpenSSH `allowed_signers` file format
// (agepony-core's AllowedSigners), so a list built in the app drops straight
// onto a machine's command line and back.
//
// Kept in its own file, mirroring iOS's Vault/StoredSigner.swift, so
// VaultModels.kt stays untouched apart from the snapshot field.
//

@Serializable
enum class StoredSignerSource {
    @SerialName("pasteKey") PASTE_KEY,
    @SerialName("importAllowedSigners") IMPORT_ALLOWED_SIGNERS,
    @SerialName("fromRecipient") FROM_RECIPIENT,
    /** "Add this unknown signer" from the verify badge. */
    @SerialName("fromVerification") FROM_VERIFICATION
}

@Serializable
data class StoredSigner(
    val id: String,
    /** Principal / display name (e.g. "alice@example.com"). */
    val name: String,
    /** Key algorithm, e.g. "ssh-ed25519". */
    val keyType: String,
    /**
     * The SSH public-key wire blob, Base64 — the exact bytes carried in a
     * signature, so matching is a direct equality check.
     */
    val publicKeyWireB64: String,
    val comment: String? = null,
    val source: StoredSignerSource,
    val createdAt: Long,
    /**
     * The allowed_signers options field exactly as imported (namespaces=, valid-after=,
     * valid-before=, no-touch-required, ...), or null. Kept verbatim so export round-trips
     * and so verification can enforce the restrictions instead of silently dropping them
     * (audit L-6). Null for signers added in the app and for everything stored by 5.0.0.
     */
    val options: String? = null,
) {
    /** OpenSSH-style fingerprint (`SHA256:...`) for display. */
    fun fingerprint(): String = sshFingerprint(b64d(publicKeyWireB64))

    /** One allowed_signers entry for this signer, for export. */
    fun toAllowedSigner(namespaceRestricted: Boolean = false): AllowedSigner = AllowedSigner(
        principals = listOf(name),
        // Imported restrictions win and are written back unchanged (audit L-6).
        options = options ?: if (namespaceRestricted) {
            "namespaces=\"${SSHSig.NAMESPACE_AGEPONY}\""
        } else {
            null
        },
        keyType = keyType,
        keyBase64 = publicKeyWireB64,
        comment = comment,
    )

    /** The imported restrictions in plain words, for the signer's row (audit L-6). Empty without options. */
    fun restrictions(zone: ZoneId = ZoneId.systemDefault()): List<String> = describeOptions(options, zone)

    /**
     * Why AgePony can't honor this signer's options (cert-authority, an option it doesn't know,
     * a malformed field), or null. Such a signer is shown but never imported (audit L-6).
     */
    fun unenforceableReason(): String? = unenforceableReasonFor(options)

    /** Why this signer shouldn't be trusted by default (expired, not for AgePony), or null (audit L-6). */
    fun agePonyWarning(now: Instant = Instant.now(), zone: ZoneId = ZoneId.systemDefault()): String? =
        agePonyWarningFor(options, now, zone)

    /**
     * The imported restrictions applied to a verified signature from this signer's key (audit
     * L-6): the namespace, the valid-after/valid-before window and the security-key flags, as
     * ssh-keygen -Y verify applies them. The caller has already matched the key.
     */
    fun accepts(result: SSHSigVerifier.Result, at: Instant = Instant.now()): Boolean =
        toAllowedSigner().accepts(result, at)

    companion object {
        /** Every namespace AgePony signs under: detached signatures, sig stanzas, bundles. */
        val AGEPONY_NAMESPACES: List<String> = listOf(
            SSHSig.NAMESPACE_AGEPONY,
            SignatureStanza.NAMESPACE_V2,
            SignedBundle.NAMESPACE_V2,
        )

        /** An allowed_signers options field in plain words, one restriction per item. */
        fun describeOptions(raw: String?, zone: ZoneId = ZoneId.systemDefault()): List<String> {
            if (raw.isNullOrBlank()) return emptyList()
            val o = AllowedSignerOptions.parse(raw, zone)
            val out = mutableListOf<String>()
            if (o.certAuthority) out += "certificate authority (signs certificates, not files)"
            o.namespaces?.let { ns ->
                val names = ns.split(',').joinToString(", ") { if (it.startsWith("!")) "not ${it.drop(1)}" else it }
                out += "$names only"
            }
            o.validAfter?.let { out += "valid from ${humanTime(it, zone)}" }
            o.validBefore?.let { out += "valid until ${humanTime(it, zone)}" }
            if (o.noTouchRequired) out += "security key touch not required"
            if (o.verifyRequired) out += "security key PIN or fingerprint required"
            o.unknown.forEach { out += "unknown option: $it" }
            o.error?.let { out += "unreadable options: $it" }
            return out
        }

        /** See [StoredSigner.unenforceableReason]. */
        fun unenforceableReasonFor(raw: String?): String? {
            if (raw.isNullOrBlank()) return null
            val o = AllowedSignerOptions.parse(raw, ZoneOffset.UTC)
            return when {
                o.certAuthority ->
                    "A certificate authority key. AgePony doesn't support SSH certificates, so it can't enforce this entry."
                o.error != null ->
                    "Its options can't be read (${o.error}), so AgePony can't enforce them."
                o.unknown.isNotEmpty() ->
                    "It has options AgePony doesn't understand (${o.unknown.joinToString(", ")}), so AgePony can't enforce them."
                else -> null
            }
        }

        /** See [StoredSigner.agePonyWarning]. Null for an entry [unenforceableReason] refuses. */
        fun agePonyWarningFor(raw: String?, now: Instant = Instant.now(), zone: ZoneId = ZoneId.systemDefault()): String? {
            if (raw.isNullOrBlank() || unenforceableReasonFor(raw) != null) return null
            val o = AllowedSignerOptions.parse(raw, zone)
            o.validBefore?.let { if (now.isAfter(it)) return "Expired on ${humanTime(it, zone)}." }
            o.validAfter?.let { if (now.isBefore(it)) return "Not valid until ${humanTime(it, zone)}." }
            // The namespace test on its own, at a moment inside the validity window.
            val probe = o.validAfter ?: o.validBefore ?: now
            if (AGEPONY_NAMESPACES.none { o.permits(it, probe, agePonyFamily = true) }) {
                return "Not allowed to sign AgePony files (${o.namespaces} only)."
            }
            return null
        }

        /** A date, with the time only when it isn't midnight. */
        private fun humanTime(at: Instant, zone: ZoneId): String {
            val t = at.atZone(zone).toLocalDateTime()
            return if (t.hour == 0 && t.minute == 0 && t.second == 0) {
                t.toLocalDate().toString()
            } else {
                String.format(Locale.US, "%s %02d:%02d", t.toLocalDate(), t.hour, t.minute)
            }
        }

        /**
         * A StoredSigner from one parsed allowed_signers entry. The entry's first
         * principal becomes the name; entries with several principals still import as
         * one signer, since the key (not the principal list) is what verification
         * matches on. Returns null if the entry's base64 doesn't decode.
         */
        fun fromAllowedSigner(entry: AllowedSigner, source: StoredSignerSource): StoredSigner? {
            val principal = entry.principals.firstOrNull() ?: return null
            entry.publicKeyWire ?: return null
            return StoredSigner(
                id = UUID.randomUUID().toString(),
                name = principal,
                keyType = entry.keyType,
                publicKeyWireB64 = entry.keyBase64,
                comment = entry.comment,
                source = source,
                createdAt = System.currentTimeMillis(),
                options = entry.options?.takeIf { it.isNotBlank() },
            )
        }

        /**
         * OpenSSH-style SHA256 fingerprint of a public-key wire blob, rendered exactly
         * as `ssh-keygen -lf` prints it: unpadded Base64. Both platforms print identical
         * strings for the same key.
         */
        fun sshFingerprint(wireBlob: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(wireBlob)
            return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest)
        }
    }
}

/**
 * One allowed_signers entry as the import preview shows it (audit L-6). An entry AgePony can't
 * enforce ([blocked]) is listed but never imported; one that is expired, not yet valid or not
 * allowed to sign AgePony files ([warning]) is listed unticked, for the user to decide.
 */
class AllowedSignerReview(
    val entry: AllowedSigner,
    /** What would be stored, or null when the entry's key can't be read. */
    val signer: StoredSigner?,
    /** The key is already on the signers list (import would skip it). */
    val alreadyPresent: Boolean,
    val blocked: String?,
    val warning: String?,
) {
    val restrictions: List<String> get() = StoredSigner.describeOptions(entry.options)
    val importable: Boolean get() = signer != null && !alreadyPresent && blocked == null
    val checkedByDefault: Boolean get() = importable && warning == null

    companion object {
        fun of(
            entry: AllowedSigner,
            source: StoredSignerSource,
            known: List<StoredSigner>,
            now: Instant = Instant.now(),
        ): AllowedSignerReview {
            val signer = StoredSigner.fromAllowedSigner(entry, source)
            val present = signer != null && known.any { it.publicKeyWireB64 == signer.publicKeyWireB64 }
            val blocked = if (signer == null) "Its key can't be read." else StoredSigner.unenforceableReasonFor(entry.options)
            return AllowedSignerReview(entry, signer, present, blocked, StoredSigner.agePonyWarningFor(entry.options, now))
        }
    }
}
