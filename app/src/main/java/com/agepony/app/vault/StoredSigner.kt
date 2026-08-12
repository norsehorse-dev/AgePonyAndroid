package com.agepony.app.vault

import com.agepony.core.ssh.AllowedSigner
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.security.MessageDigest
import java.util.Base64
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
    val createdAt: Long
) {
    /** OpenSSH-style fingerprint (`SHA256:...`) for display. */
    fun fingerprint(): String = sshFingerprint(b64d(publicKeyWireB64))

    /** One allowed_signers entry for this signer, for export. */
    fun toAllowedSigner(namespaceRestricted: Boolean = false): AllowedSigner = AllowedSigner(
        principals = listOf(name),
        options = if (namespaceRestricted) {
            "namespaces=\"${com.agepony.core.signing.SSHSig.NAMESPACE_AGEPONY}\""
        } else {
            null
        },
        keyType = keyType,
        keyBase64 = publicKeyWireB64,
        comment = comment,
    )

    companion object {
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
