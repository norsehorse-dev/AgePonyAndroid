package com.agepony.app.signing

import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.StoredSigner
import com.agepony.app.vault.b64d
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigVerifier

/**
 * Verifies a detached SSHSIG over a file and decides how much to trust the signer.
 *
 * Cryptographic validity comes from [SSHSigVerifier]. On top of that, the signer's public
 * key is matched against the vault: the user's own identities first (so a signature made
 * with your own key carries your name for it, not a signer-list principal), then the
 * trusted-signers list. A match is [Trust.TRUSTED] (with the matched name), a
 * cryptographically valid signature from an unknown key is [Trust.VALID_UNKNOWN], and a
 * failed signature is [Trust.INVALID] with a reason.
 */
class FileVerifier {
    enum class Trust { TRUSTED, VALID_UNKNOWN, INVALID }

    class Result(
        val trust: Trust,
        val keyType: String,
        val signerName: String?,
        val reason: String?,
        /**
         * The signer's public-key wire blob, present when the signature verified. This is
         * what "add this signer" persists, so the added entry matches future signatures
         * by exactly the bytes this one carried.
         */
        val signerPublicWire: ByteArray? = null,
    )

    fun verify(
        signature: ByteArray,
        message: ByteArray,
        knownIdentities: List<StoredIdentity>,
        knownSigners: List<StoredSigner> = emptyList(),
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
    ): Result = verifyHashed(signature, knownIdentities, knownSigners, namespace) { alg ->
        SSHSig.hashMessage(message, alg)
    }

    /**
     * The same checks as [verify] for a message too large to hold: [messageHashFor] supplies the
     * message hash under the envelope's hash algorithm, which a streaming decrypt computes while
     * the payload goes past on its way to disk.
     */
    fun verifyHashed(
        signature: ByteArray,
        knownIdentities: List<StoredIdentity>,
        knownSigners: List<StoredSigner> = emptyList(),
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        messageHashFor: (String) -> ByteArray,
    ): Result {
        val result = SSHSigVerifier.verifyHashed(signature, namespace, messageHashFor)
        if (!result.valid) {
            return Result(Trust.INVALID, result.keyType, null, result.reason)
        }
        val ownMatch = knownIdentities.firstOrNull { identity ->
            publicWireOf(identity)?.contentEquals(result.signerPublicWire) == true
        }
        if (ownMatch != null) {
            return Result(Trust.TRUSTED, result.keyType, ownMatch.name, null, result.signerPublicWire)
        }
        val signerMatch = knownSigners.firstOrNull { signer ->
            b64dOrNull(signer.publicKeyWireB64)?.contentEquals(result.signerPublicWire) == true
        }
        if (signerMatch != null) {
            return Result(Trust.TRUSTED, result.keyType, signerMatch.name, null, result.signerPublicWire)
        }
        return Result(Trust.VALID_UNKNOWN, result.keyType, null, null, result.signerPublicWire)
    }

    /** The SSHSIG public-key wire for an identity, used to match the envelope's signer. */
    private fun publicWireOf(identity: StoredIdentity): ByteArray? = when (identity.type) {
        StoredIdentityType.SSH_ED25519 -> SSHSig.ed25519PublicWire(b64d(identity.publicKeyB64))
        // The stored `ssh-rsa BASE64 [comment]` line's base64 field IS the wire blob.
        StoredIdentityType.SSH_RSA -> {
            val parts = String(b64d(identity.publicKeyB64), Charsets.UTF_8)
                .trim().split(' ').filter { it.isNotEmpty() }
            if (parts.size >= 2) b64dOrNull(parts[1]) else null
        }
        // hardware and security-key identities already store the full SSHSIG public wire
        StoredIdentityType.HARDWARE_KEY -> b64d(identity.publicKeyB64)
        StoredIdentityType.SK_ED25519 -> b64d(identity.publicKeyB64)
        StoredIdentityType.SK_ECDSA_P256 -> b64d(identity.publicKeyB64)
        StoredIdentityType.X25519 -> null
        // Encryption-only; never a signer.
        StoredIdentityType.MLKEM768X25519 -> null
    }

    private fun b64dOrNull(s: String): ByteArray? = try {
        b64d(s)
    } catch (e: IllegalArgumentException) {
        null
    }

    companion object {
        /** OpenSSH-style SHA256 fingerprint for display; see [StoredSigner.sshFingerprint]. */
        fun sshFingerprint(wireBlob: ByteArray): String = StoredSigner.sshFingerprint(wireBlob)
    }
}
