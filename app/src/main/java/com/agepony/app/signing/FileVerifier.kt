package com.agepony.app.signing

import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.b64d
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigVerifier

/**
 * Verifies a detached SSHSIG over a file and decides how much to trust the signer.
 *
 * Cryptographic validity comes from [SSHSigVerifier]. On top of that, the signer's public
 * key is matched against the vault's known identities: a match is [Trust.TRUSTED] (with the
 * identity name), a cryptographically valid signature from an unknown key is
 * [Trust.VALID_UNKNOWN], and a failed signature is [Trust.INVALID] with a reason.
 */
class FileVerifier {
    enum class Trust { TRUSTED, VALID_UNKNOWN, INVALID }

    class Result(
        val trust: Trust,
        val keyType: String,
        val signerName: String?,
        val reason: String?,
    )

    fun verify(
        signature: ByteArray,
        message: ByteArray,
        knownIdentities: List<StoredIdentity>,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
    ): Result {
        val result = SSHSigVerifier.verify(signature, message, namespace)
        if (!result.valid) {
            return Result(Trust.INVALID, result.keyType, null, result.reason)
        }
        val match = knownIdentities.firstOrNull { identity ->
            publicWireOf(identity)?.contentEquals(result.signerPublicWire) == true
        }
        return if (match != null) {
            Result(Trust.TRUSTED, result.keyType, match.name, null)
        } else {
            Result(Trust.VALID_UNKNOWN, result.keyType, null, null)
        }
    }

    /** The SSHSIG public-key wire for an identity, used to match the envelope's signer. */
    private fun publicWireOf(identity: StoredIdentity): ByteArray? = when (identity.type) {
        StoredIdentityType.SSH_ED25519 -> SSHSig.ed25519PublicWire(b64d(identity.publicKeyB64))
        // hardware and security-key identities already store the full SSHSIG public wire
        StoredIdentityType.HARDWARE_KEY -> b64d(identity.publicKeyB64)
        StoredIdentityType.SK_ED25519 -> b64d(identity.publicKeyB64)
        StoredIdentityType.SK_ECDSA_P256 -> b64d(identity.publicKeyB64)
        StoredIdentityType.SSH_RSA -> null
        StoredIdentityType.X25519 -> null
    }
}
