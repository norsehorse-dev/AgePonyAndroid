package com.agepony.app.signing

import com.agepony.app.R
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.UiText
import com.agepony.app.vault.StoredSigner
import com.agepony.app.vault.b64d
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigVerifier
import com.agepony.core.ssh.AllowedSigner
import java.io.IOException
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/**
 * Verifies a detached SSHSIG over a file and decides how much to trust the signer.
 *
 * Cryptographic validity comes from [SSHSigVerifier]. On top of that, the signer's public
 * key is matched against the vault: the user's own identities first (so a signature made
 * with your own key carries your name for it, not a signer-list principal), then the
 * trusted-signers list. A match is [Trust.TRUSTED] (with the matched name), a
 * cryptographically valid signature from an unknown key is [Trust.VALID_UNKNOWN], and a
 * failed signature is [Trust.INVALID] with a reason.
 *
 * Recipients are never trusted as signers. A trusted signer imported from an allowed_signers
 * file keeps its options (namespaces=, valid-after=, valid-before=, cert-authority,
 * no-touch-required, verify-required), and they are enforced here (audit L-6): a key match the
 * options reject is reported as [Trust.VALID_UNKNOWN] with [Result.untrustedSignerName] and
 * [Result.untrustedReason] set, never as trusted. A malformed signature is [Trust.INVALID],
 * never an exception.
 */
class FileVerifier {
    enum class Trust { TRUSTED, VALID_UNKNOWN, INVALID }

    class Result(
        val trust: Trust,
        val keyType: String,
        val signerName: String?,
        /** Why the signature failed, as a whole sentence from resources (5.1.0, UI plan U5). */
        val reason: UiText?,
        /**
         * The signer's public-key wire blob, present when the signature verified. This is
         * what "add this signer" persists, so the added entry matches future signatures
         * by exactly the bytes this one carried.
         */
        val signerPublicWire: ByteArray? = null,
        /**
         * Set when the key is on the trusted-signers list but that entry's options reject this
         * signature ([trust] is then [Trust.VALID_UNKNOWN]): the entry's name, for display.
         */
        val untrustedSignerName: String? = null,
        /** Why the matching trusted-signer entry did not accept the signature, as a whole sentence. */
        val untrustedReason: UiText? = null,
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
        // Look at the envelope's key first so a trusted-signer entry with no-touch-required can
        // relax the security-key touch check, as OpenSSH does, and only for that key.
        val envelopeKey = signerWireOrNull(signature)
        val ownMatch = envelopeKey?.let { wire ->
            knownIdentities.firstOrNull { identity -> publicWireOf(identity)?.contentEquals(wire) == true }
        }
        val signerMatch = if (ownMatch != null) null else envelopeKey?.let { wire ->
            knownSigners.firstOrNull { signer -> b64dOrNull(signer.publicKeyWireB64)?.contentEquals(wire) == true }
        }
        val entry = signerMatch?.toAllowedSigner()
        val allowNoTouch = entry != null && !entry.requiresTouch

        val result = try {
            SSHSigVerifier.verifyHashed(signature, namespace, allowNoTouch, messageHashFor)
        } catch (e: IOException) {
            throw e // could not read the signed file: not a verdict on the signature
        } catch (e: SSHSig.SSHSigFormatException) {
            return Result(Trust.INVALID, "unknown", null, UiText.res(R.string.sign_reason_malformed))
        } catch (e: Exception) {
            return Result(Trust.INVALID, "unknown", null, UiText.res(R.string.sign_reason_unchecked))
        }
        if (!result.valid) {
            return Result(Trust.INVALID, result.keyType, null, failureReason(result))
        }
        if (ownMatch != null && ownMatch.hasWire(result.signerPublicWire)) {
            return Result(Trust.TRUSTED, result.keyType, ownMatch.name, null, result.signerPublicWire)
        }
        if (signerMatch != null && entry != null &&
            b64dOrNull(signerMatch.publicKeyWireB64)?.contentEquals(result.signerPublicWire) == true
        ) {
            val now = Instant.now()
            if (entry.accepts(result, now)) {
                return Result(Trust.TRUSTED, result.keyType, signerMatch.name, null, result.signerPublicWire)
            }
            return Result(
                Trust.VALID_UNKNOWN, result.keyType, null, null, result.signerPublicWire,
                untrustedSignerName = signerMatch.name,
                untrustedReason = rejectionReason(entry, result, now),
            )
        }
        return Result(Trust.VALID_UNKNOWN, result.keyType, null, null, result.signerPublicWire)
    }

    private fun StoredIdentity.hasWire(wire: ByteArray): Boolean =
        publicWireOf(this)?.contentEquals(wire) == true

    /** The envelope's signer key, or null if the signature does not even parse (the verifier then says why). */
    private fun signerWireOrNull(signature: ByteArray): ByteArray? = try {
        if (signature.size > SSHSigVerifier.MAX_SIGNATURE_BYTES) {
            null
        } else {
            SSHSig.decode(SSHSig.decodeArmoredOrRaw(signature)).publicKeyBlob
        }
    } catch (_: Exception) {
        null
    }

    /** Why a signature that parsed failed, as a whole sentence. Stays clearly a failure (U5). */
    private fun failureReason(result: SSHSigVerifier.Result): UiText = when (result.failure) {
        SSHSigVerifier.Failure.NAMESPACE_MISMATCH -> UiText.res(R.string.sign_reason_namespace, result.namespace)
        SSHSigVerifier.Failure.RSA_KEY_UNACCEPTABLE -> UiText.res(R.string.sign_reason_rsa_key)
        SSHSigVerifier.Failure.NO_TOUCH -> UiText.res(R.string.sign_reason_no_touch)
        SSHSigVerifier.Failure.SIGNATURE_MISMATCH, null -> UiText.res(R.string.sign_reason_mismatch)
    }

    /**
     * Why [entry] does not accept the (valid) [result] at [at], as a whole sentence for the
     * verdict (5.1.0, UI plan U5). The entry's own option text is data, shown as it is.
     */
    private fun rejectionReason(entry: AllowedSigner, result: SSHSigVerifier.Result, at: Instant): UiText {
        val opts = entry.parsedOptions()
        val validAfter = opts.validAfter
        val validBefore = opts.validBefore
        return when {
            opts.error != null -> UiText.res(R.string.sign_entry_options_unreadable)
            opts.unknown.isNotEmpty() ->
                UiText.res(R.string.sign_entry_options_unsupported, opts.unknown.joinToString(", "))
            opts.certAuthority -> UiText.res(R.string.sign_entry_cert_authority)
            validAfter != null && at.isBefore(validAfter) ->
                UiText.res(R.string.sign_entry_not_yet_valid, formatInstant(validAfter))
            validBefore != null && at.isAfter(validBefore) ->
                UiText.res(R.string.sign_entry_expired, formatInstant(validBefore))
            !entry.permitsAgePony(result.namespace, at) ->
                UiText.res(R.string.sign_entry_namespace, result.namespace)
            result.userPresent == false && !opts.noTouchRequired -> UiText.res(R.string.sign_entry_needs_touch)
            opts.verifyRequired && result.userVerified == false -> UiText.res(R.string.sign_entry_needs_verify)
            else -> UiText.res(R.string.sign_entry_refuses)
        }
    }

    /** A date and time in the user's locale and zone. */
    private fun formatInstant(at: Instant): String =
        DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM).withZone(ZoneId.systemDefault()).format(at)

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
        StoredIdentityType.HARDWARE_TAG, StoredIdentityType.HARDWARE_TAG_PQ, StoredIdentityType.YUBIKEY_PIV -> null
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
