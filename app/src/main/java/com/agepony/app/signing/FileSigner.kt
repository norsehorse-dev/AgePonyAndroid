package com.agepony.app.signing

import androidx.fragment.app.FragmentActivity
import com.agepony.app.R
import com.agepony.app.security.SecurityKeyService
import com.agepony.app.security.keystore.HardwareKeyService
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.b64d
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner
import com.agepony.core.ssh.OpenSSHPrivateKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream

/**
 * Produces a detached SSHSIG over a file, routing by identity type:
 *  - software SSH Ed25519 signs in-process,
 *  - software SSH RSA signs in-process (rsa-sha2-512, from the vault's stored PEM),
 *  - a hardware (Keystore) key signs in the TEE/StrongBox, behind a biometric prompt when
 *    the key requires user auth,
 *  - a security key signs over NFC, prompting for a PIN when the authenticator requires one.
 *
 * The result is the armored SSHSIG text; callers save it next to the file as `<name>.sig`.
 */
class FileSigner(
    private val activity: FragmentActivity,
) {
    /** [reason] is what the app shows; the message is internal (5.1.0, UI plan U5). */
    class FileSignerException(
        val reason: FileSignerException.Reason,
        cause: Throwable? = null,
    ) : Exception(reason.name, cause) {
        enum class Reason { X25519_CANNOT_SIGN, QUANTUM_SAFE_CANNOT_SIGN, DECRYPT_ONLY_KEY, SECURITY_KEY_NOT_HERE, KEY_DAMAGED }
    }

    suspend fun sign(
        identity: StoredIdentity,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        pin: String? = null,
    ): String = when (identity.type) {
        StoredIdentityType.SSH_ED25519 ->
            SSHSigner.signEd25519(b64d(identity.privateKeyB64), b64d(identity.publicKeyB64), message, namespace)

        StoredIdentityType.X25519 ->
            throw FileSignerException(FileSignerException.Reason.X25519_CANNOT_SIGN)

        StoredIdentityType.MLKEM768X25519 ->
            throw FileSignerException(FileSignerException.Reason.QUANTUM_SAFE_CANNOT_SIGN)

        StoredIdentityType.SSH_RSA -> {
            // The vault stores the decrypted, cipher=none PEM (see IdentityImport), so no
            // passphrase is needed here.
            SSHSigner.sign(parseStoredRsa(identity), message, namespace)
        }

        StoredIdentityType.HARDWARE_KEY -> {
            val alias = identity.keystoreAlias
                ?: throw FileSignerException(FileSignerException.Reason.KEY_DAMAGED)
            if (HardwareKeyService.isUserAuthRequired(alias)) {
                HardwareKeyService.signAuthenticated(
                    activity = activity,
                    alias = alias,
                    message = message,
                    title = activity.getString(R.string.core_prompt_sign_title),
                    subtitle = identity.name,
                    namespace = namespace,
                )
            } else {
                HardwareKeyService.sign(alias, message, namespace)
            }
        }

        StoredIdentityType.SK_ED25519, StoredIdentityType.SK_ECDSA_P256 ->
            SecurityKeyService(activity).signSSHSIG(identity, message, namespace, pin)

        StoredIdentityType.HARDWARE_TAG, StoredIdentityType.HARDWARE_TAG_PQ, StoredIdentityType.YUBIKEY_PIV ->
            throw FileSignerException(FileSignerException.Reason.DECRYPT_ONLY_KEY)
    }

    /**
     * Sign an already-computed sha512 message hash, for callers that stream the payload
     * past [SSHSig.hashStream] — the encrypt flow's sign-then-encrypt pass and
     * [signStream]. Hardware-key prompts hop to the main thread here, so this is safe to
     * call from an IO context. Security keys are rejected: their FIDO exchange belongs on
     * the Sign tab, not mid-flow.
     */
    suspend fun signHashed(
        identity: StoredIdentity,
        messageHash: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
    ): String = when (identity.type) {
        StoredIdentityType.SSH_ED25519 -> SSHSigner.signEd25519Hashed(
            b64d(identity.privateKeyB64), b64d(identity.publicKeyB64), messageHash, namespace,
        )

        StoredIdentityType.SSH_RSA -> {
            val key = parseStoredRsa(identity)
            SSHSigner.signRsaSha512Hashed(key.n, key.e, key.d, messageHash, namespace)
        }

        StoredIdentityType.HARDWARE_KEY -> {
            val alias = identity.keystoreAlias
                ?: throw FileSignerException(FileSignerException.Reason.KEY_DAMAGED)
            withContext(Dispatchers.Main) {
                if (HardwareKeyService.isUserAuthRequired(alias)) {
                    HardwareKeyService.signAuthenticatedHashed(
                        activity = activity,
                        alias = alias,
                        messageHash = messageHash,
                        title = activity.getString(R.string.core_prompt_sign_title),
                        subtitle = identity.name,
                        namespace = namespace,
                    )
                } else {
                    HardwareKeyService.signHashed(alias, messageHash, namespace)
                }
            }
        }

        StoredIdentityType.SK_ED25519, StoredIdentityType.SK_ECDSA_P256 ->
            throw FileSignerException(FileSignerException.Reason.SECURITY_KEY_NOT_HERE)

        StoredIdentityType.X25519 ->
            throw FileSignerException(FileSignerException.Reason.X25519_CANNOT_SIGN)

        StoredIdentityType.MLKEM768X25519 ->
            throw FileSignerException(FileSignerException.Reason.QUANTUM_SAFE_CANNOT_SIGN)

        StoredIdentityType.HARDWARE_TAG, StoredIdentityType.HARDWARE_TAG_PQ, StoredIdentityType.YUBIKEY_PIV ->
            throw FileSignerException(FileSignerException.Reason.DECRYPT_ONLY_KEY)
    }

    /**
     * [sign] for a file that should not be held in memory. Software keys and hardware
     * keys stream the digest, so any file size costs one read and a 64 KiB buffer.
     * Security keys still read the whole file, because the FIDO envelope-assembly path
     * takes the message; their typical inputs are small.
     *
     * [open] may be called once; the stream is closed here.
     */
    suspend fun signStream(
        identity: StoredIdentity,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        pin: String? = null,
        open: () -> InputStream,
    ): String = when (identity.type) {
        StoredIdentityType.SSH_ED25519,
        StoredIdentityType.SSH_RSA,
        StoredIdentityType.HARDWARE_KEY,
        -> {
            val hash = withContext(Dispatchers.IO) { open().use { SSHSig.hashStream(it) } }
            signHashed(identity, hash, namespace)
        }

        else -> {
            val message = withContext(Dispatchers.IO) { open().use { it.readBytes() } }
            sign(identity, message, namespace, pin)
        }
    }

    fun signedName(inputName: String): String = "$inputName.sig"

    private fun parseStoredRsa(identity: StoredIdentity): OpenSSHPrivateKey.RSA {
        val pem = String(b64d(identity.privateKeyB64), Charsets.UTF_8)
        val key = try {
            OpenSSHPrivateKey.parse(pem)
        } catch (e: Exception) {
            throw FileSignerException(FileSignerException.Reason.KEY_DAMAGED, e)
        }
        return key as? OpenSSHPrivateKey.RSA
            ?: throw FileSignerException(FileSignerException.Reason.KEY_DAMAGED)
    }

    companion object {
        /** Identity types that can produce a signature, for pickers to filter on. */
        val SIGNING_TYPES: Set<StoredIdentityType> = setOf(
            StoredIdentityType.SSH_ED25519,
            StoredIdentityType.SSH_RSA,
            StoredIdentityType.HARDWARE_KEY,
            StoredIdentityType.SK_ED25519,
            StoredIdentityType.SK_ECDSA_P256,
        )

        /**
         * The subset eligible for sign-then-encrypt: everything except security keys,
         * which are excluded there the same way iOS's SignEncryptService excludes them
         * (an NFC tap mid-encrypt is the wrong moment).
         */
        val ENCRYPT_SIGNING_TYPES: Set<StoredIdentityType> = setOf(
            StoredIdentityType.SSH_ED25519,
            StoredIdentityType.SSH_RSA,
            StoredIdentityType.HARDWARE_KEY,
        )
    }
}
