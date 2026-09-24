package com.agepony.app.signing

import androidx.fragment.app.FragmentActivity
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
    class FileSignerException(message: String, cause: Throwable? = null) : Exception(message, cause)

    suspend fun sign(
        identity: StoredIdentity,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        pin: String? = null,
    ): String = when (identity.type) {
        StoredIdentityType.SSH_ED25519 ->
            SSHSigner.signEd25519(b64d(identity.privateKeyB64), b64d(identity.publicKeyB64), message, namespace)

        StoredIdentityType.X25519 ->
            throw FileSignerException("age X25519 identities can't sign; choose an SSH key, hardware key, or security key")

        StoredIdentityType.MLKEM768X25519 ->
            throw FileSignerException("quantum-safe identities are for encryption, not signing; choose an SSH key, hardware key, or security key")

        StoredIdentityType.SSH_RSA -> {
            // The vault stores the decrypted, cipher=none PEM (see IdentityImport), so no
            // passphrase is needed here.
            SSHSigner.sign(parseStoredRsa(identity), message, namespace)
        }

        StoredIdentityType.HARDWARE_KEY -> {
            val alias = identity.keystoreAlias
                ?: throw FileSignerException("hardware identity is missing its keystore alias")
            if (HardwareKeyService.isUserAuthRequired(alias)) {
                HardwareKeyService.signAuthenticated(
                    activity = activity,
                    alias = alias,
                    message = message,
                    title = "Sign with hardware key",
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
            throw FileSignerException("hardware decryption keys can't sign; choose an SSH key or hardware signing key")
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
                ?: throw FileSignerException("hardware identity is missing its keystore alias")
            withContext(Dispatchers.Main) {
                if (HardwareKeyService.isUserAuthRequired(alias)) {
                    HardwareKeyService.signAuthenticatedHashed(
                        activity = activity,
                        alias = alias,
                        messageHash = messageHash,
                        title = "Sign with hardware key",
                        subtitle = identity.name,
                        namespace = namespace,
                    )
                } else {
                    HardwareKeyService.signHashed(alias, messageHash, namespace)
                }
            }
        }

        StoredIdentityType.SK_ED25519, StoredIdentityType.SK_ECDSA_P256 ->
            throw FileSignerException("security keys sign from the Sign tab; they can't sign inside this flow")

        StoredIdentityType.X25519 ->
            throw FileSignerException("age X25519 identities can't sign; choose an SSH key or hardware key")

        StoredIdentityType.MLKEM768X25519 ->
            throw FileSignerException("quantum-safe identities are for encryption, not signing; choose an SSH key or hardware key")

        StoredIdentityType.HARDWARE_TAG, StoredIdentityType.HARDWARE_TAG_PQ, StoredIdentityType.YUBIKEY_PIV ->
            throw FileSignerException("hardware decryption keys can't sign; choose an SSH key or hardware signing key")
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
            throw FileSignerException("couldn't read the stored RSA key: ${e.message}", e)
        }
        return key as? OpenSSHPrivateKey.RSA
            ?: throw FileSignerException("stored ssh-rsa identity did not parse as RSA")
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
