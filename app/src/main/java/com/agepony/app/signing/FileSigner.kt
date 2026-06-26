package com.agepony.app.signing

import androidx.fragment.app.FragmentActivity
import com.agepony.app.security.SecurityKeyService
import com.agepony.app.security.keystore.HardwareKeyService
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.b64d
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner

/**
 * Produces a detached SSHSIG over a file, routing by identity type:
 *  - software SSH Ed25519 signs in-process,
 *  - a hardware (Keystore) key signs in the TEE/StrongBox, behind a biometric prompt when
 *    the key requires user auth,
 *  - a security key signs over NFC, prompting for a PIN when the authenticator requires one.
 *
 * The result is the armored SSHSIG text; callers save it next to the file as `<name>.sig`.
 */
class FileSigner(
    private val activity: FragmentActivity,
    private val pinProvider: SecurityKeyService.PinProvider? = null,
) {
    class FileSignerException(message: String, cause: Throwable? = null) : Exception(message, cause)

    suspend fun sign(
        identity: StoredIdentity,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
    ): String = when (identity.type) {
        StoredIdentityType.SSH_ED25519 ->
            SSHSigner.signEd25519(b64d(identity.privateKeyB64), b64d(identity.publicKeyB64), message, namespace)

        StoredIdentityType.X25519 ->
            throw FileSignerException("age X25519 identities can't sign; choose an SSH key, hardware key, or security key")

        StoredIdentityType.SSH_RSA ->
            throw FileSignerException("RSA signing isn't supported yet")

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
            SecurityKeyService(activity, pinProvider).signSSHSIG(identity, message, namespace)
    }

    fun signedName(inputName: String): String = "$inputName.sig"
}
