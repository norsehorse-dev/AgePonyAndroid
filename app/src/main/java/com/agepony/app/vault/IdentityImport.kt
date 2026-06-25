package com.agepony.app.vault

import com.agepony.core.recipients.SSHEd25519Identity
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.ssh.OpenSSHPrivateKey
import java.util.UUID

//
// Android counterpart of iOS's SSHIdentityImporter, plus the age-secret-key
// path. Produces a StoredIdentity ready for the vault. ssh-ed25519 and age
// X25519 are supported now; ssh-rsa private keys are deferred.
//

class IdentityImportException(val kind: Kind, message: String) : Exception(message) {
    enum class Kind { PASSPHRASE_REQUIRED, WRONG_PASSPHRASE, UNSUPPORTED, MALFORMED }
}

object IdentityImport {

    /** Import an `AGE-SECRET-KEY-1…` private key string. */
    fun fromAgeSecretKey(secret: String, name: String): StoredIdentity {
        val t = secret.trim()
        val identity = try {
            X25519Identity(t)
        } catch (e: Exception) {
            throw IdentityImportException(
                IdentityImportException.Kind.MALFORMED,
                "Not a valid AGE-SECRET-KEY-1… string."
            )
        }
        return StoredIdentity(
            id = UUID.randomUUID().toString(),
            name = name.trim().ifBlank { "age identity" },
            type = StoredIdentityType.X25519,
            publicKeyB64 = b64e(identity.publicKey),
            privateKeyB64 = b64e(identity.privateKey),
            createdAt = System.currentTimeMillis(),
        )
    }

    /** Import an OpenSSH private key PEM (ed25519 supported; rsa deferred). */
    fun fromOpenSSHPem(pem: String, passphrase: String?, name: String): StoredIdentity {
        val parsed = try {
            OpenSSHPrivateKey.parse(pem.trim(), passphrase?.ifBlank { null })
        } catch (e: Exception) {
            val m = e.message ?: ""
            throw when {
                m.contains("no passphrase provided") -> IdentityImportException(
                    IdentityImportException.Kind.PASSPHRASE_REQUIRED,
                    "This key is passphrase-protected. Enter its passphrase."
                )

                m.contains("wrong passphrase") -> IdentityImportException(
                    IdentityImportException.Kind.WRONG_PASSPHRASE,
                    "Wrong passphrase."
                )

                m.contains("unsupported", ignoreCase = true) -> IdentityImportException(
                    IdentityImportException.Kind.UNSUPPORTED, m
                )

                else -> IdentityImportException(
                    IdentityImportException.Kind.MALFORMED,
                    "Couldn't read that OpenSSH key ($m)."
                )
            }
        }

        return when (parsed) {
            is OpenSSHPrivateKey.Ed25519 -> {
                val identity = SSHEd25519Identity(parsed)
                StoredIdentity(
                    id = UUID.randomUUID().toString(),
                    name = name.trim().ifBlank { "SSH Ed25519" },
                    type = StoredIdentityType.SSH_ED25519,
                    publicKeyB64 = b64e(identity.edPublicKey),
                    privateKeyB64 = b64e(identity.edSeed),
                    sshComment = null,
                    createdAt = System.currentTimeMillis(),
                )
            }

            is OpenSSHPrivateKey.RSA -> throw IdentityImportException(
                IdentityImportException.Kind.UNSUPPORTED,
                "SSH RSA private-key import is coming in a later update. (RSA recipients work today.)"
            )
        }
    }
}
