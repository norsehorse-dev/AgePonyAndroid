package com.agepony.app.vault

import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.SSHEd25519Identity
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.signing.SSHSig
import com.agepony.core.ssh.OpenSSHEncryptedKey
import com.agepony.core.ssh.OpenSSHPrivateKey
import java.util.UUID

//
// Android counterpart of iOS's SSHIdentityImporter, plus the age-secret-key
// path. Produces a StoredIdentity ready for the vault. age X25519, age
// post-quantum (AGE-SECRET-KEY-PQ-), ssh-ed25519, and ssh-rsa are supported.
//

class IdentityImportException(val kind: Kind, message: String) : Exception(message) {
    enum class Kind { PASSPHRASE_REQUIRED, WRONG_PASSPHRASE, UNSUPPORTED, MALFORMED }
}

object IdentityImport {

    /**
     * Import an age secret key string. Handles both the classical `AGE-SECRET-KEY-1…`
     * and the post-quantum `AGE-SECRET-KEY-PQ-1…` forms, routing on the prefix.
     */
    fun fromAgeSecretKey(secret: String, name: String): StoredIdentity {
        val t = secret.trim()
        return if (t.uppercase().startsWith("AGE-SECRET-KEY-PQ-")) {
            fromAgePqSecretKey(t, name)
        } else {
            fromAgeClassicSecretKey(t, name)
        }
    }

    private fun fromAgeClassicSecretKey(t: String, name: String): StoredIdentity {
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

    /** Import a post-quantum `AGE-SECRET-KEY-PQ-1…` private key string. */
    private fun fromAgePqSecretKey(t: String, name: String): StoredIdentity {
        val identity = try {
            HybridIdentity(t)
        } catch (e: Exception) {
            throw IdentityImportException(
                IdentityImportException.Kind.MALFORMED,
                "Not a valid AGE-SECRET-KEY-PQ-1… string."
            )
        }
        return StoredIdentity(
            id = UUID.randomUUID().toString(),
            name = name.trim().ifBlank { "quantum-safe identity" },
            type = StoredIdentityType.MLKEM768X25519,
            publicKeyB64 = b64e(identity.publicKey),
            privateKeyB64 = b64e(identity.seed),
            createdAt = System.currentTimeMillis(),
        )
    }

    /** Import an OpenSSH private key PEM (ed25519 and rsa). */
    fun fromOpenSSHPem(pem: String, passphrase: String?, name: String): StoredIdentity {
        val parsed = try {
            OpenSSHPrivateKey.parse(pem.trim(), passphrase?.ifBlank { null })
        } catch (e: Exception) {
            val m = e.message ?: e.javaClass.simpleName
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

        // The parsers are stricter since 5.0.1 (Ed25519 points, RSA key consistency, bcrypt round
        // caps) and throw IllegalArgumentException as well as their own exceptions; anything
        // thrown past the parse still has to reach the user as a readable import error.
        return try {
            storedFromParsed(parsed, pem, passphrase, name)
        } catch (e: IdentityImportException) {
            throw e
        } catch (e: Exception) {
            throw IdentityImportException(
                IdentityImportException.Kind.MALFORMED,
                "Couldn't read that OpenSSH key (${e.message ?: e.javaClass.simpleName})."
            )
        }
    }

    private fun storedFromParsed(
        parsed: OpenSSHPrivateKey,
        pem: String,
        passphrase: String?,
        name: String,
    ): StoredIdentity {
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

            is OpenSSHPrivateKey.RSA -> {
                // Stored form mirrors iOS: priv = UTF-8 bytes of the decrypted OpenSSH
                // PEM (normalized to cipher=none by OpenSSHEncryptedKey, so the vault
                // never needs the import passphrase again), pub = UTF-8 bytes of the
                // `ssh-rsa BASE64 [comment]` line.
                val normalizedPem = try {
                    OpenSSHEncryptedKey.decryptedPem(pem.trim(), passphrase?.ifBlank { null })
                } catch (e: Exception) {
                    throw IdentityImportException(
                        IdentityImportException.Kind.MALFORMED,
                        "Couldn't re-serialize the RSA key (${e.message})."
                    )
                }
                val wireB64 = b64e(SSHSig.rsaPublicWire(parsed.e, parsed.n))
                val c = parsed.comment?.trim().orEmpty()
                val line = if (c.isEmpty()) "ssh-rsa $wireB64" else "ssh-rsa $wireB64 $c"
                StoredIdentity(
                    id = UUID.randomUUID().toString(),
                    name = name.trim().ifBlank { "SSH RSA" },
                    type = StoredIdentityType.SSH_RSA,
                    publicKeyB64 = b64e(line.toByteArray(Charsets.UTF_8)),
                    privateKeyB64 = b64e(normalizedPem.toByteArray(Charsets.UTF_8)),
                    sshComment = parsed.comment,
                    createdAt = System.currentTimeMillis(),
                )
            }
        }
    }
}
