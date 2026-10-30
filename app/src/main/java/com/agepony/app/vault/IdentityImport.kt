package com.agepony.app.vault

import com.agepony.app.security.piv.YubiKeyBroker
import com.agepony.core.piv.YubiKeyIdentityFile
import com.agepony.core.piv.YubiKeyPinPolicy
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.YubiKeyStub
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

/** [kind] is what the app shows; the message is internal and never shown (5.1.0, UI plan U5). */
class IdentityImportException(val kind: Kind, message: String, cause: Throwable? = null) : Exception(message, cause) {
    enum class Kind { PASSPHRASE_REQUIRED, WRONG_PASSPHRASE, UNSUPPORTED, MALFORMED }
}

object IdentityImport {

    /**
     * Import an age secret key string. Handles both the classical `AGE-SECRET-KEY-1…`
     * and the post-quantum `AGE-SECRET-KEY-PQ-1…` forms, routing on the prefix.
     */
    fun fromAgeSecretKey(secret: String, name: String, names: DefaultKeyNames): StoredIdentity {
        val t = secret.trim()
        return if (t.uppercase().startsWith("AGE-SECRET-KEY-PQ-")) {
            fromAgePqSecretKey(t, name, names)
        } else {
            fromAgeClassicSecretKey(t, name, names)
        }
    }

    private fun fromAgeClassicSecretKey(t: String, name: String, names: DefaultKeyNames): StoredIdentity {
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
            name = name.trim().ifBlank { names.identity(StoredIdentityType.X25519) },
            type = StoredIdentityType.X25519,
            publicKeyB64 = b64e(identity.publicKey),
            privateKeyB64 = b64e(identity.privateKey),
            createdAt = System.currentTimeMillis(),
        )
    }

    /** Import a post-quantum `AGE-SECRET-KEY-PQ-1…` private key string. */
    private fun fromAgePqSecretKey(t: String, name: String, names: DefaultKeyNames): StoredIdentity {
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
            name = name.trim().ifBlank { names.identity(StoredIdentityType.MLKEM768X25519) },
            type = StoredIdentityType.MLKEM768X25519,
            publicKeyB64 = b64e(identity.publicKey),
            privateKeyB64 = b64e(identity.seed),
            createdAt = System.currentTimeMillis(),
        )
    }

    /** True when [text] is an age-plugin-yubikey identity file or a bare AGE-PLUGIN-YUBIKEY-1 line. */
    fun isYubiKeyIdentity(text: String): Boolean = YubiKeyIdentityFile.contains(text)

    /**
     * Import an age-plugin-yubikey identity (5.0.0; PIN policy 5.1.0 item 1). A full identity
     * file carries the public key in its `Recipient:` comment, which saves a tap, and the slot's
     * PIN policy in its `PIN policy:` comment. Without the recipient line, [readKey] taps the
     * YubiKey for the public key and GET METADATA; the policy that tap reads wins when the key
     * answers. [defaultName] names the key from its serial when [name] is blank.
     */
    fun fromYubiKey(
        text: String,
        name: String,
        defaultName: (serial: Long) -> String,
        readKey: (YubiKeyStub) -> Pair<ByteArray, YubiKeyPinPolicy> = YubiKeyBroker::readPublicKeyAndPinPolicy,
    ): StoredIdentity {
        val file = try {
            YubiKeyIdentityFile.parse(text)
        } catch (e: Exception) {
            throw IdentityImportException(
                IdentityImportException.Kind.MALFORMED,
                "Not a valid AGE-PLUGIN-YUBIKEY-1… identity."
            )
        }
        val fromFile = file.publicKey
        val (publicKey, policy) = if (fromFile != null) {
            fromFile to file.pinPolicy
        } else {
            val (key, tapped) = readKey(file.stub)
            key to (if (tapped != YubiKeyPinPolicy.UNKNOWN) tapped else file.pinPolicy)
        }
        return StoredIdentity(
            id = UUID.randomUUID().toString(),
            name = name.trim().ifBlank { defaultName(file.stub.serial) },
            type = StoredIdentityType.YUBIKEY_PIV,
            publicKeyB64 = b64e(publicKey),
            privateKeyB64 = b64e(file.stub.toBytes()),
            createdAt = System.currentTimeMillis(),
        ).withYubiKeyPinPolicy(policy)
    }

    /** Import an OpenSSH private key PEM (ed25519 and rsa). */
    fun fromOpenSSHPem(pem: String, passphrase: String?, name: String, names: DefaultKeyNames): StoredIdentity {
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
                    IdentityImportException.Kind.UNSUPPORTED, m, e
                )

                else -> IdentityImportException(
                    IdentityImportException.Kind.MALFORMED,
                    "Couldn't read that OpenSSH key ($m).",
                    e,
                )
            }
        }

        // The parsers are stricter since 5.0.1 (Ed25519 points, RSA key consistency, bcrypt round
        // caps) and throw IllegalArgumentException as well as their own exceptions; anything
        // thrown past the parse still has to reach the user as a readable import error.
        return try {
            storedFromParsed(parsed, pem, passphrase, name, names)
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
        names: DefaultKeyNames,
    ): StoredIdentity {
        return when (parsed) {
            is OpenSSHPrivateKey.Ed25519 -> {
                val identity = SSHEd25519Identity(parsed)
                StoredIdentity(
                    id = UUID.randomUUID().toString(),
                    name = name.trim().ifBlank { names.identity(StoredIdentityType.SSH_ED25519) },
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
                    name = name.trim().ifBlank { names.identity(StoredIdentityType.SSH_RSA) },
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
