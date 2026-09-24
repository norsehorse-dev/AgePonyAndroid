package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.HKDF
import com.agepony.core.crypto.SHA256
import com.agepony.core.crypto.X25519Crypto
import com.agepony.core.ssh.Ed25519Conversion
import com.agepony.core.ssh.OpenSSHPrivateKey
import com.agepony.core.ssh.OpenSSHPublicKey
import com.agepony.core.ssh.SSHWire
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import java.io.ByteArrayOutputStream

private const val SSH_ED25519_STANZA_TYPE = "ssh-ed25519"
private const val SSH_ED25519_INFO = "age-encryption.org/v1/ssh-ed25519"
private const val SSH_ED25519_KEYTYPE = "ssh-ed25519"
private const val RECIPIENT_TAG_LEN = 4
private val ZERO_NONCE_12 = ByteArray(12)
private const val SSH_ED25519_BODY_SIZE = 16 + 16   // file key (16) + ChaCha20Poly1305 tag (16)

/** Build the SSH wire blob: `<len="ssh-ed25519">"ssh-ed25519"<len=32><pubKey>`. */
private fun buildSSHWireBlob(edPublicKey: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    SSHWire.writeString(out, SSH_ED25519_KEYTYPE.toByteArray(Charsets.US_ASCII))
    SSHWire.writeString(out, edPublicKey)
    return out.toByteArray()
}

/**
 * Recipient using an ssh-ed25519 public key. See age spec for the filippo HKDF tweak.
 */
class SSHEd25519Recipient(val edPublicKey: ByteArray) : AgeRecipient {
    private val x25519PublicKey: ByteArray
    private val sshWireBlob: ByteArray
    private val recipientTag: ByteArray

    init {
        require(edPublicKey.size == 32) { "Ed25519 public key must be 32 bytes" }
        x25519PublicKey = Ed25519Conversion.publicKeyToX25519(edPublicKey)
        sshWireBlob = buildSSHWireBlob(edPublicKey)
        recipientTag = SHA256.digest(sshWireBlob).copyOfRange(0, RECIPIENT_TAG_LEN)
    }

    constructor(parsed: OpenSSHPublicKey.Ed25519) : this(parsed.publicKey)

    override fun wrap(fileKey: ByteArray): Stanza {
        val ephPriv = X25519Crypto.generatePrivateKey()
        val ephPub = X25519Crypto.publicKey(ephPriv)
        // BC refuses an all-zero shared secret (low-order point); report a bad recipient.
        var shared = X25519Crypto.keyExchangeOrNull(ephPriv, x25519PublicKey)
            ?: throw IllegalArgumentException("ssh-ed25519 recipient is a low-order point; refusing to encrypt to it")
        val tweak = HKDF.derive(ByteArray(0), sshWireBlob, SSH_ED25519_INFO.toByteArray(), 32)
        shared = X25519Crypto.keyExchangeOrNull(tweak, shared)
            ?: throw IllegalArgumentException("ssh-ed25519 tweaked shared secret is zero")
        val salt = ephPub + x25519PublicKey
        val wrapKey = HKDF.derive(shared, salt, SSH_ED25519_INFO.toByteArray(), 32)
        val body = ChaChaPoly.encrypt(wrapKey, ZERO_NONCE_12, fileKey)
        return Stanza(
            SSH_ED25519_STANZA_TYPE,
            listOf(Stanza.base64NoPad(recipientTag), Stanza.base64NoPad(ephPub)),
            body
        )
    }

    companion object {
        fun fromOpenSSHString(line: String): SSHEd25519Recipient {
            val parsed = OpenSSHPublicKey.parse(line)
            require(parsed is OpenSSHPublicKey.Ed25519) {
                "expected ssh-ed25519, got '${parsed.keyType}'"
            }
            return SSHEd25519Recipient(parsed)
        }
    }
}

/**
 * Identity using an ssh-ed25519 private key (32-byte seed).
 */
class SSHEd25519Identity(val edSeed: ByteArray) : AgeIdentity {
    val edPublicKey: ByteArray
    private val x25519PrivateKey: ByteArray
    private val x25519PublicKey: ByteArray
    private val sshWireBlob: ByteArray
    private val recipientTag: ByteArray

    init {
        require(edSeed.size == 32) { "Ed25519 seed must be 32 bytes" }
        val edPriv = Ed25519PrivateKeyParameters(edSeed, 0)
        edPublicKey = edPriv.generatePublicKey().encoded
        x25519PrivateKey = Ed25519Conversion.privateKeyToX25519(edSeed)
        x25519PublicKey = Ed25519Conversion.publicKeyToX25519(edPublicKey)
        sshWireBlob = buildSSHWireBlob(edPublicKey)
        recipientTag = SHA256.digest(sshWireBlob).copyOfRange(0, RECIPIENT_TAG_LEN)
    }

    constructor(parsed: OpenSSHPrivateKey.Ed25519) : this(parsed.privateKey)

    override fun unwrap(stanza: Stanza): ByteArray? {
        if (stanza.type != SSH_ED25519_STANZA_TYPE) return null
        if (stanza.args.size != 2) return null

        val tag = try { Stanza.base64Decode(stanza.args[0]) } catch (_: Exception) { return null }
        if (tag.size != RECIPIENT_TAG_LEN) return null
        if (!tag.contentEquals(recipientTag)) return null

        val ephPub = try { Stanza.base64Decode(stanza.args[1]) } catch (_: Exception) { return null }
        if (ephPub.size != 32) return null
        // The wrapped file key is always 32 bytes; anything else is not a valid stanza (audit L-5).
        if (stanza.body.size != SSH_ED25519_BODY_SIZE) return null

        // Low-order ephemeral share: BC refuses the all-zero secret; treat as not for us.
        var shared = X25519Crypto.keyExchangeOrNull(x25519PrivateKey, ephPub) ?: return null

        val tweak = HKDF.derive(ByteArray(0), sshWireBlob, SSH_ED25519_INFO.toByteArray(), 32)
        shared = X25519Crypto.keyExchangeOrNull(tweak, shared) ?: return null

        val salt = ephPub + x25519PublicKey
        val wrapKey = HKDF.derive(shared, salt, SSH_ED25519_INFO.toByteArray(), 32)
        return try {
            ChaChaPoly.decrypt(wrapKey, ZERO_NONCE_12, stanza.body)
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        /**
         * Parse a `-----BEGIN OPENSSH PRIVATE KEY-----` PEM into an Identity.
         * If the PEM is passphrase-encrypted, supply `passphrase`. Throws on wrong/missing
         * passphrase (detected via check1/check2 mismatch after decryption).
         */
        fun fromPEM(pem: String, passphrase: String? = null): SSHEd25519Identity {
            val parsed = OpenSSHPrivateKey.parse(pem, passphrase)
            require(parsed is OpenSSHPrivateKey.Ed25519) {
                "expected ssh-ed25519, got '${parsed.keyType}'"
            }
            return SSHEd25519Identity(parsed)
        }

        fun generate(): SSHEd25519Identity {
            val priv = Ed25519PrivateKeyParameters(java.security.SecureRandom())
            return SSHEd25519Identity(priv.encoded)
        }
    }
}
