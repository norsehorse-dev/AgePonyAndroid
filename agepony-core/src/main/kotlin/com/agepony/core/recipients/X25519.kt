package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.bech32.Bech32
import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.HKDF
import com.agepony.core.crypto.X25519Crypto

private const val X25519_HRP_PUB = "age"
private const val X25519_HRP_SEC = "AGE-SECRET-KEY-"
private const val X25519_STANZA_TYPE = "X25519"
private const val X25519_HKDF_INFO = "age-encryption.org/v1/X25519"
private val ZERO_NONCE_12 = ByteArray(12)

/**
 * An age X25519 public-key recipient.
 *
 * Wrap: generate ephemeral keypair (e, E), shared = e*recipientPub,
 *   salt = E || recipientPub,
 *   info = "age-encryption.org/v1/X25519",
 *   wrapKey = HKDF-SHA256(ikm=shared, salt=salt, info=info, L=32),
 *   body = ChaCha20Poly1305(wrapKey, 0-nonce, fileKey).
 *
 * Stanza: type="X25519", args=[base64NoPad(E)].
 */
class X25519Recipient(val publicKey: ByteArray) : AgeRecipient {
    init {
        require(publicKey.size == 32) { "X25519 public key must be 32 bytes" }
    }

    /** Parse a Bech32 `age1...` string. */
    constructor(bech32: String) : this(decodeBech32Pub(bech32))

    override fun wrap(fileKey: ByteArray): Stanza {
        val ephPriv = X25519Crypto.generatePrivateKey()
        val ephPub = X25519Crypto.publicKey(ephPriv)
        val shared = X25519Crypto.keyExchange(ephPriv, publicKey)
        if (isAllZero(shared)) {
            // RFC 7748 §6.1 / age spec: low-order point yields zero shared secret; reject.
            throw IllegalArgumentException("X25519 shared secret is zero (low-order point)")
        }
        val salt = ephPub + publicKey
        val wrapKey = HKDF.derive(shared, salt, X25519_HKDF_INFO.toByteArray(), 32)
        val body = ChaChaPoly.encrypt(wrapKey, ZERO_NONCE_12, fileKey)
        return Stanza(X25519_STANZA_TYPE, listOf(Stanza.base64NoPad(ephPub)), body)
    }

    /** Encode this public key as a Bech32 `age1...` string. */
    fun toBech32(): String = Bech32.encode(X25519_HRP_PUB, publicKey)

    private fun isAllZero(b: ByteArray): Boolean = b.all { it == 0.toByte() }

    companion object {
        private fun decodeBech32Pub(s: String): ByteArray {
            val (hrp, bytes) = Bech32.decode(s)
            if (hrp != X25519_HRP_PUB) throw IllegalArgumentException(
                "expected HRP '$X25519_HRP_PUB', got '$hrp'"
            )
            if (bytes.size != 32) throw IllegalArgumentException(
                "expected 32-byte pub key, got ${bytes.size}"
            )
            return bytes
        }
    }
}

/**
 * An age X25519 private-key identity.
 *
 * Unwrap: parse ephemeral E from args[0], compute shared = identityPriv*E,
 *   derive wrapKey identically, attempt ChaCha20Poly1305 decrypt; return null if not for us.
 */
class X25519Identity(val privateKey: ByteArray) : AgeIdentity {
    val publicKey: ByteArray = X25519Crypto.publicKey(privateKey)

    init {
        require(privateKey.size == 32) { "X25519 private key must be 32 bytes" }
    }

    /** Parse a Bech32 `AGE-SECRET-KEY-1...` string (case-insensitive per BIP-0173). */
    constructor(bech32: String) : this(decodeBech32Sec(bech32))

    override fun unwrap(stanza: Stanza): ByteArray? {
        if (stanza.type != X25519_STANZA_TYPE) return null
        if (stanza.args.size != 1) return null
        val ephPub = try {
            Stanza.base64Decode(stanza.args[0])
        } catch (e: Exception) {
            return null
        }
        if (ephPub.size != 32) return null
        val shared = X25519Crypto.keyExchange(privateKey, ephPub)
        if (isAllZero(shared)) return null   // low-order ephemeral; reject silently
        val salt = ephPub + publicKey
        val wrapKey = HKDF.derive(shared, salt, X25519_HKDF_INFO.toByteArray(), 32)
        return try {
            ChaChaPoly.decrypt(wrapKey, ZERO_NONCE_12, stanza.body)
        } catch (e: Exception) {
            null  // not our stanza
        }
    }

    /** Encode this private key as a Bech32 `AGE-SECRET-KEY-1...` string (uppercase per age convention). */
    fun toBech32(): String = Bech32.encode(X25519_HRP_SEC, privateKey).uppercase()

    private fun isAllZero(b: ByteArray): Boolean = b.all { it == 0.toByte() }

    companion object {
        /** Generate a fresh X25519 identity from random bytes. */
        fun generate(): X25519Identity = X25519Identity(X25519Crypto.generatePrivateKey())

        private fun decodeBech32Sec(s: String): ByteArray {
            val (hrp, bytes) = Bech32.decode(s)
            if (!hrp.equals(X25519_HRP_SEC, ignoreCase = true)) throw IllegalArgumentException(
                "expected HRP '$X25519_HRP_SEC', got '$hrp'"
            )
            if (bytes.size != 32) throw IllegalArgumentException(
                "expected 32-byte private key, got ${bytes.size}"
            )
            return bytes
        }
    }
}
