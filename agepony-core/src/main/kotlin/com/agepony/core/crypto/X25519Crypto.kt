package com.agepony.core.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom

/**
 * X25519 key generation, public key derivation, and key exchange.
 */
object X25519Crypto {
    /**
     * Generate a random 32-byte X25519 private key (uniformly random; BC clamps when used).
     */
    fun generatePrivateKey(): ByteArray {
        val priv = X25519PrivateKeyParameters(SecureRandom())
        return priv.encoded
    }

    /**
     * Derive the public key (32 bytes) for the given private key (32 bytes).
     */
    fun publicKey(privateKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "X25519 private key must be 32 bytes, got ${privateKey.size}" }
        val priv = X25519PrivateKeyParameters(privateKey, 0)
        return priv.generatePublicKey().encoded
    }

    /**
     * X25519 Diffie-Hellman: returns the 32-byte shared secret. Throws [IllegalStateException]
     * (from Bouncy Castle) when the peer key is a low-order point and the result would be all
     * zeros; see [keyExchangeOrNull].
     */
    fun keyExchange(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "private key must be 32 bytes" }
        require(peerPublicKey.size == 32) { "peer public key must be 32 bytes" }
        val priv = X25519PrivateKeyParameters(privateKey, 0)
        val pub = X25519PublicKeyParameters(peerPublicKey, 0)
        val agreement = X25519Agreement()
        agreement.init(priv)
        val shared = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(pub, shared, 0)
        return shared
    }

    /**
     * [keyExchange], but null for a low-order peer point. Bouncy Castle already refuses the
     * all-zero shared secret RFC 7748 section 6.1 warns about by throwing
     * [IllegalStateException], which made the old `isAllZero` checks after it unreachable; this
     * turns that into the "not for me" answer an identity needs (audit L-14 parity).
     */
    fun keyExchangeOrNull(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray? = try {
        keyExchange(privateKey, peerPublicKey)
    } catch (_: IllegalStateException) {
        null
    }
}
