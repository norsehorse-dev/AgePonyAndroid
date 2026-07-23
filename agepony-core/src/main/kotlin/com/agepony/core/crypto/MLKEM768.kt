package com.agepony.core.crypto

import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.SecureRandom

/**
 * ML-KEM-768 (FIPS 203) thin wrapper over Bouncy Castle, exposing exactly what the
 * MLKEM768-X25519 hybrid KEM needs:
 *
 *   - deterministic key generation from a 64-byte seed (`d || z`), so an age
 *     identity seed reproduces the same keypair on every device,
 *   - deterministic or random encapsulation,
 *   - decapsulation (with ML-KEM's built-in implicit rejection).
 *
 * The lattice math itself is delegated to Bouncy Castle (`bcprov-jdk18on`), which
 * ships FIPS 203 ML-KEM as of 1.78. Everything else in the hybrid construction is
 * assembled in [HpkeMlkem768X25519].
 */
object MLKEM768 {
    const val SEED_SIZE = 64            // ML-KEM key seed: d(32) || z(32)
    const val ENCAPS_KEY_SIZE = 1184    // encapsulation key: t(1152) || rho(32)
    const val CIPHERTEXT_SIZE = 1088
    const val SHARED_SECRET_SIZE = 32
    const val M_SIZE = 32               // encapsulation randomness

    private val params = MLKEMParameters.ml_kem_768

    /** A generated keypair: the encapsulation key bytes, plus BC private params for decap. */
    class KeyPair(val encapsulationKey: ByteArray, val privateParams: MLKEMPrivateKeyParameters)

    /**
     * Deterministic ML-KEM-768 key generation from a 64-byte seed `d || z`, matching
     * FIPS 203 `ML-KEM.KeyGen_internal`. Bouncy Castle's engine reads `d` then `z`
     * from the supplied randomness, so a fixed byte source reproduces the reference
     * keypair exactly.
     */
    fun keyPairFromSeed(seed64: ByteArray): KeyPair {
        require(seed64.size == SEED_SIZE) { "ML-KEM seed must be $SEED_SIZE bytes, got ${seed64.size}" }
        val gen = MLKEMKeyPairGenerator()
        gen.init(MLKEMKeyGenerationParameters(FixedRandom(seed64), params))
        val kp = gen.generateKeyPair()
        val pub = kp.public as MLKEMPublicKeyParameters
        val priv = kp.private as MLKEMPrivateKeyParameters
        return KeyPair(pub.encoded, priv)
    }

    /** Reconstruct a public (encapsulation) key from its 1184-byte encoding. */
    fun publicFromBytes(encapsKey: ByteArray): MLKEMPublicKeyParameters {
        require(encapsKey.size == ENCAPS_KEY_SIZE) {
            "ML-KEM encapsulation key must be $ENCAPS_KEY_SIZE bytes, got ${encapsKey.size}"
        }
        return MLKEMPublicKeyParameters(params, encapsKey)
    }

    /**
     * Encapsulate to `pub`, returning `(sharedSecret 32B, ciphertext 1088B)`.
     * When `m` (32 bytes) is supplied the operation is deterministic (known-answer
     * tests); otherwise fresh randomness is used.
     */
    fun encapsulate(pub: MLKEMPublicKeyParameters, m: ByteArray? = null): Pair<ByteArray, ByteArray> {
        val rand = if (m != null) {
            require(m.size == M_SIZE) { "ML-KEM encapsulation randomness must be $M_SIZE bytes" }
            FixedRandom(m)
        } else {
            SecureRandom()
        }
        val enc = MLKEMGenerator(rand).generateEncapsulated(pub)
        return enc.secret to enc.encapsulation
    }

    /** Decapsulate `ct` (1088 bytes) with `priv`, returning the 32-byte shared secret. */
    fun decapsulate(priv: MLKEMPrivateKeyParameters, ct: ByteArray): ByteArray {
        require(ct.size == CIPHERTEXT_SIZE) { "ML-KEM ciphertext must be $CIPHERTEXT_SIZE bytes, got ${ct.size}" }
        return MLKEMExtractor(priv).extractSecret(ct)
    }

    /**
     * A [SecureRandom] that returns bytes sequentially from a fixed buffer, so
     * Bouncy Castle's key generation and encapsulation become deterministic. Only
     * `nextBytes` is used by those code paths.
     */
    private class FixedRandom(private val buf: ByteArray) : SecureRandom() {
        private var pos = 0
        override fun nextBytes(bytes: ByteArray) {
            require(pos + bytes.size <= buf.size) { "FixedRandom exhausted" }
            System.arraycopy(buf, pos, bytes, 0, bytes.size)
            pos += bytes.size
        }
    }
}
