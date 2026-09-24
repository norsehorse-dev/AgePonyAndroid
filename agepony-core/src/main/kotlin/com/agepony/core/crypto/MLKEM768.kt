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

    /** ML-KEM modulus q. */
    private const val Q = 3329

    /** Bytes of ByteEncode12(t): k = 3 polynomials of 256 12-bit coefficients. */
    private const val T_BYTES = 1152

    /**
     * FIPS 203 section 7.2 encapsulation-key modulus check: ByteDecode12 the first 1152 bytes
     * and require every coefficient to be below q = 3329, i.e. the key re-encodes to itself.
     * Implemented here rather than trusting the provider to do it (audit L-12 on iOS; the same
     * gap applies to BC 1.78/1.79). A key that fails it would produce files nobody can decrypt.
     */
    fun isValidEncapsulationKey(encapsKey: ByteArray): Boolean {
        if (encapsKey.size != ENCAPS_KEY_SIZE) return false
        var i = 0
        while (i < T_BYTES) {
            val b0 = encapsKey[i].toInt() and 0xff
            val b1 = encapsKey[i + 1].toInt() and 0xff
            val b2 = encapsKey[i + 2].toInt() and 0xff
            val c0 = b0 or ((b1 and 0x0f) shl 8)
            val c1 = (b1 ushr 4) or (b2 shl 4)
            if (c0 >= Q || c1 >= Q) return false
            i += 3
        }
        return true
    }

    /** Throws [IllegalArgumentException] unless [encapsKey] passes [isValidEncapsulationKey]. */
    fun requireValidEncapsulationKey(encapsKey: ByteArray) {
        require(encapsKey.size == ENCAPS_KEY_SIZE) {
            "ML-KEM encapsulation key must be $ENCAPS_KEY_SIZE bytes, got ${encapsKey.size}"
        }
        require(isValidEncapsulationKey(encapsKey)) {
            "ML-KEM encapsulation key is malformed (a coefficient is not reduced mod $Q)"
        }
    }

    /**
     * Reconstruct a public (encapsulation) key from its 1184-byte encoding, after the FIPS 203
     * modulus check, so encrypting to a malformed key fails here instead of writing a file.
     */
    fun publicFromBytes(encapsKey: ByteArray): MLKEMPublicKeyParameters {
        requireValidEncapsulationKey(encapsKey)
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
