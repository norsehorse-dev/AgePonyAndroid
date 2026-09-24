package com.agepony.core.crypto

import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * P-256 ECDH as a pluggable operation. The private half may live in software ([P256SoftwareKey])
 * or in secure hardware (Android Keystore, Secure Enclave, a YubiKey), which is why decapsulation
 * never touches a scalar directly.
 */
fun interface P256KeyAgreement {
    /**
     * ECDH with [peerUncompressed] (a 65-byte SEC1 uncompressed point), returning the 32-byte
     * big-endian x-coordinate of the shared point.
     */
    fun sharedX(peerUncompressed: ByteArray): ByteArray
}

/** Curve helpers for P-256 (secp256r1) over Bouncy Castle. */
object P256Curve {
    val domain: ECDomainParameters by lazy {
        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        ECDomainParameters(spec.curve, spec.g, spec.n, spec.h)
    }

    const val UNCOMPRESSED_SIZE = 65
    const val COMPRESSED_SIZE = 33
    const val SCALAR_SIZE = 32

    /** Decode a compressed or uncompressed point, rejecting infinity and off-curve input. */
    fun decode(encoded: ByteArray): ECPoint {
        // Only SEC1 compressed (02/03, 33 bytes) and uncompressed (04, 65 bytes), as Go's
        // crypto/ecdh accepts. Bouncy Castle would also take the "hybrid" 06/07 forms, which
        // age rejects, and a recipient that parses here but not in age can never be decrypted.
        require(
            (encoded.size == COMPRESSED_SIZE && (encoded[0] == 0x02.toByte() || encoded[0] == 0x03.toByte())) ||
                (encoded.size == UNCOMPRESSED_SIZE && encoded[0] == 0x04.toByte())
        ) { "invalid P-256 point encoding" }
        val p = domain.curve.decodePoint(encoded).normalize()
        require(!p.isInfinity && p.isValid) { "invalid P-256 point" }
        return p
    }

    fun uncompressed(p: ECPoint): ByteArray = p.normalize().getEncoded(false)
    fun compressed(p: ECPoint): ByteArray = p.normalize().getEncoded(true)

    fun toUncompressed(encoded: ByteArray): ByteArray = uncompressed(decode(encoded))

    // Byte/BigInteger-only helpers for callers outside this module: Bouncy Castle is an
    // implementation dependency of agepony-core, so its ECPoint type isn't visible to the app.

    /** Validated affine (x, y) of a SEC1-encoded point. */
    fun affineXY(encoded: ByteArray): Pair<BigInteger, BigInteger> {
        val p = decode(encoded)
        return p.affineXCoord.toBigInteger() to p.affineYCoord.toBigInteger()
    }

    /** A fresh random public point, uncompressed. For probing a key agreement. */
    fun randomPublicUncompressed(): ByteArray = uncompressed(publicPoint(randomScalar()))
    fun toCompressed(encoded: ByteArray): ByteArray = compressed(decode(encoded))

    /** True if [d] is a valid private scalar (0 < d < n). */
    fun isValidScalar(d: BigInteger): Boolean = d.signum() > 0 && d < domain.n

    fun randomScalar(rng: SecureRandom = SecureRandom()): BigInteger {
        while (true) {
            val b = ByteArray(SCALAR_SIZE).also { rng.nextBytes(it) }
            val d = BigInteger(1, b)
            if (isValidScalar(d)) return d
        }
    }

    fun publicPoint(d: BigInteger): ECPoint = domain.g.multiply(d).normalize()

    /** x-coordinate of d*peer, fixed 32 bytes. */
    fun ecdhX(d: BigInteger, peer: ECPoint): ByteArray {
        val s = peer.multiply(d).normalize()
        require(!s.isInfinity) { "P-256 shared point is the point at infinity" }
        return s.affineXCoord.encoded
    }
}

/** A P-256 private key held in software. Used for tests and for any non-hardware path. */
class P256SoftwareKey(private val d: BigInteger) : P256KeyAgreement {
    init { require(P256Curve.isValidScalar(d)) { "invalid P-256 scalar" } }

    val publicUncompressed: ByteArray = P256Curve.uncompressed(P256Curve.publicPoint(d))

    override fun sharedX(peerUncompressed: ByteArray): ByteArray =
        P256Curve.ecdhX(d, P256Curve.decode(peerUncompressed))

    companion object {
        fun generate(): P256SoftwareKey = P256SoftwareKey(P256Curve.randomScalar())
    }
}

/**
 * HPKE (RFC 9180) base mode, single shot, with KDF HKDF-SHA256 (0x0001) and AEAD
 * ChaCha20Poly1305 (0x0003), for the two KEMs age's tag recipients use:
 *
 *   - DHKEM(P-256, HKDF-SHA256), KEM id 0x0010, for `p256tag`,
 *   - MLKEM768-P256 from draft-ietf-hpke-pq, KEM id 0x0050, for `mlkem768p256tag`.
 *
 * Mirrors filippo.io/hpke v0.4.0 (the implementation age 1.3 uses). Decapsulation takes a
 * [P256KeyAgreement], so the P-256 half can be a hardware key.
 */
object HpkeP256 {
    const val KEM_DHKEM_P256 = 0x0010
    const val KEM_MLKEM768_P256 = 0x0050
    private const val KDF_HKDF_SHA256 = 0x0001
    private const val AEAD_CHACHA20POLY1305 = 0x0003

    const val DHKEM_ENC_SIZE = P256Curve.UNCOMPRESSED_SIZE                                  // 65
    const val HYBRID_PUBLIC_KEY_SIZE = MLKEM768.ENCAPS_KEY_SIZE + P256Curve.UNCOMPRESSED_SIZE // 1249
    const val HYBRID_ENC_SIZE = MLKEM768.CIPHERTEXT_SIZE + P256Curve.UNCOMPRESSED_SIZE        // 1153
    const val HYBRID_SEED_SIZE = 32

    private val HPKE_V1 = "HPKE-v1".toByteArray(Charsets.US_ASCII)
    private val HYBRID_LABEL = "MLKEM768-P256".toByteArray(Charsets.US_ASCII)

    // ---- DHKEM(P-256, HKDF-SHA256) ----

    /** Encapsulate to a P-256 public key (any SEC1 encoding). Returns (sharedSecret, enc). */
    fun dhkemEncap(recipientPub: ByteArray, ephemeral: BigInteger? = null): Pair<ByteArray, ByteArray> {
        val pkR = P256Curve.decode(recipientPub)
        val e = ephemeral ?: P256Curve.randomScalar()
        val enc = P256Curve.uncompressed(P256Curve.publicPoint(e))
        val dh = P256Curve.ecdhX(e, pkR)
        return dhkemExtractAndExpand(dh, enc + P256Curve.uncompressed(pkR)) to enc
    }

    /** Decapsulate [enc] for the key behind [ka], whose public key is [recipientPub]. */
    fun dhkemDecap(enc: ByteArray, ka: P256KeyAgreement, recipientPub: ByteArray): ByteArray {
        require(enc.size == DHKEM_ENC_SIZE) { "DHKEM(P-256) enc must be $DHKEM_ENC_SIZE bytes" }
        P256Curve.decode(enc) // reject off-curve input before it reaches hardware
        val dh = ka.sharedX(enc)
        return dhkemExtractAndExpand(dh, enc + P256Curve.toUncompressed(recipientPub))
    }

    private fun dhkemExtractAndExpand(dh: ByteArray, kemContext: ByteArray): ByteArray {
        val suite = kemSuite(KEM_DHKEM_P256)
        val prk = labeledExtract(suite, ByteArray(0), "eae_prk", dh)
        return labeledExpand(suite, prk, "shared_secret", kemContext, 32)
    }

    /** RFC 9180 7.1.3 DeriveKeyPair for DHKEM(P-256). Deterministic; used for test vectors. */
    fun dhkemDeriveKeyPair(ikm: ByteArray): BigInteger {
        val suite = kemSuite(KEM_DHKEM_P256)
        val prk = labeledExtract(suite, ByteArray(0), "dkp_prk", ikm)
        for (counter in 0 until 256) {
            val candidate = labeledExpand(suite, prk, "candidate", byteArrayOf(counter.toByte()), 32)
            val d = BigInteger(1, candidate)
            if (P256Curve.isValidScalar(d)) return d
        }
        throw IllegalStateException("DeriveKeyPair failed")
    }

    // ---- MLKEM768-P256 ----

    /** Hybrid private key material: ML-KEM half in software, P-256 half behind [p256]. */
    class HybridPrivateKey(
        val mlkem: MLKEM768.KeyPair,
        val p256: P256KeyAgreement,
        val p256PublicUncompressed: ByteArray,
    ) {
        init { require(p256PublicUncompressed.size == P256Curve.UNCOMPRESSED_SIZE) }
        val publicKey: ByteArray get() = mlkem.encapsulationKey + p256PublicUncompressed
    }

    /**
     * Expand a 32-byte hybrid seed as filippo.io/hpke `NewPrivateKey` does: one SHAKE256 stream
     * yields the 64-byte ML-KEM seed, then 32-byte P-256 candidates until one is a valid scalar.
     * Returns the ML-KEM seed and the P-256 scalar.
     */
    fun hybridExpandSeed(seed: ByteArray): Pair<ByteArray, BigInteger> {
        require(seed.size == HYBRID_SEED_SIZE) { "hybrid seed must be $HYBRID_SEED_SIZE bytes" }
        for (tries in 1..64) {
            val stream = Sha3.shake256(seed, MLKEM768.SEED_SIZE + 32 * tries)
            val candidate = BigInteger(1, stream.copyOfRange(stream.size - 32, stream.size))
            if (P256Curve.isValidScalar(candidate)) {
                return stream.copyOfRange(0, MLKEM768.SEED_SIZE) to candidate
            }
        }
        throw IllegalStateException("hybrid seed expansion failed")
    }

    /** A fully software hybrid key from a 32-byte seed. */
    fun hybridFromSeed(seed: ByteArray): HybridPrivateKey {
        val (mlkemSeed, d) = hybridExpandSeed(seed)
        val sw = P256SoftwareKey(d)
        return HybridPrivateKey(MLKEM768.keyPairFromSeed(mlkemSeed), sw, sw.publicUncompressed)
    }

    /** draft-ietf-hpke-pq DeriveKeyPair for MLKEM768-P256 (SHAKE256 labeled derive to a 32-byte seed). */
    fun hybridDeriveSeed(ikm: ByteArray): ByteArray {
        val suite = kemSuite(KEM_MLKEM768_P256)
        val label = "DeriveKeyPair".toByteArray(Charsets.US_ASCII)
        val input = ikm + HPKE_V1 + suite + be16(label.size) + label + be16(32)
        return Sha3.shake256(input, 32)
    }

    /**
     * Encapsulate to a 1249-byte hybrid public key (`ek_PQ || P-256 uncompressed`).
     * [testRandom], when given, is 64 bytes: ML-KEM `m` || P-256 ephemeral scalar.
     */
    fun hybridEncap(publicKey: ByteArray, testRandom: ByteArray? = null): Pair<ByteArray, ByteArray> {
        require(publicKey.size == HYBRID_PUBLIC_KEY_SIZE) { "MLKEM768-P256 public key must be $HYBRID_PUBLIC_KEY_SIZE bytes" }
        val ekPQ = publicKey.copyOfRange(0, MLKEM768.ENCAPS_KEY_SIZE)
        val ekT = publicKey.copyOfRange(MLKEM768.ENCAPS_KEY_SIZE, publicKey.size)
        val pkT = P256Curve.decode(ekT)

        val e = testRandom?.let { BigInteger(1, it.copyOfRange(32, 64)) } ?: P256Curve.randomScalar()
        val ssT = P256Curve.ecdhX(e, pkT)
        val ctT = P256Curve.uncompressed(P256Curve.publicPoint(e))
        val (ssPQ, ctPQ) = MLKEM768.encapsulate(MLKEM768.publicFromBytes(ekPQ), testRandom?.copyOfRange(0, 32))
        return hybridCombine(ssPQ, ssT, ctT, ekT) to (ctPQ + ctT)
    }

    fun hybridDecap(priv: HybridPrivateKey, enc: ByteArray): ByteArray {
        require(enc.size == HYBRID_ENC_SIZE) { "MLKEM768-P256 enc must be $HYBRID_ENC_SIZE bytes" }
        val ctPQ = enc.copyOfRange(0, MLKEM768.CIPHERTEXT_SIZE)
        val ctT = enc.copyOfRange(MLKEM768.CIPHERTEXT_SIZE, enc.size)
        P256Curve.decode(ctT)
        val ssPQ = MLKEM768.decapsulate(priv.mlkem.privateParams, ctPQ)
        val ssT = priv.p256.sharedX(ctT)
        return hybridCombine(ssPQ, ssT, ctT, priv.p256PublicUncompressed)
    }

    private fun hybridCombine(ssPQ: ByteArray, ssT: ByteArray, ctT: ByteArray, ekT: ByteArray): ByteArray =
        Sha3.sha3_256(ssPQ + ssT + ctT + ekT + HYBRID_LABEL)

    // ---- HPKE single-shot seal/open ----

    fun seal(kemId: Int, sharedSecret: ByteArray, info: ByteArray, plaintext: ByteArray): ByteArray {
        val (key, nonce) = keySchedule(kemId, sharedSecret, info)
        return ChaChaPoly.encrypt(key, nonce, plaintext)
    }

    fun open(kemId: Int, sharedSecret: ByteArray, info: ByteArray, ciphertext: ByteArray): ByteArray {
        val (key, nonce) = keySchedule(kemId, sharedSecret, info)
        return ChaChaPoly.decrypt(key, nonce, ciphertext)
    }

    private fun keySchedule(kemId: Int, ss: ByteArray, info: ByteArray): Pair<ByteArray, ByteArray> {
        val suite = "HPKE".toByteArray(Charsets.US_ASCII) + be16(kemId) + be16(KDF_HKDF_SHA256) + be16(AEAD_CHACHA20POLY1305)
        val pskIdHash = labeledExtract(suite, ByteArray(0), "psk_id_hash", ByteArray(0))
        val infoHash = labeledExtract(suite, ByteArray(0), "info_hash", info)
        val ctx = byteArrayOf(0) + pskIdHash + infoHash
        val secret = labeledExtract(suite, ss, "secret", ByteArray(0))
        return labeledExpand(suite, secret, "key", ctx, 32) to labeledExpand(suite, secret, "base_nonce", ctx, 12)
    }

    // ---- HKDF-SHA256 with HPKE labels ----

    private fun kemSuite(kemId: Int): ByteArray = "KEM".toByteArray(Charsets.US_ASCII) + be16(kemId)

    private fun labeledExtract(suite: ByteArray, salt: ByteArray, label: String, ikm: ByteArray): ByteArray =
        hkdfExtract(salt, HPKE_V1 + suite + label.toByteArray(Charsets.US_ASCII) + ikm)

    private fun labeledExpand(suite: ByteArray, prk: ByteArray, label: String, info: ByteArray, length: Int): ByteArray =
        hkdfExpand(prk, be16(length) + HPKE_V1 + suite + label.toByteArray(Charsets.US_ASCII) + info, length)

    internal fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
        return mac.doFinal(ikm)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            mac.reset(); mac.update(t); mac.update(info); mac.update(counter.toByte())
            t = mac.doFinal(); out.write(t); counter++
        }
        return out.toByteArray().copyOf(length)
    }

    private fun be16(v: Int): ByteArray = byteArrayOf((v ushr 8).toByte(), v.toByte())
}
