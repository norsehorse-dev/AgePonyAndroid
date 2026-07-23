package com.agepony.core.crypto

import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The MLKEM768-X25519 hybrid KEM (a.k.a. X-Wing, `0x647a`) wrapped in single-shot
 * HPKE (RFC 9180) base mode, exactly as age's `mlkem768x25519` recipient uses it.
 *
 * KEM (draft-ietf-hpke-pq / filippo.io/hpke):
 *   - identity is a 32-byte seed; SHAKE256(seed) yields the 64-byte ML-KEM key seed
 *     followed by the 32-byte X25519 scalar,
 *   - public key = `ek_PQ(1184) || ek_T(32)`,
 *   - encap: `ss = SHA3-256(ss_PQ || ss_T || ct_T || ek_T || label)`,
 *     `enc = ct_PQ(1088) || ct_T(32)` where `label = 5c2e2f2f5e5c`.
 *
 * HPKE suite: KEM `0x647a`, KDF HKDF-SHA256 (`0x0001`), AEAD ChaCha20Poly1305 (`0x0003`).
 * The file key (16 bytes) seals to a 32-byte body.
 *
 * Verified byte-for-byte against filippo.io/hpke reference known-answer vectors.
 */
object HpkeMlkem768X25519 {
    const val KEM_ID = 0x647a
    const val KDF_ID = 0x0001
    const val AEAD_ID = 0x0003

    const val SEED_SIZE = 32                                   // identity seed
    const val PUBLIC_KEY_SIZE = MLKEM768.ENCAPS_KEY_SIZE + 32  // 1184 + 32 = 1216
    const val ENC_SIZE = MLKEM768.CIPHERTEXT_SIZE + 32         // 1088 + 32 = 1120

    // The hybrid KEM combiner label: the literal bytes `\.//^\`.
    private val LABEL = byteArrayOf(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c)

    // HPKE suite_id = "HPKE" || I2OSP(kem,2) || I2OSP(kdf,2) || I2OSP(aead,2).
    private val SUITE_ID = "HPKE".toByteArray(Charsets.US_ASCII) + be16(KEM_ID) + be16(KDF_ID) + be16(AEAD_ID)
    private val HPKE_V1 = "HPKE-v1".toByteArray(Charsets.US_ASCII)

    // ---- Key derivation ----

    /**
     * A hybrid private key derived from a 32-byte identity seed. Holds the ML-KEM
     * keypair (for decap), the X25519 scalar, and the concatenated public key.
     */
    class PrivateKey(seed: ByteArray) {
        init { require(seed.size == SEED_SIZE) { "hybrid seed must be $SEED_SIZE bytes, got ${seed.size}" } }

        val mlkem: MLKEM768.KeyPair
        val x25519Priv: ByteArray
        val publicKey: ByteArray

        init {
            // SHAKE256(seed) -> 64-byte ML-KEM seed, then 32-byte X25519 scalar (one XOF stream).
            val expanded = Sha3.shake256(seed, MLKEM768.SEED_SIZE + 32)
            val mlkemSeed = expanded.copyOfRange(0, MLKEM768.SEED_SIZE)
            x25519Priv = expanded.copyOfRange(MLKEM768.SEED_SIZE, MLKEM768.SEED_SIZE + 32)
            mlkem = MLKEM768.keyPairFromSeed(mlkemSeed)
            val x25519Pub = X25519Crypto.publicKey(x25519Priv)
            publicKey = mlkem.encapsulationKey + x25519Pub
        }
    }

    private fun publicKeyParts(pk: ByteArray): Pair<ByteArray, ByteArray> {
        require(pk.size == PUBLIC_KEY_SIZE) { "hybrid public key must be $PUBLIC_KEY_SIZE bytes, got ${pk.size}" }
        val ekPQ = pk.copyOfRange(0, MLKEM768.ENCAPS_KEY_SIZE)
        val ekT = pk.copyOfRange(MLKEM768.ENCAPS_KEY_SIZE, PUBLIC_KEY_SIZE)
        return ekPQ to ekT
    }

    private fun combine(ssPQ: ByteArray, ssT: ByteArray, ctT: ByteArray, ekT: ByteArray): ByteArray =
        Sha3.sha3_256(ssPQ + ssT + ctT + ekT + LABEL)

    // ---- KEM ----

    /**
     * Encapsulate to `publicKey`, returning `(sharedSecret 32B, enc 1120B)`.
     * `testRandom`, when supplied, is 64 bytes: ML-KEM `m` (32) || X25519 ephemeral
     * scalar (32), making the operation deterministic for known-answer tests.
     */
    fun encap(publicKey: ByteArray, testRandom: ByteArray? = null): Pair<ByteArray, ByteArray> {
        val (ekPQ, ekT) = publicKeyParts(publicKey)
        val pub = MLKEM768.publicFromBytes(ekPQ)
        val m = testRandom?.copyOfRange(0, 32)
        val (ssPQ, ctPQ) = MLKEM768.encapsulate(pub, m)

        val ephPriv = testRandom?.copyOfRange(32, 64) ?: X25519Crypto.generatePrivateKey()
        val ctT = X25519Crypto.publicKey(ephPriv)
        val ssT = X25519Crypto.keyExchange(ephPriv, ekT)

        val ss = combine(ssPQ, ssT, ctT, ekT)
        return ss to (ctPQ + ctT)
    }

    /** Decapsulate `enc` (1120B) with `priv`, returning the 32-byte shared secret. */
    fun decap(priv: PrivateKey, enc: ByteArray): ByteArray {
        require(enc.size == ENC_SIZE) { "enc must be $ENC_SIZE bytes, got ${enc.size}" }
        val ctPQ = enc.copyOfRange(0, MLKEM768.CIPHERTEXT_SIZE)
        val ctT = enc.copyOfRange(MLKEM768.CIPHERTEXT_SIZE, ENC_SIZE)
        val ssPQ = MLKEM768.decapsulate(priv.mlkem.privateParams, ctPQ)
        val ekT = X25519Crypto.publicKey(priv.x25519Priv)
        val ssT = X25519Crypto.keyExchange(priv.x25519Priv, ctT)
        return combine(ssPQ, ssT, ctT, ekT)
    }

    // ---- HPKE base mode (single-shot) ----

    /**
     * Seal `plaintext` to `publicKey` under `info`, returning `(enc, ciphertext)`.
     * A single Seal uses sequence number 0, so the AEAD nonce is exactly base_nonce.
     */
    fun seal(
        publicKey: ByteArray,
        info: ByteArray,
        plaintext: ByteArray,
        testRandom: ByteArray? = null,
    ): Pair<ByteArray, ByteArray> {
        val (ss, enc) = encap(publicKey, testRandom)
        val ctx = keySchedule(ss, info)
        val ct = ChaChaPoly.encrypt(ctx.key, ctx.baseNonce, plaintext)
        return enc to ct
    }

    /** Open `ciphertext` produced by [seal] for `enc` under `info`. */
    fun open(priv: PrivateKey, enc: ByteArray, info: ByteArray, ciphertext: ByteArray): ByteArray {
        val ss = decap(priv, enc)
        val ctx = keySchedule(ss, info)
        return ChaChaPoly.decrypt(ctx.key, ctx.baseNonce, ciphertext)
    }

    private class Context(val key: ByteArray, val baseNonce: ByteArray)

    private fun keySchedule(sharedSecret: ByteArray, info: ByteArray): Context {
        val pskIdHash = labeledExtract(ByteArray(0), "psk_id_hash", ByteArray(0))
        val infoHash = labeledExtract(ByteArray(0), "info_hash", info)
        val ksContext = byteArrayOf(0) + pskIdHash + infoHash            // mode_base = 0x00
        val secret = labeledExtract(sharedSecret, "secret", ByteArray(0))
        val key = labeledExpand(secret, "key", ksContext, 32)           // Nk
        val baseNonce = labeledExpand(secret, "base_nonce", ksContext, 12) // Nn
        return Context(key, baseNonce)
    }

    private fun labeledExtract(salt: ByteArray, label: String, ikm: ByteArray): ByteArray =
        hkdfExtract(salt, HPKE_V1 + SUITE_ID + label.toByteArray(Charsets.US_ASCII) + ikm)

    private fun labeledExpand(prk: ByteArray, label: String, info: ByteArray, length: Int): ByteArray =
        hkdfExpand(prk, be16(length) + HPKE_V1 + SUITE_ID + label.toByteArray(Charsets.US_ASCII) + info, length)

    // ---- HKDF-SHA256 primitives (RFC 5869), extract and expand kept separate for HPKE ----

    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val key = if (salt.isEmpty()) ByteArray(32) else salt   // empty salt -> HashLen zeros
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(ikm)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            mac.reset()
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            out.write(t)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    private fun be16(v: Int): ByteArray = byteArrayOf((v ushr 8).toByte(), v.toByte())
}
