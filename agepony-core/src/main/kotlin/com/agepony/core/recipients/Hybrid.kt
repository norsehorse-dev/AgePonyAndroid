package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.bech32.Bech32
import com.agepony.core.crypto.HpkeMlkem768X25519
import java.security.SecureRandom

private const val HYBRID_HRP_PUB = "age1pq"
private const val HYBRID_HRP_SEC = "AGE-SECRET-KEY-PQ-"
private const val HYBRID_STANZA_TYPE = "mlkem768x25519"
private const val HYBRID_INFO = "age-encryption.org/mlkem768x25519"
private const val HYBRID_BODY_SIZE = 16 + 16   // file key (16) + ChaCha20Poly1305 tag (16)

/** age label marking a recipient as post-quantum; see [LabeledAgeRecipient]. */
const val POSTQUANTUM_LABEL = "postquantum"

/**
 * The post-quantum age recipient: the standardized MLKEM768-X25519 hybrid
 * (`mlkem768x25519` stanza, `age1pq1…` public key). Files encrypted to this
 * recipient interoperate with the `age` CLI v1.3.0+ and are safe against future
 * quantum computers.
 *
 * Wrap: `HPKE.Seal(publicKey, info = "age-encryption.org/mlkem768x25519", fileKey)`;
 *   stanza = type `mlkem768x25519`, args = [base64(enc)], body = HPKE ciphertext.
 *
 * Note: for real post-quantum security a file must not also carry a classical
 * recipient (the weakest recipient sets the bar). The reference enforces this via
 * a "postquantum" label; AgePony should surface/enforce that at the encrypt-flow
 * and migration layers.
 */
class HybridRecipient(val publicKey: ByteArray) : LabeledAgeRecipient {
    init {
        require(publicKey.size == HpkeMlkem768X25519.PUBLIC_KEY_SIZE) {
            "MLKEM768-X25519 public key must be ${HpkeMlkem768X25519.PUBLIC_KEY_SIZE} bytes, got ${publicKey.size}"
        }
    }

    /** This recipient is post-quantum; it may only share a file with other post-quantum recipients. */
    override fun labels(): Set<String> = setOf(POSTQUANTUM_LABEL)

    /** Parse a Bech32 `age1pq1…` string. */
    constructor(bech32: String) : this(decodeBech32Pub(bech32))

    override fun wrap(fileKey: ByteArray): Stanza = wrap(fileKey, null)

    /**
     * Test hook: deterministic wrap. `testRandom` is 64 bytes (ML-KEM `m` || X25519
     * ephemeral scalar). Production callers use [wrap].
     */
    internal fun wrap(fileKey: ByteArray, testRandom: ByteArray?): Stanza {
        val (enc, ct) = HpkeMlkem768X25519.seal(
            publicKey, HYBRID_INFO.toByteArray(Charsets.US_ASCII), fileKey, testRandom
        )
        return Stanza(HYBRID_STANZA_TYPE, listOf(Stanza.base64NoPad(enc)), ct)
    }

    /** Encode this public key as a Bech32 `age1pq1…` string. */
    fun toBech32(): String = Bech32.encode(HYBRID_HRP_PUB, publicKey)

    companion object {
        private fun decodeBech32Pub(s: String): ByteArray {
            val (hrp, bytes) = Bech32.decode(s)
            if (hrp != HYBRID_HRP_PUB) throw IllegalArgumentException(
                "expected HRP '$HYBRID_HRP_PUB', got '$hrp'"
            )
            if (bytes.size != HpkeMlkem768X25519.PUBLIC_KEY_SIZE) throw IllegalArgumentException(
                "expected ${HpkeMlkem768X25519.PUBLIC_KEY_SIZE}-byte public key, got ${bytes.size}"
            )
            return bytes
        }
    }
}

/**
 * The post-quantum age identity: a 32-byte seed encoded as `AGE-SECRET-KEY-PQ-1…`.
 * The ML-KEM and X25519 keys are derived deterministically from the seed.
 *
 * Unwrap: for a `mlkem768x25519` stanza, run `HPKE.Open`; returns null if the
 * stanza is not ours or authentication fails.
 */
class HybridIdentity private constructor(private val key: HpkeMlkem768X25519.PrivateKey, seed: ByteArray) : AgeIdentity {
    /** The 32-byte identity seed. */
    val seed: ByteArray = seed.copyOf()

    /** The 1216-byte hybrid public key. */
    val publicKey: ByteArray get() = key.publicKey

    constructor(seed: ByteArray) : this(HpkeMlkem768X25519.PrivateKey(seed), seed)

    /** Parse a Bech32 `AGE-SECRET-KEY-PQ-1…` string (case-insensitive per BIP-0173). */
    constructor(bech32: String) : this(decodeBech32Sec(bech32))

    override fun unwrap(stanza: Stanza): ByteArray? {
        if (stanza.type != HYBRID_STANZA_TYPE) return null
        if (stanza.args.size != 1) return null
        val enc = try {
            Stanza.base64Decode(stanza.args[0])
        } catch (e: Exception) {
            return null
        }
        if (enc.size != HpkeMlkem768X25519.ENC_SIZE) return null
        if (stanza.body.size != HYBRID_BODY_SIZE) return null
        return try {
            HpkeMlkem768X25519.open(key, enc, HYBRID_INFO.toByteArray(Charsets.US_ASCII), stanza.body)
        } catch (e: Exception) {
            null   // not our stanza / authentication failed
        }
    }

    /** The public [HybridRecipient] corresponding to this identity. */
    fun recipient(): HybridRecipient = HybridRecipient(key.publicKey)

    /** Encode this identity as a Bech32 `AGE-SECRET-KEY-PQ-1…` string (uppercase per age convention). */
    fun toBech32(): String = Bech32.encode(HYBRID_HRP_SEC, seed).uppercase()

    companion object {
        /** Generate a fresh hybrid identity from a random 32-byte seed. */
        fun generate(): HybridIdentity {
            val seed = ByteArray(HpkeMlkem768X25519.SEED_SIZE)
            SecureRandom().nextBytes(seed)
            return HybridIdentity(seed)
        }

        private fun decodeBech32Sec(s: String): ByteArray {
            val (hrp, bytes) = Bech32.decode(s)
            if (!hrp.equals(HYBRID_HRP_SEC, ignoreCase = true)) throw IllegalArgumentException(
                "expected HRP '$HYBRID_HRP_SEC', got '$hrp'"
            )
            if (bytes.size != HpkeMlkem768X25519.SEED_SIZE) throw IllegalArgumentException(
                "expected ${HpkeMlkem768X25519.SEED_SIZE}-byte seed, got ${bytes.size}"
            )
            return bytes
        }
    }
}
