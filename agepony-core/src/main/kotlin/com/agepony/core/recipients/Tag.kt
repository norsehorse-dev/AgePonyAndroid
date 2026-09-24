package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.bech32.Bech32
import com.agepony.core.crypto.HpkeP256
import com.agepony.core.crypto.MLKEM768
import com.agepony.core.crypto.P256Curve
import com.agepony.core.crypto.P256KeyAgreement
import com.agepony.core.crypto.P256SoftwareKey
import java.math.BigInteger
import java.security.MessageDigest

private const val TAG_HRP = "age1tag"
private const val TAGPQ_HRP = "age1tagpq"
const val P256TAG_STANZA_TYPE = "p256tag"
const val MLKEM768P256TAG_STANZA_TYPE = "mlkem768p256tag"
private const val P256TAG_LABEL = "age-encryption.org/p256tag"
private const val MLKEM768P256TAG_LABEL = "age-encryption.org/mlkem768p256tag"
private const val TAG_SIZE = 4
private const val FILE_KEY_BODY_SIZE = 32

/**
 * age's tagged recipients (age v1.3, C2SP age.md), built for identities that live in hardware:
 *
 *   - classic `age1tag1...`: a 33-byte compressed P-256 point, stanza `p256tag`,
 *     HPKE DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305;
 *   - hybrid `age1tagpq1...`: ML-KEM-768 encapsulation key || 65-byte uncompressed P-256 point,
 *     stanza `mlkem768p256tag`, HPKE MLKEM768-P256. Post-quantum, so labeled "postquantum" and
 *     refused alongside non-PQ recipients.
 *
 * Stanza: `-> <type> base64(tag) base64(enc)` with a 32-byte body. The 4-byte tag is
 * HKDF-Extract(salt = label, ikm = enc || SHA-256(recipient)[:4])[:4], where the hybrid form
 * hashes only its P-256 part. It lets an identity recognise its stanza without an ECDH, which
 * matters when every ECDH is a hardware call behind a user prompt.
 *
 * Interoperates with stock age 1.3 (native support), age-plugin-yubikey, age-plugin-se and
 * age-plugin-tpm.
 */
class TagRecipient(publicKey: ByteArray) : LabeledAgeRecipient {
    /** Raw recipient encoding: 33-byte compressed point, or 1249-byte hybrid key. */
    val publicKey: ByteArray = publicKey.copyOf()

    val hybrid: Boolean = when (publicKey.size) {
        P256Curve.COMPRESSED_SIZE -> false
        HpkeP256.HYBRID_PUBLIC_KEY_SIZE -> true
        else -> throw IllegalArgumentException("tag recipient must be 33 or ${HpkeP256.HYBRID_PUBLIC_KEY_SIZE} bytes, got ${publicKey.size}")
    }

    init {
        // Validate the P-256 part up front so a bad key fails at parse time, not at encrypt time.
        P256Curve.decode(p256Part())
        if (hybrid) MLKEM768.publicFromBytes(publicKey.copyOfRange(0, MLKEM768.ENCAPS_KEY_SIZE))
    }

    constructor(bech32: String) : this(decodeBech32(bech32))

    val stanzaType: String get() = if (hybrid) MLKEM768P256TAG_STANZA_TYPE else P256TAG_STANZA_TYPE
    private val label: ByteArray get() = (if (hybrid) MLKEM768P256TAG_LABEL else P256TAG_LABEL).toByteArray(Charsets.US_ASCII)
    private val kemId: Int get() = if (hybrid) HpkeP256.KEM_MLKEM768_P256 else HpkeP256.KEM_DHKEM_P256

    /** The P-256 part: compressed point (classic) or uncompressed point (hybrid). */
    fun p256Part(): ByteArray =
        if (hybrid) publicKey.copyOfRange(MLKEM768.ENCAPS_KEY_SIZE, publicKey.size) else publicKey

    override fun labels(): Set<String> = if (hybrid) setOf(POSTQUANTUM_LABEL) else emptySet()

    override fun wrap(fileKey: ByteArray): Stanza = wrap(fileKey, null)

    /** Test hook. Classic: 32-byte ephemeral scalar. Hybrid: ML-KEM m (32) || P-256 scalar (32). */
    internal fun wrap(fileKey: ByteArray, testRandom: ByteArray?): Stanza {
        val (ss, enc) = if (hybrid) {
            HpkeP256.hybridEncap(publicKey, testRandom)
        } else {
            HpkeP256.dhkemEncap(publicKey, testRandom?.let { BigInteger(1, it) })
        }
        val body = HpkeP256.seal(kemId, ss, label, fileKey)
        return Stanza(stanzaType, listOf(Stanza.base64NoPad(tag(enc)), Stanza.base64NoPad(enc)), body)
    }

    /** The 4-byte tag for [enc] under this recipient. */
    fun tag(enc: ByteArray): ByteArray {
        val rh = MessageDigest.getInstance("SHA-256").digest(p256Part()).copyOf(TAG_SIZE)
        return HpkeP256.hkdfExtract(label, enc + rh).copyOf(TAG_SIZE)
    }

    fun toBech32(): String = Bech32.encode(if (hybrid) TAGPQ_HRP else TAG_HRP, publicKey)

    override fun equals(other: Any?): Boolean = other is TagRecipient && other.publicKey.contentEquals(publicKey)
    override fun hashCode(): Int = publicKey.contentHashCode()

    companion object {
        fun isTagRecipient(s: String): Boolean {
            val t = s.trim().lowercase()
            return t.startsWith("${TAG_HRP}1") || t.startsWith("${TAGPQ_HRP}1")
        }

        private fun decodeBech32(s: String): ByteArray {
            val (hrp, bytes) = Bech32.decode(s.trim())
            return when (hrp) {
                TAG_HRP -> bytes.also {
                    require(it.size == P256Curve.COMPRESSED_SIZE) { "age1tag1 recipient must be a 33-byte compressed point" }
                }
                TAGPQ_HRP -> bytes.also {
                    require(it.size == HpkeP256.HYBRID_PUBLIC_KEY_SIZE) { "age1tagpq1 recipient must be ${HpkeP256.HYBRID_PUBLIC_KEY_SIZE} bytes" }
                }
                else -> throw IllegalArgumentException("expected HRP '$TAG_HRP' or '$TAGPQ_HRP', got '$hrp'")
            }
        }
    }
}

/**
 * An identity for a [TagRecipient]. The P-256 private half is a [P256KeyAgreement], so it can be
 * a Keystore / Secure Enclave key; the ML-KEM half of a hybrid identity is software.
 *
 * [unwrap] checks the tag first and only then performs the ECDH, so a hardware key is asked to
 * act only for stanzas addressed to it. Errors from the key agreement itself (for example a
 * Keystore key that needs user authentication) propagate to the caller; a failed AEAD open or a
 * stanza for someone else returns null.
 */
class TagIdentity private constructor(
    val recipient: TagRecipient,
    private val p256: P256KeyAgreement,
    private val mlkem: MLKEM768.KeyPair?,
) : HardwareIdentity {

    /** True if [stanza] is a tag stanza addressed to this identity. Needs no private-key operation. */
    override fun matches(stanza: Stanza): Boolean = parse(stanza) != null

    override fun unwrap(stanza: Stanza): ByteArray? {
        val (enc, body) = parse(stanza) ?: return null
        val ss = if (recipient.hybrid) {
            HpkeP256.hybridDecap(
                HpkeP256.HybridPrivateKey(mlkem!!, p256, P256Curve.toUncompressed(recipient.p256Part())), enc
            )
        } else {
            HpkeP256.dhkemDecap(enc, p256, recipient.publicKey)
        }
        val kemId = if (recipient.hybrid) HpkeP256.KEM_MLKEM768_P256 else HpkeP256.KEM_DHKEM_P256
        val label = (if (recipient.hybrid) MLKEM768P256TAG_LABEL else P256TAG_LABEL).toByteArray(Charsets.US_ASCII)
        return try {
            HpkeP256.open(kemId, ss, label, body)
        } catch (e: Exception) {
            null
        }
    }

    private fun parse(stanza: Stanza): Pair<ByteArray, ByteArray>? {
        if (stanza.type != recipient.stanzaType || stanza.args.size != 2) return null
        if (stanza.body.size != FILE_KEY_BODY_SIZE) return null
        val tag = runCatching { Stanza.base64Decode(stanza.args[0]) }.getOrNull() ?: return null
        val enc = runCatching { Stanza.base64Decode(stanza.args[1]) }.getOrNull() ?: return null
        val encSize = if (recipient.hybrid) HpkeP256.HYBRID_ENC_SIZE else HpkeP256.DHKEM_ENC_SIZE
        if (tag.size != TAG_SIZE || enc.size != encSize) return null
        if (!MessageDigest.isEqual(tag, recipient.tag(enc))) return null
        return enc to stanza.body
    }

    companion object {
        /** A classic identity whose P-256 key sits behind [p256]; [compressedPublicKey] is its public point. */
        fun classic(compressedPublicKey: ByteArray, p256: P256KeyAgreement): TagIdentity =
            TagIdentity(TagRecipient(P256Curve.toCompressed(compressedPublicKey)), p256, null)

        /**
         * A hybrid identity: ML-KEM-768 from [mlkemSeed] (64 bytes, `d || z`) in software, P-256
         * behind [p256] with public point [p256Public] (any SEC1 encoding).
         */
        fun hybrid(mlkemSeed: ByteArray, p256Public: ByteArray, p256: P256KeyAgreement): TagIdentity {
            val kp = MLKEM768.keyPairFromSeed(mlkemSeed)
            return TagIdentity(TagRecipient(kp.encapsulationKey + P256Curve.toUncompressed(p256Public)), p256, kp)
        }

        /** Fully software classic identity (tests, and platforms without a hardware key). */
        fun softwareClassic(d: BigInteger): TagIdentity {
            val sw = P256SoftwareKey(d)
            return classic(sw.publicUncompressed, sw)
        }

        /** Fully software hybrid identity from a 32-byte seed, matching filippo.io/hpke key expansion. */
        fun softwareHybrid(seed: ByteArray): TagIdentity {
            val (mlkemSeed, d) = HpkeP256.hybridExpandSeed(seed)
            val sw = P256SoftwareKey(d)
            return hybrid(mlkemSeed, sw.publicUncompressed, sw)
        }
    }
}
