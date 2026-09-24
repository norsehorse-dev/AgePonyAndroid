package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.bech32.Bech32
import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.HKDF
import com.agepony.core.crypto.P256Curve
import com.agepony.core.crypto.P256KeyAgreement
import java.security.MessageDigest

/**
 * A key held in a YubiKey PIV slot, as age-plugin-yubikey sets it up.
 *
 * The identity file line (`AGE-PLUGIN-YUBIKEY-1...`) is only a pointer: Bech32 of
 * serial (u32 little-endian) || retired slot id (0x82..0x95) || 4-byte tag, where the tag is
 * SHA-256 of the compressed public key, truncated. The private key never leaves the YubiKey.
 */
class YubiKeyStub(val serial: Long, val slot: Int, val tag: ByteArray) {
    init {
        require(slot in 0x82..0x95) { "not a PIV retired slot: 0x%02x".format(slot) }
        require(tag.size == 4) { "tag must be 4 bytes" }
    }

    fun toBytes(): ByteArray = byteArrayOf(
        serial.toByte(), (serial ushr 8).toByte(), (serial ushr 16).toByte(), (serial ushr 24).toByte(),
        slot.toByte(),
    ) + tag

    fun encode(): String = Bech32.encode(HRP, toBytes()).uppercase()

    /** Does [compressedPublicKey] belong to this stub? */
    fun matchesKey(compressedPublicKey: ByteArray): Boolean = MessageDigest.isEqual(tag, staticTag(compressedPublicKey))

    override fun equals(other: Any?): Boolean = other is YubiKeyStub && other.toBytes().contentEquals(toBytes())
    override fun hashCode(): Int = toBytes().contentHashCode()

    companion object {
        const val HRP = "age-plugin-yubikey-"

        fun isStub(s: String): Boolean = s.trim().uppercase().startsWith("AGE-PLUGIN-YUBIKEY-1")

        fun parse(s: String): YubiKeyStub {
            val (hrp, bytes) = Bech32.decode(s.trim())
            require(hrp == HRP) { "expected an AGE-PLUGIN-YUBIKEY-1… identity" }
            return fromBytes(bytes)
        }

        fun fromBytes(bytes: ByteArray): YubiKeyStub {
            require(bytes.size >= 9) { "YubiKey identity is too short" }
            val serial = (bytes[0].toLong() and 0xff) or ((bytes[1].toLong() and 0xff) shl 8) or
                ((bytes[2].toLong() and 0xff) shl 16) or ((bytes[3].toLong() and 0xff) shl 24)
            return YubiKeyStub(serial, bytes[4].toInt() and 0xff, bytes.copyOfRange(5, 9))
        }

        /** The 4-byte static tag age-plugin-yubikey uses for a key. */
        fun staticTag(compressedPublicKey: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(compressedPublicKey).copyOf(4)
    }
}

/**
 * The decrypting side of a `piv-p256` (`age1yubikey1…`) recipient. ECDH goes through [ka],
 * which for a real YubiKey is a PIV GENERAL AUTHENTICATE over NFC.
 *
 * Stanza `piv-p256 <tag> <epk>`: tag = SHA-256(recipient)[:4], epk a compressed point.
 * wrapKey = HKDF-SHA256(ikm = ECDH x, salt = epk || recipient, info = "piv-p256").
 */
class PivP256Identity(compressedPublicKey: ByteArray, private val ka: P256KeyAgreement) : HardwareIdentity {
    val compressedPublicKey: ByteArray = P256Curve.toCompressed(compressedPublicKey)
    private val tag = YubiKeyStub.staticTag(this.compressedPublicKey)

    override fun matches(stanza: Stanza): Boolean = parse(stanza) != null

    override fun unwrap(stanza: Stanza): ByteArray? {
        val epk = parse(stanza) ?: return null
        val shared = ka.sharedX(P256Curve.toUncompressed(epk))
        val wrapKey = HKDF.derive(shared, epk + compressedPublicKey, "piv-p256".toByteArray(Charsets.US_ASCII), 32)
        return try {
            ChaChaPoly.decrypt(wrapKey, ByteArray(12), stanza.body)
        } catch (e: Exception) {
            null
        }
    }

    private fun parse(stanza: Stanza): ByteArray? {
        if (stanza.type != "piv-p256" || stanza.args.size != 2 || stanza.body.size != 32) return null
        val t = runCatching { Stanza.base64Decode(stanza.args[0]) }.getOrNull() ?: return null
        val epk = runCatching { Stanza.base64Decode(stanza.args[1]) }.getOrNull() ?: return null
        if (t.size != 4 || epk.size != 33 || !MessageDigest.isEqual(t, tag)) return null
        return if (runCatching { P256Curve.decode(epk) }.isSuccess) epk else null
    }
}

/**
 * A YubiKey age identity: one PIV key that answers both the older `piv-p256` stanzas and the
 * age 1.3 `p256tag` ones (newer age-plugin-yubikey versions write the latter), with a single
 * key agreement so either costs one tap.
 */
class YubiKeyIdentity(val stub: YubiKeyStub, compressedPublicKey: ByteArray, ka: P256KeyAgreement) : HardwareIdentity {
    private val piv = PivP256Identity(compressedPublicKey, ka)
    private val tag = TagIdentity.classic(compressedPublicKey, ka)

    init {
        require(stub.matchesKey(piv.compressedPublicKey)) { "that public key doesn't belong to this YubiKey identity" }
    }

    override fun matches(stanza: Stanza): Boolean = piv.matches(stanza) || tag.matches(stanza)

    override fun unwrap(stanza: Stanza): ByteArray? = when (stanza.type) {
        "piv-p256" -> piv.unwrap(stanza)
        P256TAG_STANZA_TYPE -> tag.unwrap(stanza)
        else -> null
    }
}
