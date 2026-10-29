package com.agepony.core.crypto

import com.agepony.core.Stanza
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.HybridRecipient
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

/**
 * The hybrid KEM refuses an all-zero X25519 shared secret (identity or low-order point) on both
 * encapsulation and decapsulation, as iOS `HybridKEMError.lowOrderPoint` does. CCTV vectors
 * `hybrid_identity` and `hybrid_low_order` cover the decrypt side end to end.
 */
class HpkeMlkem768X25519Tests {
    private val hex = HexFormat.of()

    private val seed = hex.parseHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )

    /** X25519 u-coordinates whose shared secret is all zeros for every scalar (libsodium's list). */
    private val lowOrderPoints = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000", // 0
        "0100000000000000000000000000000000000000000000000000000000000000", // 1
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 8
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // order 8
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p + 1
    ).map { hex.parseHex(it) }

    /** A real enc for [seed] with its X25519 half replaced by [share]. */
    private fun encWithShare(share: ByteArray): ByteArray {
        val (_, enc) = HpkeMlkem768X25519.encap(HybridIdentity(seed).publicKey)
        return enc.copyOfRange(0, MLKEM768.CIPHERTEXT_SIZE) + share
    }

    @Test
    fun decapRejectsLowOrderShare() {
        val priv = HpkeMlkem768X25519.PrivateKey(seed)
        for (point in lowOrderPoints) {
            val enc = encWithShare(point)
            val e = assertThrows(HpkeMlkem768X25519.LowOrderPointException::class.java) {
                HpkeMlkem768X25519.decap(priv, enc)
            }
            assertTrue(e.message!!.contains("low-order"), e.message)
        }
    }

    @Test
    fun encapRejectsLowOrderRecipientKey() {
        val pk = HybridIdentity(seed).publicKey
        for (point in lowOrderPoints) {
            val bad = pk.copyOfRange(0, MLKEM768.ENCAPS_KEY_SIZE) + point
            assertThrows(HpkeMlkem768X25519.LowOrderPointException::class.java) {
                HpkeMlkem768X25519.encap(bad)
            }
            // Still an IllegalArgumentException for callers that catch a bad recipient that way.
            assertThrows(IllegalArgumentException::class.java) {
                HybridRecipient(bad).wrap(ByteArray(16))
            }
        }
    }

    @Test
    fun identityTreatsLowOrderShareAsNotForUs() {
        val id = HybridIdentity(seed)
        for (point in lowOrderPoints) {
            val enc = encWithShare(point)
            val stanza = Stanza("mlkem768x25519", listOf(Stanza.base64NoPad(enc)), ByteArray(32))
            assertNull(id.unwrap(stanza))
        }
    }

    @Test
    fun encapDecapStillRoundTrip() {
        val priv = HpkeMlkem768X25519.PrivateKey(seed)
        val (ss, enc) = HpkeMlkem768X25519.encap(priv.publicKey)
        assertArrayEquals(ss, HpkeMlkem768X25519.decap(priv, enc))
    }

    @Test
    fun isAllZeroChecksEveryByte() {
        assertTrue(HpkeMlkem768X25519.isAllZero(ByteArray(32)))
        assertTrue(HpkeMlkem768X25519.isAllZero(ByteArray(0)))
        for (i in 0 until 32) {
            assertFalse(HpkeMlkem768X25519.isAllZero(ByteArray(32).also { it[i] = 0x80.toByte() }))
            assertFalse(HpkeMlkem768X25519.isAllZero(ByteArray(32).also { it[i] = 1 }))
        }
    }
}
