package com.agepony.core.crypto

import com.agepony.core.bech32.Bech32
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.HybridRecipient
import com.agepony.core.recipients.TagIdentity
import com.agepony.core.recipients.TagRecipient
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/** FIPS 203 section 7.2 modulus check on ML-KEM-768 encapsulation keys (audit L-12). */
class MLKEM768ValidationTest {
    private val rng = SecureRandom()

    /** Set coefficient 0 of [ek] to [value] (12 bits, little-endian packing). */
    private fun withCoefficient0(ek: ByteArray, value: Int): ByteArray = ek.copyOf().also {
        it[0] = (value and 0xff).toByte()
        it[1] = ((it[1].toInt() and 0xf0) or ((value ushr 8) and 0x0f)).toByte()
    }

    /** Set coefficient 767 (the last one, the high half of bytes 1149..1151). */
    private fun withLastCoefficient(ek: ByteArray, value: Int): ByteArray = ek.copyOf().also {
        it[1150] = ((it[1150].toInt() and 0x0f) or ((value and 0x0f) shl 4)).toByte()
        it[1151] = ((value ushr 4) and 0xff).toByte()
    }

    @Test
    fun validKeysPassAndUnreducedCoefficientsFail() {
        val ek = HybridIdentity.generate().publicKey.copyOfRange(0, MLKEM768.ENCAPS_KEY_SIZE)
        assertTrue(MLKEM768.isValidEncapsulationKey(ek))
        assertTrue(MLKEM768.isValidEncapsulationKey(withCoefficient0(ek, 3328)))
        assertFalse(MLKEM768.isValidEncapsulationKey(withCoefficient0(ek, 3329)))
        assertFalse(MLKEM768.isValidEncapsulationKey(withCoefficient0(ek, 4095)))
        assertFalse(MLKEM768.isValidEncapsulationKey(withLastCoefficient(ek, 3329)))
        assertFalse(MLKEM768.isValidEncapsulationKey(ek.copyOf(1183)))
        assertThrows(IllegalArgumentException::class.java) { MLKEM768.publicFromBytes(withCoefficient0(ek, 3329)) }
        // rho (the last 32 bytes) is not range-checked; any value is fine.
        assertTrue(MLKEM768.isValidEncapsulationKey(ek.copyOf().also { it.fill(0xff.toByte(), 1152, 1184) }))
    }

    @Test
    fun age1pq1ParsingRejectsAMalformedKeyButStoredBytesStillLoad() {
        val pk = HybridIdentity.generate().publicKey
        val bad = withCoefficient0(pk.copyOfRange(0, MLKEM768.ENCAPS_KEY_SIZE), 4000) + pk.copyOfRange(MLKEM768.ENCAPS_KEY_SIZE, pk.size)
        assertThrows(IllegalArgumentException::class.java) { HybridRecipient(Bech32.encode("age1pq", bad)) }
        // Already-saved bytes keep loading (the vault must not break), but encrypting refuses.
        val stored = HybridRecipient(bad)
        assertThrows(IllegalArgumentException::class.java) { stored.wrap(ByteArray(16)) }
        HybridRecipient(Bech32.encode("age1pq", pk)).wrap(ByteArray(16))
    }

    @Test
    fun hybridRecipientWithLowOrderX25519HalfIsRefusedAtEncrypt() {
        val pk = HybridIdentity.generate().publicKey.copyOf()
        pk.fill(0, MLKEM768.ENCAPS_KEY_SIZE, pk.size)
        val e = assertThrows(IllegalArgumentException::class.java) { HybridRecipient(pk).wrap(ByteArray(16)) }
        assertTrue(e.message!!.contains("low-order"), e.message)
    }

    @Test
    fun age1tagpq1ParsingRejectsAMalformedKey() {
        val seed = ByteArray(32).also { rng.nextBytes(it) }
        val good = TagIdentity.softwareHybrid(seed).recipient.publicKey
        val bad = withCoefficient0(good.copyOfRange(0, MLKEM768.ENCAPS_KEY_SIZE), 3329) + good.copyOfRange(MLKEM768.ENCAPS_KEY_SIZE, good.size)
        assertThrows(IllegalArgumentException::class.java) { TagRecipient(Bech32.encode("age1tagpq", bad)) }
        TagRecipient(Bech32.encode("age1tagpq", good))
        // Raw bytes (as a vault stores them) still construct; encrypting refuses.
        assertThrows(IllegalArgumentException::class.java) { TagRecipient(bad).wrap(ByteArray(16)) }
    }
}
