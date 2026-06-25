package com.agepony.core.bech32

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class Bech32Tests {
    @Test
    fun roundTrip_emptyData() {
        val encoded = Bech32.encode("a", ByteArray(0))
        val (hrp, data) = Bech32.decode(encoded)
        assertEquals("a", hrp)
        assertEquals(0, data.size)
    }

    @Test
    fun roundTrip_age32Bytes() {
        val pub = ByteArray(32) { it.toByte() }
        val encoded = Bech32.encode("age", pub)
        assert(encoded.startsWith("age1"))
        val (hrp, data) = Bech32.decode(encoded)
        assertEquals("age", hrp)
        assertArrayEquals(pub, data)
    }

    @Test
    fun roundTrip_ageSecretKey() {
        val sec = ByteArray(32) { (0xff - it).toByte() }
        val encoded = Bech32.encode("AGE-SECRET-KEY-", sec).uppercase()
        assert(encoded.startsWith("AGE-SECRET-KEY-1"))
        val (hrp, data) = Bech32.decode(encoded)
        assertEquals("age-secret-key-", hrp)   // decode lowercases
        assertArrayEquals(sec, data)
    }

    @Test
    fun rejectsMixedCase() {
        val encoded = Bech32.encode("age", ByteArray(32))
        // Force one char to uppercase, rest lowercase: mixed
        val mixed = encoded.substring(0, encoded.length - 1) +
                    encoded.last().uppercaseChar()
        assertThrows(Bech32.Bech32Exception::class.java) { Bech32.decode(mixed) }
    }

    @Test
    fun rejectsBadChecksum() {
        val encoded = Bech32.encode("age", ByteArray(32))
        // Flip last character to a different one in the charset
        val flipped = encoded.substring(0, encoded.length - 1) +
                      if (encoded.last() == 'q') 'p' else 'q'
        assertThrows(Bech32.Bech32Exception::class.java) { Bech32.decode(flipped) }
    }

    @Test
    fun rejectsMissingSeparator() {
        assertThrows(Bech32.Bech32Exception::class.java) {
            Bech32.decode("ageqqqqqqqqqqqqqqq")
        }
    }

    @Test
    fun rejectsInvalidCharacter() {
        // 'b', 'i', 'o' are excluded from Bech32 charset
        assertThrows(Bech32.Bech32Exception::class.java) {
            Bech32.decode("age1bbbbbbbbbb")
        }
    }

    /** BIP-0173 valid test vector. */
    @Test
    fun bip173_validVector_a12uel5l() {
        val (hrp, data) = Bech32.decode("A12UEL5L")
        assertEquals("a", hrp)
        assertEquals(0, data.size)
    }
}
