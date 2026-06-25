package com.agepony.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class ArmorTests {
    @Test
    fun roundTrip_emptyBinary() {
        val armored = Armor.encode(ByteArray(0))
        assertTrue(armored.startsWith(Armor.BEGIN_MARKER))
        assertTrue(armored.trimEnd().endsWith(Armor.END_MARKER))
        val decoded = Armor.decode(armored)
        assertArrayEquals(ByteArray(0), decoded)
    }

    @Test
    fun roundTrip_smallBinary() {
        val data = "hello agepony".toByteArray()
        val armored = Armor.encode(data)
        assertArrayEquals(data, Armor.decode(armored))
    }

    @Test
    fun roundTrip_largeBinary() {
        val data = ByteArray(10000).also { SecureRandom().nextBytes(it) }
        val armored = Armor.encode(data)
        // All body lines except possibly the last should be exactly 64 chars
        val lines = armored.split('\n')
        for (i in 1 until lines.size - 2) {   // -2 to skip END marker + trailing ""
            assertTrue(lines[i].length <= 64, "line $i too long: ${lines[i].length}")
        }
        assertArrayEquals(data, Armor.decode(armored))
    }

    @Test
    fun decode_acceptsCRLF() {
        val data = "test".toByteArray()
        val armored = Armor.encode(data).replace("\n", "\r\n")
        assertArrayEquals(data, Armor.decode(armored))
    }

    @Test
    fun decode_rejectsMissingBeginMarker() {
        val bad = "not an armor\nblob\n-----END AGE ENCRYPTED FILE-----\n"
        assertThrows(Armor.ArmorException::class.java) { Armor.decode(bad) }
    }

    @Test
    fun decode_rejectsMissingEndMarker() {
        val bad = "-----BEGIN AGE ENCRYPTED FILE-----\nAQID\n"
        assertThrows(Armor.ArmorException::class.java) { Armor.decode(bad) }
    }

    @Test
    fun decode_rejectsInvalidBase64() {
        val bad = "-----BEGIN AGE ENCRYPTED FILE-----\n!@#$%^\n-----END AGE ENCRYPTED FILE-----\n"
        assertThrows(Armor.ArmorException::class.java) { Armor.decode(bad) }
    }
}
