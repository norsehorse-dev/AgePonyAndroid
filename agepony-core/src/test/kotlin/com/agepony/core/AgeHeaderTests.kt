package com.agepony.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class AgeHeaderTests {
    private fun randomFileKey() = ByteArray(16).also { SecureRandom().nextBytes(it) }

    @Test
    fun roundTrip_singleStanza() {
        val fileKey = randomFileKey()
        val stanza = Stanza("X25519", listOf("ZGVm"), ByteArray(32) { it.toByte() })
        val header = AgeHeader.serialize(listOf(stanza), fileKey)

        // Append some bytes so parse() can locate the payload boundary
        val withPayload = header + ByteArray(48) { (0x80 + it).toByte() }
        val parsed = AgeHeader.parse(withPayload)

        assertEquals(1, parsed.stanzas.size)
        assertEquals("X25519", parsed.stanzas[0].type)
        assertEquals(listOf("ZGVm"), parsed.stanzas[0].args)
        assertArrayEquals(stanza.body, parsed.stanzas[0].body)
        AgeHeader.verifyMAC(parsed.macInputBytes, parsed.mac, fileKey)
    }

    @Test
    fun roundTrip_multipleStanzas() {
        val fileKey = randomFileKey()
        val stanzas = listOf(
            Stanza("X25519", listOf("aGVsbG8"), ByteArray(32) { it.toByte() }),
            Stanza("X25519", listOf("d29ybGQ"), ByteArray(32) { (it + 1).toByte() }),
            Stanza("custom", listOf("a", "b", "c"), ByteArray(20) { it.toByte() }),
        )
        val header = AgeHeader.serialize(stanzas, fileKey)
        val withPayload = header + ByteArray(16)
        val parsed = AgeHeader.parse(withPayload)

        assertEquals(3, parsed.stanzas.size)
        for (i in stanzas.indices) {
            assertEquals(stanzas[i].type, parsed.stanzas[i].type)
            assertEquals(stanzas[i].args, parsed.stanzas[i].args)
            assertArrayEquals(stanzas[i].body, parsed.stanzas[i].body)
        }
        AgeHeader.verifyMAC(parsed.macInputBytes, parsed.mac, fileKey)
    }

    @Test
    fun verifyMAC_failsOnTamperedHeader() {
        val fileKey = randomFileKey()
        val stanza = Stanza("X25519", listOf("ZGVm"), ByteArray(32))
        val header = AgeHeader.serialize(listOf(stanza), fileKey)
        val parsed = AgeHeader.parse(header + ByteArray(48))
        // Tamper macInputBytes AFTER parsing — flip a byte in the version line area.
        // This guarantees the bytes differ from what was MAC'd without breaking parse.
        val tampered = parsed.macInputBytes.copyOf()
        tampered[10] = (tampered[10].toInt() xor 0x01).toByte()
        assertThrows(AgeHeader.HeaderException::class.java) {
            AgeHeader.verifyMAC(tampered, parsed.mac, fileKey)
        }
    }

    @Test
    fun verifyMAC_failsWithWrongFileKey() {
        val fileKey = randomFileKey()
        val wrongKey = randomFileKey()
        val stanza = Stanza("X25519", listOf("ZGVm"), ByteArray(32))
        val header = AgeHeader.serialize(listOf(stanza), fileKey)
        val parsed = AgeHeader.parse(header + ByteArray(48))
        assertThrows(AgeHeader.HeaderException::class.java) {
            AgeHeader.verifyMAC(parsed.macInputBytes, parsed.mac, wrongKey)
        }
    }

    @Test
    fun parse_rejectsMissingVersionLine() {
        // Header that's just "--- <mac>\n" with no version line
        val fake = "--- AAAA\nxxxxxxxxxxxxxxxx".toByteArray()
        assertThrows(AgeHeader.HeaderException::class.java) {
            AgeHeader.parse(fake)
        }
    }

    @Test
    fun parse_rejectsMissingMACLine() {
        val fake = "age-encryption.org/v1\n-> X25519 abc\nAQID\n".toByteArray()
        assertThrows(AgeHeader.HeaderException::class.java) {
            AgeHeader.parse(fake)
        }
    }
}
