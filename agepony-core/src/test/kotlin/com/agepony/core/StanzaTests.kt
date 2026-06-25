package com.agepony.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class StanzaTests {
    @Test
    fun serialize_simpleStanza() {
        val s = Stanza("X25519", listOf("abc"), ByteArray(10) { it.toByte() })
        val out = s.serialize()
        assertTrue(out.startsWith("-> X25519 abc\n"))
        assertTrue(out.endsWith("\n"))
    }

    @Test
    fun serialize_emptyBody_noBodyLines() {
        val s = Stanza("test", listOf("a"), ByteArray(0))
        assertEquals("-> test a\n", s.serialize())
    }

    @Test
    fun roundTrip_smallBody() {
        val original = Stanza("X25519", listOf("ZGVm"), ByteArray(20) { it.toByte() })
        val text = original.serialize()
        val lines = text.split('\n').dropLastWhile { it.isEmpty() }   // drop trailing ""
        val (parsed, _) = Stanza.parseOne(lines, 0)
        assertEquals(original.type, parsed.type)
        assertEquals(original.args, parsed.args)
        assertArrayEquals(original.body, parsed.body)
    }

    /**
     * Critical edge case: body length is exactly 48 bytes (= 64 base64 chars).
     * Serialization must emit an extra empty line as terminator; parsing must accept it.
     */
    @Test
    fun roundTrip_body48Bytes_emptyTerminator() {
        val body = ByteArray(48) { it.toByte() }
        val original = Stanza("type", listOf("arg"), body)
        val text = original.serialize()
        // Expect: "-> type arg\n<64-char-base64>\n\n"
        val parts = text.split('\n')
        assertEquals("-> type arg", parts[0])
        assertEquals(64, parts[1].length)
        assertEquals("", parts[2])         // empty terminator
        assertEquals("", parts[3])         // final \n from terminator
        // Round-trip parse
        val (parsed, _) = Stanza.parseOne(text.split('\n').dropLastWhile { it.isEmpty() }, 0)
        assertArrayEquals(body, parsed.body)
    }

    @Test
    fun roundTrip_body96Bytes_alignsTo128b64chars() {
        val body = ByteArray(96) { it.toByte() }   // 128 base64 chars = 2 lines of 64
        val original = Stanza("type", emptyList(), body)
        val text = original.serialize()
        val parts = text.split('\n')
        assertEquals("-> type", parts[0])
        assertEquals(64, parts[1].length)
        assertEquals(64, parts[2].length)
        assertEquals("", parts[3])         // empty terminator (256-char total mod 64 = 0)
        val (parsed, _) = Stanza.parseOne(text.split('\n').dropLastWhile { it.isEmpty() }, 0)
        assertArrayEquals(body, parsed.body)
    }

    @Test
    fun roundTrip_body51Bytes_lastLineShort() {
        val body = ByteArray(51) { it.toByte() }   // 68 base64 chars = 64 + 4
        val original = Stanza("X25519", listOf("ZGVm"), body)
        val text = original.serialize()
        val parts = text.split('\n').dropLastWhile { it.isEmpty() }
        assertEquals(3, parts.size)         // header + 64-char line + 4-char line
        assertEquals(64, parts[1].length)
        assertEquals(4, parts[2].length)
        val (parsed, _) = Stanza.parseOne(parts, 0)
        assertArrayEquals(body, parsed.body)
    }

    @Test
    fun parse_rejectsMissingArrow() {
        assertThrows(Stanza.Companion.StanzaException::class.java) {
            Stanza.parseOne(listOf("not a stanza"), 0)
        }
    }

    @Test
    fun parse_terminatesAtNextStanza() {
        val lines = listOf(
            "-> first a",
            "AQID",            // body of first stanza
            "-> second b",
            "BAUG",            // body of second stanza
            "---"
        )
        val (first, nextIdx) = Stanza.parseOne(lines, 0)
        assertEquals("first", first.type)
        assertEquals(listOf("a"), first.args)
        assertEquals(2, nextIdx)
        val (second, finalIdx) = Stanza.parseOne(lines, nextIdx)
        assertEquals("second", second.type)
        assertEquals(4, finalIdx)
    }

    @Test
    fun parse_terminatesAtMACMarker() {
        val lines = listOf(
            "-> X25519 abc",
            "AQIDBA",
            "--- 0123456789"   // would be header MAC line in a real file
        )
        val (s, nextIdx) = Stanza.parseOne(lines, 0)
        assertEquals("X25519", s.type)
        assertEquals(2, nextIdx)
    }
}
