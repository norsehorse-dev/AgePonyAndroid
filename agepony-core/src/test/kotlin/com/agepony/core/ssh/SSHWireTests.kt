package com.agepony.core.ssh

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

class SSHWireTests {
    @Test
    fun roundTrip_emptyString() {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, ByteArray(0))
        val bytes = out.toByteArray()
        assertEquals(4, bytes.size)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), bytes)
        val buf = SSHWire.wrapForRead(bytes)
        assertArrayEquals(ByteArray(0), SSHWire.readString(buf))
    }

    @Test
    fun roundTrip_shortString() {
        val data = "ssh-ed25519".toByteArray()
        val encoded = SSHWire.encodeString(data)
        assertEquals(4 + data.size, encoded.size)
        assertEquals(0x0b, encoded[3].toInt())   // length = 11 in BE
        val buf = SSHWire.wrapForRead(encoded)
        assertArrayEquals(data, SSHWire.readString(buf))
    }

    @Test
    fun roundTrip_longString_300bytes() {
        val data = ByteArray(300) { it.toByte() }
        val encoded = SSHWire.encodeString(data)
        // 300 = 0x12c → length bytes are 00 00 01 2c
        assertEquals(0x01, encoded[2].toInt())
        assertEquals(0x2c, encoded[3].toInt())
        val buf = SSHWire.wrapForRead(encoded)
        assertArrayEquals(data, SSHWire.readString(buf))
    }

    @Test
    fun multipleStrings_inSequence() {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, "alpha".toByteArray())
        SSHWire.writeString(out, "beta".toByteArray())
        SSHWire.writeString(out, "gamma".toByteArray())
        val buf = SSHWire.wrapForRead(out.toByteArray())
        assertEquals("alpha", String(SSHWire.readString(buf)))
        assertEquals("beta", String(SSHWire.readString(buf)))
        assertEquals("gamma", String(SSHWire.readString(buf)))
    }

    @Test
    fun readString_rejectsTruncatedLength() {
        assertThrows(SSHWire.SSHWireException::class.java) {
            SSHWire.readString(ByteBuffer.wrap(byteArrayOf(0, 0)))
        }
    }

    @Test
    fun readString_rejectsLengthExceedingBuffer() {
        // Length prefix = 100, but only 5 bytes follow
        val bytes = byteArrayOf(0, 0, 0, 100, 1, 2, 3, 4, 5)
        assertThrows(SSHWire.SSHWireException::class.java) {
            SSHWire.readString(SSHWire.wrapForRead(bytes))
        }
    }

    @Test
    fun readUInt32_rejectsNegative() {
        // Highest bit set → reads as negative Int
        val bytes = byteArrayOf(0xff.toByte(), 0, 0, 0)
        assertThrows(SSHWire.SSHWireException::class.java) {
            SSHWire.readUInt32(SSHWire.wrapForRead(bytes))
        }
    }
}
