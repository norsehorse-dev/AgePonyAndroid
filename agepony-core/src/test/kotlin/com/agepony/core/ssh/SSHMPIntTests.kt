package com.agepony.core.ssh

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom

class SSHMPIntTests {
    @Test
    fun roundTrip_zero() {
        val encoded = SSHMPInt.encode(BigInteger.ZERO)
        // Length prefix = 0, no bytes
        assertEquals(4, encoded.size)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), encoded)
        val buf = SSHWire.wrapForRead(encoded)
        assertEquals(BigInteger.ZERO, SSHMPInt.read(buf))
    }

    @Test
    fun roundTrip_smallPositive_noLeadingZero() {
        // e = 65537 = 0x010001 (3 bytes, MSB=0x01 has high bit clear → no leading zero)
        val e = BigInteger.valueOf(65537)
        val encoded = SSHMPInt.encode(e)
        // Length prefix = 3, then 3 bytes
        assertEquals(7, encoded.size)
        assertEquals(0x03, encoded[3].toInt())
        assertEquals(0x01, encoded[4].toInt())
        assertEquals(0x00, encoded[5].toInt())
        assertEquals(0x01, encoded[6].toInt())
        val buf = SSHWire.wrapForRead(encoded)
        assertEquals(e, SSHMPInt.read(buf))
    }

    @Test
    fun roundTrip_largePositive_highBitSet_leadingZeroAdded() {
        // Value with high bit set: 0xff (= 255). BC must prepend 0x00 byte.
        val v = BigInteger.valueOf(255)
        val encoded = SSHMPInt.encode(v)
        // Length prefix = 2, then [0x00, 0xff]
        assertEquals(6, encoded.size)
        assertEquals(0x02, encoded[3].toInt())
        assertEquals(0x00, encoded[4].toInt())
        assertEquals(0xff.toByte(), encoded[5])
        val buf = SSHWire.wrapForRead(encoded)
        assertEquals(v, SSHMPInt.read(buf))
    }

    @Test
    fun roundTrip_random2048BitValue() {
        // RSA-2048 modulus-sized random number: high bit usually set
        val random = SecureRandom()
        val bytes = ByteArray(256).also { random.nextBytes(it) }
        // Force high bit set to test the leading-zero rule
        bytes[0] = (bytes[0].toInt() or 0x80).toByte()
        val v = BigInteger(1, bytes)   // positive, BE
        val encoded = SSHMPInt.encode(v)
        // Length should be 257 (256 + leading zero)
        val len = ((encoded[0].toInt() and 0xff) shl 24) or
                  ((encoded[1].toInt() and 0xff) shl 16) or
                  ((encoded[2].toInt() and 0xff) shl 8) or
                  (encoded[3].toInt() and 0xff)
        assertEquals(257, len)
        val buf = SSHWire.wrapForRead(encoded)
        assertEquals(v, SSHMPInt.read(buf))
    }

    @Test
    fun multipleMPInts_inSequence() {
        val out = ByteArrayOutputStream()
        SSHMPInt.write(out, BigInteger.valueOf(65537))
        SSHMPInt.write(out, BigInteger.valueOf(123456789))
        SSHMPInt.write(out, BigInteger.ZERO)
        val buf = SSHWire.wrapForRead(out.toByteArray())
        assertEquals(BigInteger.valueOf(65537), SSHMPInt.read(buf))
        assertEquals(BigInteger.valueOf(123456789), SSHMPInt.read(buf))
        assertEquals(BigInteger.ZERO, SSHMPInt.read(buf))
    }

    @Test
    fun write_rejectsNegative() {
        assertThrows(SSHMPInt.SSHMPIntException::class.java) {
            SSHMPInt.write(ByteArrayOutputStream(), BigInteger.valueOf(-1))
        }
    }

    @Test
    fun read_failsOnTruncatedInput() {
        // Length prefix says 10 bytes but only 5 follow
        val bytes = byteArrayOf(0, 0, 0, 10, 1, 2, 3, 4, 5)
        assertThrows(SSHMPInt.SSHMPIntException::class.java) {
            SSHMPInt.read(SSHWire.wrapForRead(bytes))
        }
    }
}
