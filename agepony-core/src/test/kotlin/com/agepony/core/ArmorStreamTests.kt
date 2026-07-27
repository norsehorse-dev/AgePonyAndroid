package com.agepony.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.Random

/**
 * Streaming armor must be a drop-in for the whole-buffer pair: same output bytes, same accepted
 * input, and bounded memory regardless of input size (the 3.1.0 large-file fix depends on it).
 */
class ArmorStreamTests {

    private fun data(n: Int, seed: Long = 42): ByteArray =
        ByteArray(n).also { Random(seed).nextBytes(it) }

    private fun encodeStream(binary: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        Armor.encodeStream(ByteArrayInputStream(binary), out)
        return out.toByteArray()
    }

    private fun decodeStream(armored: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        Armor.decodeStream(ByteArrayInputStream(armored), out)
        return out.toByteArray()
    }

    /** Sizes around the 48-byte group boundary, the 64-char line, and the read buffer. */
    private val sizes = listOf(0, 1, 2, 3, 47, 48, 49, 63, 64, 96, 1000, 49151, 49152, 49159, 300_000)

    @Test
    fun encodeStream_isByteIdenticalToEncode() {
        for (n in sizes) {
            val d = data(n, n.toLong())
            assertArrayEquals(
                Armor.encode(d).toByteArray(Charsets.US_ASCII),
                encodeStream(d),
                "streamed armor differs from Armor.encode at n=$n",
            )
        }
    }

    @Test
    fun decodeStream_readsWhatEncodeWrote() {
        for (n in sizes) {
            val d = data(n, n.toLong())
            assertArrayEquals(d, decodeStream(Armor.encode(d).toByteArray()), "round trip failed at n=$n")
            assertArrayEquals(d, decodeStream(encodeStream(d)), "stream round trip failed at n=$n")
        }
    }

    @Test
    fun decodeStream_acceptsCrlfBlankLinesAndTrailingSpaces() {
        val d = data(500)
        val armored = Armor.encode(d)
        assertArrayEquals(d, decodeStream(armored.replace("\n", "\r\n").toByteArray()))
        assertArrayEquals(d, decodeStream(("\n\n$armored\n\n").toByteArray()))
        assertArrayEquals(d, decodeStream(armored.replace("\n", "  \n").toByteArray()))
    }

    @Test
    fun decodeStream_handlesEmptyBody() {
        assertArrayEquals(ByteArray(0), decodeStream(Armor.encode(ByteArray(0)).toByteArray()))
    }

    @Test
    fun decodeStream_rejectsMalformedArmor() {
        assertThrows(Armor.ArmorException::class.java) {
            decodeStream("nope\nAAAA\n${Armor.END_MARKER}\n".toByteArray())
        }
        assertThrows(Armor.ArmorException::class.java) {
            decodeStream("${Armor.BEGIN_MARKER}\nAAAA\n".toByteArray())
        }
        assertThrows(Armor.ArmorException::class.java) {
            decodeStream((Armor.encode(data(10)) + "trailing junk\n").toByteArray())
        }
        assertThrows(Armor.ArmorException::class.java) {
            decodeStream("${Armor.BEGIN_MARKER}\n!!!!\n${Armor.END_MARKER}\n".toByteArray())
        }
    }

    @Test
    fun looksArmored_recognizesHeadOfStream() {
        val armored = Armor.encode(data(100)).toByteArray()
        assertTrue(Armor.looksArmored(armored.copyOfRange(0, Armor.SNIFF_LEN)))
        assertTrue(Armor.looksArmored("-----BEGIN AGE".toByteArray()))
        assertFalse(Armor.looksArmored(data(Armor.SNIFF_LEN)))
        assertFalse(Armor.looksArmored(ByteArray(0)))
    }

    /**
     * The point of the streaming pair: a 40 MB input must encode without ever holding the input
     * or the output. Counting sink, so the test measures the produced length rather than keeping it.
     */
    @Test
    fun encodeStream_isBoundedMemory() {
        val size = 40L * 1024 * 1024
        var produced = 0L
        val sink = object : OutputStream() {
            override fun write(b: Int) { produced++ }
            override fun write(b: ByteArray, off: Int, len: Int) { produced += len }
        }
        Armor.encodeStream(zeros(size), sink)

        val fullGroups = size / 48
        val rem = size % 48
        val tail = if (rem == 0L) 0L else 4L * ((rem + 2) / 3) + 1
        val expected = (Armor.BEGIN_MARKER.length + 1L) + fullGroups * 65L + tail + (Armor.END_MARKER.length + 1L)
        assertEquals(expected, produced)
    }

    /** An input stream of `n` zero bytes that never allocates them. */
    private fun zeros(n: Long): InputStream = object : InputStream() {
        private var left = n
        override fun read(): Int = if (left-- > 0) 0 else -1
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (left <= 0) return -1
            val take = minOf(len.toLong(), left).toInt()
            java.util.Arrays.fill(b, off, off + take, 0)
            left -= take
            return take
        }
    }
}
