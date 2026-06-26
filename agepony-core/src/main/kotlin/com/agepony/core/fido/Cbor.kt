package com.agepony.core.fido

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * CTAP2-canonical CBOR, limited to the subset CTAP2 uses: unsigned/negative integers,
 * byte and text strings, arrays, maps, booleans, and null. No floats, tags, or
 * indefinite-length items.
 *
 * Canonical form (CTAP2 / RFC 7049 §3.9): integers in shortest encoding, definite
 * lengths, and map keys sorted by their encoded bytes shortest-first then bytewise. This
 * ordering is what authenticators require on request maps and is verified byte-for-byte
 * against python-fido2 / cbor2 in the tests.
 *
 * Decoded types: integers as [Long], byte strings as [ByteArray], text as [String],
 * arrays as [List], maps as [LinkedHashMap] (keys [Long] or [String]).
 */
object Cbor {
    class CborException(message: String) : Exception(message)

    // --- Encode ---

    fun encode(value: Any?): ByteArray {
        val out = ByteArrayOutputStream()
        encodeValue(out, value)
        return out.toByteArray()
    }

    private fun encodeValue(out: ByteArrayOutputStream, v: Any?) {
        when (v) {
            null -> out.write(0xf6)
            is Boolean -> out.write(if (v) 0xf5 else 0xf4)
            is Int -> encodeInt(out, v.toLong())
            is Long -> encodeInt(out, v)
            is ByteArray -> { writeTypeLen(out, 2, v.size.toLong()); out.write(v) }
            is String -> {
                val b = v.toByteArray(Charsets.UTF_8)
                writeTypeLen(out, 3, b.size.toLong()); out.write(b)
            }
            is List<*> -> { writeTypeLen(out, 4, v.size.toLong()); v.forEach { encodeValue(out, it) } }
            is Map<*, *> -> encodeMap(out, v)
            else -> throw CborException("unsupported CBOR type: ${v::class}")
        }
    }

    private fun encodeInt(out: ByteArrayOutputStream, n: Long) {
        if (n >= 0) writeTypeLen(out, 0, n) else writeTypeLen(out, 1, -1 - n)
    }

    private fun writeTypeLen(out: ByteArrayOutputStream, major: Int, len: Long) {
        val mt = major shl 5
        when {
            len < 24L -> out.write(mt or len.toInt())
            len < 0x100L -> { out.write(mt or 24); out.write((len and 0xff).toInt()) }
            len < 0x10000L -> { out.write(mt or 25); writeBE(out, len, 2) }
            len < 0x100000000L -> { out.write(mt or 26); writeBE(out, len, 4) }
            else -> { out.write(mt or 27); writeBE(out, len, 8) }
        }
    }

    private fun writeBE(out: ByteArrayOutputStream, value: Long, bytes: Int) {
        for (i in bytes - 1 downTo 0) out.write(((value ushr (8 * i)) and 0xff).toInt())
    }

    private fun encodeMap(out: ByteArrayOutputStream, m: Map<*, *>) {
        writeTypeLen(out, 5, m.size.toLong())
        val encoded = m.entries.map { encode(it.key) to it.value }
        val sorted = encoded.sortedWith(Comparator { a, b -> canonicalKeyCompare(a.first, b.first) })
        for ((k, v) in sorted) {
            out.write(k)
            encodeValue(out, v)
        }
    }

    /** Shortest-first, then unsigned bytewise. */
    private fun canonicalKeyCompare(a: ByteArray, b: ByteArray): Int {
        if (a.size != b.size) return a.size - b.size
        for (i in a.indices) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return 0
    }

    // --- Decode ---

    fun decode(bytes: ByteArray): Any? {
        val buf = ByteBuffer.wrap(bytes)
        val v = decodeValue(buf)
        if (buf.hasRemaining()) throw CborException("trailing bytes after CBOR value: ${buf.remaining()}")
        return v
    }

    /** Decode one value from [buf], leaving any trailing bytes (CTAP responses may append). */
    fun decodeValue(buf: ByteBuffer): Any? {
        if (!buf.hasRemaining()) throw CborException("unexpected end of CBOR")
        val initial = buf.get().toInt() and 0xff
        val major = initial shr 5
        val info = initial and 0x1f
        return when (major) {
            0 -> readLength(buf, info)
            1 -> -1L - readLength(buf, info)
            2 -> readBytes(buf, readLength(buf, info))
            3 -> String(readBytes(buf, readLength(buf, info)), Charsets.UTF_8)
            4 -> {
                val n = readLength(buf, info)
                ArrayList<Any?>(n.toInt()).apply { repeat(n.toInt()) { add(decodeValue(buf)) } }
            }
            5 -> {
                val n = readLength(buf, info)
                LinkedHashMap<Any?, Any?>().apply {
                    repeat(n.toInt()) {
                        val k = decodeValue(buf)
                        put(k, decodeValue(buf))
                    }
                }
            }
            7 -> when (info) {
                20 -> false
                21 -> true
                22 -> null
                23 -> null
                else -> throw CborException("unsupported simple/float value: $info")
            }
            else -> throw CborException("unsupported CBOR major type: $major")
        }
    }

    private fun readLength(buf: ByteBuffer, info: Int): Long = when {
        info < 24 -> info.toLong()
        info == 24 -> readUInt(buf, 1)
        info == 25 -> readUInt(buf, 2)
        info == 26 -> readUInt(buf, 4)
        info == 27 -> readUInt(buf, 8)
        else -> throw CborException("invalid CBOR additional info: $info")
    }

    private fun readUInt(buf: ByteBuffer, bytes: Int): Long {
        if (buf.remaining() < bytes) throw CborException("short read for $bytes-byte length")
        var v = 0L
        repeat(bytes) { v = (v shl 8) or (buf.get().toLong() and 0xff) }
        if (v < 0) throw CborException("CBOR length exceeds supported range")
        return v
    }

    private fun readBytes(buf: ByteBuffer, n: Long): ByteArray {
        if (n < 0 || n > buf.remaining()) throw CborException("short read for $n-byte string")
        val b = ByteArray(n.toInt())
        buf.get(b)
        return b
    }

    // --- Typed access helpers for parsing CTAP responses ---

    @Suppress("UNCHECKED_CAST")
    fun asMap(v: Any?): Map<Long, Any?> {
        if (v !is Map<*, *>) throw CborException("expected CBOR map")
        val out = LinkedHashMap<Long, Any?>()
        for ((k, value) in v) {
            val key = when (k) {
                is Long -> k
                is Int -> k.toLong()
                else -> throw CborException("expected integer map key, got $k")
            }
            out[key] = value
        }
        return out
    }

    fun asBytes(v: Any?): ByteArray = v as? ByteArray ?: throw CborException("expected CBOR byte string")
    fun asText(v: Any?): String = v as? String ?: throw CborException("expected CBOR text string")
    fun asLong(v: Any?): Long = when (v) {
        is Long -> v
        is Int -> v.toLong()
        else -> throw CborException("expected CBOR integer")
    }
}
