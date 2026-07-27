package com.agepony.core.archive

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

/**
 * Compact USTAR tar, used to bundle multiple files into a single payload before age
 * encryption (so a multi-file encrypt produces one `.tar.age`).
 *
 * "Compact" means the archive is exactly the entry blocks followed by the two zero blocks
 * that mark end-of-archive, with no padding out to a 10240-byte record. Headers use fixed
 * fields (mode 0644, uid/gid 0, empty uname/gname, mtime defaulting to 0) so the same set
 * of files always produces the same bytes, matching the iOS reference archive. Standard
 * tar tools extract it normally.
 *
 * [create] / [extract] hold the whole archive in memory. [writeEntry] / [finish] and
 * [forEachEntry] are the bounded-memory equivalents for files: they copy one 64 KiB buffer at
 * a time and produce byte-identical archives for the same entries.
 */
object TarArchive {
    class TarException(message: String, cause: Throwable? = null) : Exception(message, cause)

    class Entry(val name: String, val data: ByteArray)

    private const val BLOCK = 512
    private const val NAME_MAX = 100
    private const val MODE_0644 = 420L // 0o644
    private const val COPY_BUFFER = 64 * 1024

    /** Largest entry a USTAR 12-byte octal size field can express: 8^11 - 1, just under 8 GiB. */
    const val MAX_ENTRY_SIZE = 8589934591L

    fun create(entries: List<Entry>, mtime: Long = 0L): ByteArray {
        val out = ByteArrayOutputStream()
        for (e in entries) writeEntry(out, e.name, e.data, mtime)
        finish(out)
        return out.toByteArray()
    }

    // --- Streaming write ---

    /** Append one whole-buffer entry to [out]. Same bytes as the matching [create] entry. */
    fun writeEntry(out: OutputStream, name: String, data: ByteArray, mtime: Long = 0L) {
        out.write(header(name, data.size.toLong(), mtime))
        out.write(data)
        writePadding(out, data.size.toLong())
    }

    /**
     * Append one entry whose contents are streamed from [data], without ever holding the entry
     * in memory. [size] must be the exact byte count: USTAR writes the size into the header
     * before the data, so it cannot be discovered while copying.
     *
     * Throws [TarException] if [data] ends early. When [strict] is true (the default) it also
     * reads one byte past the entry to catch a stream that holds more than [size] bytes, which
     * would silently truncate the archived file; pass false when [data] carries further entries
     * and its position must be preserved.
     */
    fun writeEntry(
        out: OutputStream,
        name: String,
        size: Long,
        data: InputStream,
        mtime: Long = 0L,
        strict: Boolean = true,
    ) {
        if (size < 0) throw TarException("entry '$name' has negative size $size")
        if (size > MAX_ENTRY_SIZE) throw TarException("entry '$name' is too large for USTAR: $size bytes")
        out.write(header(name, size, mtime))
        val buf = ByteArray(COPY_BUFFER)
        var written = 0L
        while (written < size) {
            val want = minOf(buf.size.toLong(), size - written).toInt()
            val r = data.read(buf, 0, want)
            if (r < 0) {
                throw TarException("entry '$name' ended after $written bytes, header declared $size")
            }
            out.write(buf, 0, r)
            written += r
        }
        if (strict && data.read() >= 0) {
            throw TarException("entry '$name' has more than the declared $size bytes")
        }
        writePadding(out, size)
    }

    /** Write the two zero blocks that end an archive. Call once, after the last entry. */
    fun finish(out: OutputStream) {
        out.write(ByteArray(BLOCK * 2))
    }

    fun extract(archive: ByteArray): List<Entry> {
        if (archive.size % BLOCK != 0) throw TarException("tar size is not a multiple of 512")
        val entries = ArrayList<Entry>()
        var off = 0
        while (off + BLOCK <= archive.size) {
            val headerBlock = archive.copyOfRange(off, off + BLOCK)
            if (headerBlock.all { it.toInt() == 0 }) break // end-of-archive marker
            verifyChecksum(headerBlock)
            val name = readString(headerBlock, 0, NAME_MAX)
            val size = readOctal(headerBlock, 124, 12).toInt()
            off += BLOCK
            if (size < 0 || off + size > archive.size) throw TarException("entry '$name' size exceeds archive")
            entries.add(Entry(name, archive.copyOfRange(off, off + size)))
            off += ((size + BLOCK - 1) / BLOCK) * BLOCK
        }
        return entries
    }

    // --- Streaming read ---

    /**
     * Walk [input] entry by entry without materializing the archive. [handler] receives each
     * entry's name, size, and a stream bounded to that entry's bytes; whatever the handler
     * leaves unread is skipped before the next entry. The handler must not close the stream it
     * is given, and must not use it after returning.
     *
     * Stops at the end-of-archive marker, or at end of input for an archive that was truncated
     * after a complete entry (which [extract] also tolerates).
     */
    fun forEachEntry(input: InputStream, handler: (name: String, size: Long, data: InputStream) -> Unit) {
        while (true) {
            val headerBlock = ByteArray(BLOCK)
            val got = readFully(input, headerBlock, BLOCK)
            if (got == 0) return                      // clean end of input
            if (got < BLOCK) throw TarException("truncated tar header (got $got of $BLOCK bytes)")
            if (headerBlock.all { it.toInt() == 0 }) return   // end-of-archive marker
            verifyChecksum(headerBlock)
            val name = readString(headerBlock, 0, NAME_MAX)
            val size = readOctal(headerBlock, 124, 12)
            if (size < 0) throw TarException("entry '$name' has negative size")

            val bounded = BoundedInputStream(input, size)
            handler(name, size, bounded)
            bounded.drain(name)
            skipFully(input, (BLOCK - size % BLOCK) % BLOCK, name)
        }
    }

    /** Reads one entry's bytes and no more; unread bytes are skipped by [forEachEntry]. */
    private class BoundedInputStream(private val src: InputStream, private var remaining: Long) : InputStream() {
        override fun read(): Int {
            if (remaining <= 0) return -1
            val b = src.read()
            if (b >= 0) remaining--
            return b
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (remaining <= 0) return -1
            val want = minOf(len.toLong(), remaining).toInt()
            val r = src.read(b, off, want)
            if (r > 0) remaining -= r
            return r
        }

        override fun available(): Int = minOf(remaining, Int.MAX_VALUE.toLong()).toInt()

        /** Consume whatever the handler left behind, so the next header lines up. */
        fun drain(name: String) {
            if (remaining > 0) TarArchive.skipFully(src, remaining, name)
            remaining = 0
        }

        override fun close() { /* the underlying archive stream outlives this entry */ }
    }

    // --- Internals ---

    private fun writePadding(out: OutputStream, size: Long) {
        val pad = ((BLOCK - size % BLOCK) % BLOCK).toInt()
        if (pad > 0) out.write(ByteArray(pad))
    }

    private fun readFully(input: InputStream, buf: ByteArray, n: Int): Int {
        var off = 0
        while (off < n) {
            val r = input.read(buf, off, n - off)
            if (r < 0) break
            off += r
        }
        return off
    }

    private fun skipFully(input: InputStream, count: Long, name: String) {
        var left = count
        val scratch = ByteArray(minOf(count, COPY_BUFFER.toLong()).coerceAtLeast(1L).toInt())
        while (left > 0) {
            val skipped = input.skip(left)
            if (skipped > 0) { left -= skipped; continue }
            val want = minOf(left, scratch.size.toLong()).toInt()
            val r = input.read(scratch, 0, want)
            if (r < 0) throw TarException("truncated tar: entry '$name' ended early")
            left -= r
        }
    }

    private fun header(name: String, size: Long, mtime: Long): ByteArray {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        if (nameBytes.size > NAME_MAX) throw TarException("name too long for USTAR (max 100): $name")
        if (size > MAX_ENTRY_SIZE) throw TarException("entry '$name' is too large for USTAR: $size bytes")
        val h = ByteArray(BLOCK)
        System.arraycopy(nameBytes, 0, h, 0, nameBytes.size)
        writeOctal(h, 100, 8, MODE_0644)       // mode
        writeOctal(h, 108, 8, 0)               // uid
        writeOctal(h, 116, 8, 0)               // gid
        writeOctal(h, 124, 12, size)           // size
        writeOctal(h, 136, 12, mtime)          // mtime
        for (i in 148..155) h[i] = ' '.code.toByte() // checksum field as spaces for summing
        h[156] = '0'.code.toByte()             // typeflag: regular file
        val magic = "ustar".toByteArray(Charsets.US_ASCII)
        System.arraycopy(magic, 0, h, 257, magic.size) // "ustar\0"
        h[263] = '0'.code.toByte()             // version "00"
        h[264] = '0'.code.toByte()
        writeChecksum(h)
        return h
    }

    private fun writeChecksum(h: ByteArray) {
        var sum = 0
        for (b in h) sum += b.toInt() and 0xff
        val cs = Integer.toOctalString(sum).padStart(6, '0')
        if (cs.length > 6) throw TarException("checksum overflow")
        for (i in 0 until 6) h[148 + i] = cs[i].code.toByte()
        h[154] = 0                              // null
        h[155] = ' '.code.toByte()              // space
    }

    private fun verifyChecksum(header: ByteArray) {
        val stored = readOctal(header, 148, 8)
        val calc = header.copyOf()
        for (i in 148..155) calc[i] = ' '.code.toByte()
        var sum = 0L
        for (b in calc) sum += (b.toInt() and 0xff)
        if (sum != stored) throw TarException("tar header checksum mismatch")
    }

    private fun writeOctal(buf: ByteArray, off: Int, fieldLen: Int, value: Long) {
        val digits = fieldLen - 1
        val s = java.lang.Long.toOctalString(value).padStart(digits, '0')
        if (s.length > digits) throw TarException("octal field overflow for value $value")
        for (i in 0 until digits) buf[off + i] = s[i].code.toByte()
        buf[off + digits] = 0
    }

    private fun readOctal(buf: ByteArray, off: Int, len: Int): Long {
        val sb = StringBuilder()
        for (i in off until off + len) {
            val c = buf[i].toInt() and 0xff
            if (c == 0 || c == ' '.code) {
                if (sb.isNotEmpty()) break else continue
            }
            sb.append(c.toChar())
        }
        if (sb.isEmpty()) return 0
        return sb.toString().toLongOrNull(8)
            ?: throw TarException("tar header has a non-octal numeric field at offset $off")
    }

    private fun readString(buf: ByteArray, off: Int, len: Int): String {
        var end = off
        while (end < off + len && buf[end].toInt() != 0) end++
        return String(buf, off, end - off, Charsets.UTF_8)
    }
}
