package com.agepony.core.archive

import java.io.ByteArrayOutputStream

/**
 * Compact USTAR tar, used to bundle multiple files into a single payload before age
 * encryption (so a multi-file encrypt produces one `.tar.age`).
 *
 * "Compact" means the archive is exactly the entry blocks followed by the two zero blocks
 * that mark end-of-archive, with no padding out to a 10240-byte record. Headers use fixed
 * fields (mode 0644, uid/gid 0, empty uname/gname, mtime defaulting to 0) so the same set
 * of files always produces the same bytes, matching the iOS reference archive. Standard
 * tar tools extract it normally.
 */
object TarArchive {
    class TarException(message: String, cause: Throwable? = null) : Exception(message, cause)

    class Entry(val name: String, val data: ByteArray)

    private const val BLOCK = 512
    private const val NAME_MAX = 100
    private const val MODE_0644 = 420L // 0o644

    fun create(entries: List<Entry>, mtime: Long = 0L): ByteArray {
        val out = ByteArrayOutputStream()
        for (e in entries) {
            out.write(header(e.name, e.data.size, mtime))
            out.write(e.data)
            val pad = (BLOCK - e.data.size % BLOCK) % BLOCK
            if (pad > 0) out.write(ByteArray(pad))
        }
        out.write(ByteArray(BLOCK * 2)) // two zero blocks: end of archive
        return out.toByteArray()
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

    private fun header(name: String, size: Int, mtime: Long): ByteArray {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        if (nameBytes.size > NAME_MAX) throw TarException("name too long for USTAR (max 100): $name")
        val h = ByteArray(BLOCK)
        System.arraycopy(nameBytes, 0, h, 0, nameBytes.size)
        writeOctal(h, 100, 8, MODE_0644)       // mode
        writeOctal(h, 108, 8, 0)               // uid
        writeOctal(h, 116, 8, 0)               // gid
        writeOctal(h, 124, 12, size.toLong())  // size
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
        return if (sb.isEmpty()) 0 else sb.toString().toLong(8)
    }

    private fun readString(buf: ByteArray, off: Int, len: Int): String {
        var end = off
        while (end < off + len && buf[end].toInt() != 0) end++
        return String(buf, off, end - off, Charsets.UTF_8)
    }
}
