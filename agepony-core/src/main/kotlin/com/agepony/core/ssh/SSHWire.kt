package com.agepony.core.ssh

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * SSH wire format encoding/decoding. Each "string" is `<4-byte BE uint32 length> <bytes>`.
 * Used by OpenSSH public-key blobs, OpenSSH private-key PEMs, and the ssh-ed25519
 * recipient tag construction.
 */
object SSHWire {
    class SSHWireException(message: String) : Exception(message)

    /**
     * Read a length-prefixed byte string from the buffer. Position advances past the
     * length and the bytes.
     */
    fun readString(buf: ByteBuffer): ByteArray {
        if (buf.remaining() < 4) throw SSHWireException("short read: need 4 bytes for length")
        val len = buf.int
        if (len < 0) throw SSHWireException("negative length: $len")
        if (len > buf.remaining()) throw SSHWireException(
            "length $len exceeds remaining ${buf.remaining()}"
        )
        val bytes = ByteArray(len)
        buf.get(bytes)
        return bytes
    }

    /** Read a 4-byte BE uint32 as a (positive) Int. Throws if the high bit is set. */
    fun readUInt32(buf: ByteBuffer): Int {
        if (buf.remaining() < 4) throw SSHWireException("short read: need 4 bytes for uint32")
        val v = buf.int
        if (v < 0) throw SSHWireException("uint32 too large: $v")
        return v
    }

    /** Write a length-prefixed byte string to `out`. */
    fun writeString(out: ByteArrayOutputStream, bytes: ByteArray) {
        val len = bytes.size
        out.write((len ushr 24) and 0xff)
        out.write((len ushr 16) and 0xff)
        out.write((len ushr 8) and 0xff)
        out.write(len and 0xff)
        out.write(bytes)
    }

    /** Convenience: build a single length-prefixed string blob. */
    fun encodeString(bytes: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        writeString(out, bytes)
        return out.toByteArray()
    }

    /** Wrap a byte array in a BE-ordered ByteBuffer ready for reading. */
    fun wrapForRead(bytes: ByteArray): ByteBuffer =
        ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
}
