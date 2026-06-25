package com.agepony.core.ssh

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer

/**
 * SSH multiple-precision integer (mpint) codec per RFC 4251 §5.
 *
 * Wire format: `<4-byte BE length> <bytes>`, where `bytes` is the two's-complement
 * big-endian representation of the integer. For positive integers whose MSB has the
 * high bit set, a leading 0x00 byte is included (to ensure positive interpretation).
 * Zero is encoded as length=0 with no bytes.
 *
 * `BigInteger.toByteArray()` already applies the leading-zero rule, so encoding is
 * automatic. Decoding via `BigInteger(bytes)` handles the two's-complement parse
 * correctly.
 */
object SSHMPInt {
    class SSHMPIntException(message: String) : Exception(message)

    /** Read an mpint from the buffer. */
    fun read(buf: ByteBuffer): BigInteger {
        val bytes = try {
            SSHWire.readString(buf)
        } catch (e: SSHWire.SSHWireException) {
            throw SSHMPIntException("malformed mpint length: ${e.message}")
        }
        return if (bytes.isEmpty()) BigInteger.ZERO else BigInteger(bytes)
    }

    /** Write a non-negative BigInteger as an mpint to `out`. */
    fun write(out: ByteArrayOutputStream, value: BigInteger) {
        if (value.signum() < 0) throw SSHMPIntException(
            "negative mpint not supported in this context"
        )
        val bytes = if (value.signum() == 0) ByteArray(0) else value.toByteArray()
        SSHWire.writeString(out, bytes)
    }

    /** Convenience: serialize a BigInteger as a length-prefixed mpint blob. */
    fun encode(value: BigInteger): ByteArray {
        val out = ByteArrayOutputStream()
        write(out, value)
        return out.toByteArray()
    }
}
