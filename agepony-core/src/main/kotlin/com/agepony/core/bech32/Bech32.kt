package com.agepony.core.bech32

/**
 * Bech32 (BIP-0173) encoding used by age for human-readable key strings:
 *   - `age1...`              for X25519 public keys (HRP = "age")
 *   - `AGE-SECRET-KEY-1...`  for X25519 secret keys (HRP = "AGE-SECRET-KEY")
 *
 * This is the original Bech32 (polymod constant = 1), NOT Bech32m (constant = 0x2bc830a3).
 * age uses the original variant.
 */
object Bech32 {
    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val GENERATOR = intArrayOf(
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    )

    class Bech32Exception(message: String) : Exception(message)

    /**
     * Encode arbitrary bytes with the given human-readable part.
     * Returned string is all lowercase.
     */
    fun encode(hrp: String, data: ByteArray): String {
        if (hrp.isEmpty()) throw Bech32Exception("HRP must not be empty")
        val hrpLower = hrp.lowercase()
        val converted = convertBits(data, 8, 5, pad = true)
        val checksum = createChecksum(hrpLower, converted)
        val combined = converted + checksum
        val builder = StringBuilder()
        builder.append(hrpLower).append('1')
        for (v in combined) builder.append(CHARSET[v])
        return builder.toString()
    }

    /**
     * Decode a Bech32 string. Returns (hrp, raw bytes).
     * Rejects mixed-case (BIP-0173 requirement).
     */
    fun decode(input: String): Pair<String, ByteArray> {
        if (input.length < 8) throw Bech32Exception("too short")
        if (input.length > 1023) throw Bech32Exception("too long")  // sanity cap

        // Case enforcement
        val hasUpper = input.any { it in 'A'..'Z' }
        val hasLower = input.any { it in 'a'..'z' }
        if (hasUpper && hasLower) throw Bech32Exception("mixed case")
        val s = input.lowercase()

        // Find separator (last '1')
        val sepIdx = s.lastIndexOf('1')
        if (sepIdx < 1) throw Bech32Exception("missing or misplaced separator")
        if (sepIdx + 7 > s.length) throw Bech32Exception("data part too short for checksum")

        val hrp = s.substring(0, sepIdx)
        val dataPart = s.substring(sepIdx + 1)

        // HRP charset validation
        for (c in hrp) {
            val code = c.code
            if (code !in 33..126) throw Bech32Exception("HRP character out of range")
        }

        // Decode 5-bit values
        val data5 = IntArray(dataPart.length)
        for (i in dataPart.indices) {
            val idx = CHARSET.indexOf(dataPart[i])
            if (idx < 0) throw Bech32Exception("invalid character '${dataPart[i]}'")
            data5[i] = idx
        }

        // Verify checksum
        if (!verifyChecksum(hrp, data5)) throw Bech32Exception("checksum mismatch")

        // Strip the 6-symbol checksum and convert 5-bit groups to bytes
        val payload5 = data5.sliceArray(0 until data5.size - 6)
        val bytes = convertBits(int5ArrayToByteArray(payload5), 5, 8, pad = false)
            .let { ints -> ByteArray(ints.size) { ints[it].toByte() } }
        return hrp to bytes
    }

    // --- Internals ---

    private fun polymod(values: IntArray): Int {
        var chk = 1
        for (v in values) {
            val top = chk ushr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v
            for (i in 0..4) {
                if ((top ushr i) and 1 != 0) chk = chk xor GENERATOR[i]
            }
        }
        return chk
    }

    private fun hrpExpand(hrp: String): IntArray {
        val n = hrp.length
        val out = IntArray(n * 2 + 1)
        for (i in 0 until n) out[i] = hrp[i].code ushr 5
        out[n] = 0
        for (i in 0 until n) out[n + 1 + i] = hrp[i].code and 31
        return out
    }

    private fun createChecksum(hrp: String, data: IntArray): IntArray {
        val values = hrpExpand(hrp) + data + IntArray(6)
        val mod = polymod(values) xor 1
        return IntArray(6) { (mod ushr (5 * (5 - it))) and 31 }
    }

    private fun verifyChecksum(hrp: String, data: IntArray): Boolean {
        return polymod(hrpExpand(hrp) + data) == 1
    }

    /**
     * Convert between groups of bits. `data` interpreted as `fromBits`-bit values per element.
     * Returned IntArray contains `toBits`-bit values.
     */
    private fun convertBits(data: ByteArray, fromBits: Int, toBits: Int, pad: Boolean): IntArray {
        var acc = 0
        var bits = 0
        val result = mutableListOf<Int>()
        val maxV = (1 shl toBits) - 1
        val maxAcc = (1 shl (fromBits + toBits - 1)) - 1
        for (byte in data) {
            val v = byte.toInt() and 0xff
            if (v ushr fromBits != 0) throw Bech32Exception("input value out of range for $fromBits bits")
            acc = ((acc shl fromBits) or v) and maxAcc
            bits += fromBits
            while (bits >= toBits) {
                bits -= toBits
                result.add((acc ushr bits) and maxV)
            }
        }
        if (pad) {
            if (bits > 0) result.add((acc shl (toBits - bits)) and maxV)
        } else if (bits >= fromBits || ((acc shl (toBits - bits)) and maxV) != 0) {
            throw Bech32Exception("non-zero padding in 8-to-5 conversion")
        }
        return result.toIntArray()
    }

    private fun int5ArrayToByteArray(values: IntArray): ByteArray {
        return ByteArray(values.size) { values[it].toByte() }
    }
}
