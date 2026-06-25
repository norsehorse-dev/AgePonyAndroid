package com.agepony.core.crypto

import org.bouncycastle.crypto.digests.SHA512Digest

/**
 * OpenBSD bcrypt_pbkdf KDF. Used by OpenSSH to derive AES key + IV from a passphrase
 * when storing private keys with `aes256-ctr / bcrypt` cipher mode.
 *
 * Algorithm (per `lib/libutil/bcrypt_pbkdf.c` in the OpenBSD source tree):
 *   1. sha2pass = SHA-512(passphrase)
 *   2. Output is built in blocks of 32 bytes; `stride` blocks total.
 *   3. For each block (count = 1, 2, ...):
 *        - sha2salt = SHA-512(salt || uint32_BE(count))
 *        - tmpout = bcrypt_hash(sha2pass, sha2salt)
 *        - out_block = tmpout
 *        - For each subsequent round (2..rounds):
 *            sha2salt = SHA-512(tmpout)
 *            tmpout = bcrypt_hash(sha2pass, sha2salt)
 *            out_block ^= tmpout
 *        - Stride-spread out_block bytes into final output (position = i * stride + count - 1).
 *
 * For OpenSSH unlocking we typically want 48 bytes (32-byte AES-256 key + 16-byte IV).
 */
object BcryptPBKDF {
    class BcryptPBKDFException(message: String) : Exception(message)

    private const val BCRYPT_HASHSIZE = 32

    fun derive(passphrase: ByteArray, salt: ByteArray, rounds: Int, keyLen: Int): ByteArray {
        if (rounds < 1) throw BcryptPBKDFException("rounds must be >= 1")
        if (keyLen <= 0) throw BcryptPBKDFException("keyLen must be > 0")
        if (passphrase.isEmpty()) throw BcryptPBKDFException("passphrase must be non-empty")
        if (salt.isEmpty()) throw BcryptPBKDFException("salt must be non-empty")

        val out = ByteArray(keyLen)
        val stride = (keyLen + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE
        val initialAmt = (keyLen + stride - 1) / stride

        val sha2pass = sha512(passphrase)

        var remaining = keyLen
        var count = 1
        while (remaining > 0) {
            // countsalt = salt || uint32_BE(count)
            val countsalt = ByteArray(salt.size + 4)
            System.arraycopy(salt, 0, countsalt, 0, salt.size)
            countsalt[salt.size]     = ((count ushr 24) and 0xff).toByte()
            countsalt[salt.size + 1] = ((count ushr 16) and 0xff).toByte()
            countsalt[salt.size + 2] = ((count ushr 8) and 0xff).toByte()
            countsalt[salt.size + 3] = (count and 0xff).toByte()

            var sha2salt = sha512(countsalt)
            var tmpout = bcryptHash(sha2pass, sha2salt)
            val outBlock = tmpout.copyOf()

            for (round in 1 until rounds) {
                sha2salt = sha512(tmpout)
                tmpout = bcryptHash(sha2pass, sha2salt)
                for (j in 0 until BCRYPT_HASHSIZE) {
                    outBlock[j] = (outBlock[j].toInt() xor tmpout[j].toInt()).toByte()
                }
            }

            val amt = minOf(initialAmt, remaining)
            var written = 0
            for (i in 0 until amt) {
                val dest = i * stride + (count - 1)
                if (dest >= keyLen) break
                out[dest] = outBlock[i]
                written++
            }
            remaining -= written
            count++
        }
        return out
    }

    /**
     * `bcrypt_hash` — the core primitive built on eksblowfish.
     *
     * Initializes a fresh Blowfish state, runs `expandstate(salt, pass)` once, then
     * 64 alternating `expand0state(salt)` / `expand0state(pass)` calls. Encrypts the
     * 32-byte "OxychromaticBlowfishSwatDynamite" magic string 64 times. Outputs the
     * 32 bytes as little-endian per-uint32.
     */
    private fun bcryptHash(sha2pass: ByteArray, sha2salt: ByteArray): ByteArray {
        require(sha2pass.size == 64)
        require(sha2salt.size == 64)
        val state = Blowfish()
        state.expandstate(sha2salt, sha2pass)
        for (i in 0 until 64) {
            state.expand0state(sha2salt)
            state.expand0state(sha2pass)
        }
        // "OxychromaticBlowfishSwatDynamite" as 8 big-endian uint32s
        val cdata = intArrayOf(
            0x4f787963, 0x68726f6d, 0x61746963, 0x426c6f77,
            0x66697368, 0x53776174, 0x44796e61, 0x6d697465
        )
        for (round in 0 until 64) {
            var j = 0
            while (j < 8) {
                val r = state.encipher(cdata[j], cdata[j + 1])
                cdata[j] = r[0]
                cdata[j + 1] = r[1]
                j += 2
            }
        }
        // Output as little-endian bytes
        val out = ByteArray(32)
        for (i in 0 until 8) {
            val w = cdata[i]
            out[i * 4]     = (w and 0xff).toByte()
            out[i * 4 + 1] = ((w ushr 8) and 0xff).toByte()
            out[i * 4 + 2] = ((w ushr 16) and 0xff).toByte()
            out[i * 4 + 3] = ((w ushr 24) and 0xff).toByte()
        }
        return out
    }

    private fun sha512(data: ByteArray): ByteArray {
        val digest = SHA512Digest()
        digest.update(data, 0, data.size)
        val out = ByteArray(64)
        digest.doFinal(out, 0)
        return out
    }
}
