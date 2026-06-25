package com.agepony.core.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * KAT vectors for bcrypt_pbkdf from OpenBSD's regress test suite.
 * Cross-verified against the rust-crypto bcrypt_pbkdf implementation
 * (https://rust.algorithmexamples.com/web/cryptography/bcrypt_pbkdf.html).
 *
 * If any of these vectors fail, the bug is in one of:
 *   - Blowfish constants (P-array or S-box) — caught earlier by BlowfishTests + the
 *     SHA-256 self-check in Blowfish.kt
 *   - Eksblowfish key schedule (expand0state / expandstate)
 *   - bcrypt_hash magic-string byte ordering or per-uint32 little-endian output
 *   - bcrypt_pbkdf stride-spreading logic (dest = i * stride + count - 1)
 *   - SHA-512 input layout (salt || uint32_BE(count))
 */
class BcryptPBKDFTests {
    private fun toHex(b: ByteArray): String =
        b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    @Test
    fun openbsd_vector1_password_salt_rounds4_keylen32() {
        // pass="password" (8 bytes), salt="salt" (4 bytes), rounds=4, keylen=32
        val pass = "password".toByteArray(Charsets.US_ASCII)
        val salt = "salt".toByteArray(Charsets.US_ASCII)
        val expected = "5bbf0cc293587f1c3635555c27796598" +
                       "d47e579071bf427e9d8fbe842aba34d9"
        val actual = BcryptPBKDF.derive(pass, salt, rounds = 4, keyLen = 32)
        assertEquals(expected, toHex(actual))
    }

    @Test
    fun openbsd_vector2_password_nullSalt_rounds4_keylen16() {
        // pass="password" (8 bytes), salt=\0 (1 byte), rounds=4, keylen=16
        val pass = "password".toByteArray(Charsets.US_ASCII)
        val salt = byteArrayOf(0x00)
        val expected = "c12b566235eee04c212598970a579a67"
        val actual = BcryptPBKDF.derive(pass, salt, rounds = 4, keyLen = 16)
        assertEquals(expected, toHex(actual))
    }

    @Test
    fun openbsd_vector3_nullPass_salt_rounds4_keylen16() {
        // pass=\0 (1 byte), salt="salt" (4 bytes), rounds=4, keylen=16
        val pass = byteArrayOf(0x00)
        val salt = "salt".toByteArray(Charsets.US_ASCII)
        val expected = "6051be18c2f4f82cbf0efee5471b4bb9"
        val actual = BcryptPBKDF.derive(pass, salt, rounds = 4, keyLen = 16)
        assertEquals(expected, toHex(actual))
    }

    @Test
    fun openbsd_vector4_passwordNul_saltNul_rounds4_keylen32() {
        // pass="password\0" (9 bytes), salt="salt\0" (5 bytes), rounds=4, keylen=32
        val pass = "password\u0000".toByteArray(Charsets.ISO_8859_1)
        val salt = "salt\u0000".toByteArray(Charsets.ISO_8859_1)
        val expected = "7410e44cf4fa07bfaac8a928b1727fac" +
                       "001375e7bf7384370f48efd121743050"
        val actual = BcryptPBKDF.derive(pass, salt, rounds = 4, keyLen = 32)
        assertEquals(expected, toHex(actual))
    }

    @Test
    fun openbsd_vector5_password_salt_rounds8_keylen64() {
        // pass="password" (8 bytes), salt="salt" (4 bytes), rounds=8, keylen=64
        // 64-byte output forces stride > 1, exercising the interleaving logic.
        val pass = "password".toByteArray(Charsets.US_ASCII)
        val salt = "salt".toByteArray(Charsets.US_ASCII)
        val expected = "e1367ec5151a33faac4cc1c144cd23fa" +
                       "15d5548493ecc99b9b5d9c0d3b27bec7" +
                       "6227ea66088b849b20ab7aa478010246" +
                       "e74bba51723fefa9f9474d6508845e8d"
        val actual = BcryptPBKDF.derive(pass, salt, rounds = 8, keyLen = 64)
        assertEquals(expected, toHex(actual))
    }

    @Test
    fun derive_isDeterministic() {
        // Same inputs → same output every time.
        val pass = "agepony-test-passphrase".toByteArray(Charsets.UTF_8)
        val salt = ByteArray(16) { it.toByte() }
        val a = BcryptPBKDF.derive(pass, salt, rounds = 8, keyLen = 48)
        val b = BcryptPBKDF.derive(pass, salt, rounds = 8, keyLen = 48)
        assertArrayEquals(a, b)
    }

    @Test
    fun derive_differentPassphrasesProduceDifferentKeys() {
        val salt = "fixed-salt-bytes".toByteArray(Charsets.US_ASCII)
        val a = BcryptPBKDF.derive("aaa".toByteArray(), salt, rounds = 4, keyLen = 32)
        val b = BcryptPBKDF.derive("bbb".toByteArray(), salt, rounds = 4, keyLen = 32)
        assertEquals(false, a.contentEquals(b))
    }

    @Test
    fun derive_rejectsZeroRounds() {
        assertThrows(BcryptPBKDF.BcryptPBKDFException::class.java) {
            BcryptPBKDF.derive("pass".toByteArray(), "salt".toByteArray(), rounds = 0, keyLen = 32)
        }
    }

    @Test
    fun derive_rejectsEmptyPassphrase() {
        assertThrows(BcryptPBKDF.BcryptPBKDFException::class.java) {
            BcryptPBKDF.derive(ByteArray(0), "salt".toByteArray(), rounds = 4, keyLen = 32)
        }
    }

    @Test
    fun derive_rejectsEmptySalt() {
        assertThrows(BcryptPBKDF.BcryptPBKDFException::class.java) {
            BcryptPBKDF.derive("pass".toByteArray(), ByteArray(0), rounds = 4, keyLen = 32)
        }
    }

    @Test
    fun derive_rejectsZeroKeyLen() {
        assertThrows(BcryptPBKDF.BcryptPBKDFException::class.java) {
            BcryptPBKDF.derive("pass".toByteArray(), "salt".toByteArray(), rounds = 4, keyLen = 0)
        }
    }

    @Test
    fun derive_48ByteOutput_AESKeyPlusIV() {
        // OpenSSH-style: derive 48 bytes for 32-byte AES-256 key + 16-byte IV.
        val pass = "test".toByteArray()
        val salt = ByteArray(16)
        val out = BcryptPBKDF.derive(pass, salt, rounds = 4, keyLen = 48)
        assertEquals(48, out.size)
    }
}
