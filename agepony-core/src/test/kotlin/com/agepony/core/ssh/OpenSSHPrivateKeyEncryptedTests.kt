package com.agepony.core.ssh

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for encrypted-PEM parsing via `OpenSSHPrivateKey.parse(pem, passphrase)`.
 *
 * Constructs encrypted PEMs in-test from known seeds + passphrases (via TestPEMBuilder),
 * round-trips them back through parse, verifies the recovered fields match. Also exercises
 * failure paths: wrong passphrase, missing passphrase, unsupported cipher/kdf.
 */
class OpenSSHPrivateKeyEncryptedTests {
    private val testSeed = ByteArray(32) { (it * 7 + 13).toByte() }
    private val testComment = "test@agepony"
    private val testPassphrase = "agepony-test-passphrase"

    @Test
    fun parse_encryptedEd25519_correctPassphrase_succeeds() {
        val (pem, expectedPubKey) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
        )
        val parsed = OpenSSHPrivateKey.parse(pem, testPassphrase)
        assertTrue(parsed is OpenSSHPrivateKey.Ed25519, "expected Ed25519")
        parsed as OpenSSHPrivateKey.Ed25519
        assertArrayEquals(testSeed, parsed.privateKey)
        assertArrayEquals(expectedPubKey, parsed.publicKey)
        assertEquals(testComment, parsed.comment)
    }

    @Test
    fun parse_encryptedEd25519_wrongPassphrase_throws() {
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
        )
        val exception = assertThrows(
            OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java
        ) {
            OpenSSHPrivateKey.parse(pem, "wrong-passphrase")
        }
        assertTrue(
            (exception.message ?: "").contains("passphrase"),
            "expected wrong-passphrase error, got: ${exception.message}"
        )
    }

    @Test
    fun parse_encrypted_missingPassphrase_throws() {
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
        )
        val exception = assertThrows(
            OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java
        ) {
            OpenSSHPrivateKey.parse(pem, null)
        }
        assertTrue(
            (exception.message ?: "").contains("no passphrase"),
            "expected missing-passphrase error, got: ${exception.message}"
        )
    }

    @Test
    fun parse_encrypted_unsupportedCipher_throws() {
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
            cipherName = "aes128-cbc",
        )
        val exception = assertThrows(
            OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java
        ) {
            OpenSSHPrivateKey.parse(pem, testPassphrase)
        }
        assertTrue(
            (exception.message ?: "").contains("cipher"),
            "expected cipher error, got: ${exception.message}"
        )
    }

    @Test
    fun parse_encrypted_unsupportedKDF_throws() {
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
            kdfName = "pbkdf2",
        )
        val exception = assertThrows(
            OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java
        ) {
            OpenSSHPrivateKey.parse(pem, testPassphrase)
        }
        assertTrue(
            (exception.message ?: "").contains("KDF") ||
            (exception.message ?: "").contains("kdf"),
            "expected KDF error, got: ${exception.message}"
        )
    }

    @Test
    fun encryptedPEM_changesWithPassphrase() {
        val (pemA, _) = TestPEMBuilder.buildEncryptedEd25519PEM(testSeed, testComment, "pass-a")
        val (pemB, _) = TestPEMBuilder.buildEncryptedEd25519PEM(testSeed, testComment, "pass-b")
        assertTrue(pemA != pemB, "Different passphrases should yield different ciphertexts")
    }

    @Test
    fun parse_encryptedEd25519_unicodePassphrase() {
        val unicodePass = "agepony🐴漢字"
        val (pem, expectedPubKey) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = unicodePass,
        )
        val parsed = OpenSSHPrivateKey.parse(pem, unicodePass)
        parsed as OpenSSHPrivateKey.Ed25519
        assertArrayEquals(testSeed, parsed.privateKey)
        assertArrayEquals(expectedPubKey, parsed.publicKey)
    }

    @Test
    fun parse_encryptedEd25519_highRounds() {
        // 32 rounds — slower but should still succeed
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
            rounds = 32,
        )
        val parsed = OpenSSHPrivateKey.parse(pem, testPassphrase)
        parsed as OpenSSHPrivateKey.Ed25519
        assertArrayEquals(testSeed, parsed.privateKey)
    }
}
