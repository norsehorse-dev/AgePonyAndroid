package com.agepony.core

import com.agepony.core.recipients.SSHEd25519Identity
import com.agepony.core.recipients.SSHRSAIdentity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.FileNotFoundException

/**
 * Cross-implementation tests for passphrase-encrypted SSH identities.
 *
 * Fixture flow (built by `generate-fixtures.sh`):
 *   1. `ssh-keygen -t ed25519 -N "agepony-test-passphrase"` creates an encrypted PEM.
 *   2. `age -R <pubkey>` encrypts the plaintext to the matching public key.
 *
 * If these decrypt to "hello agepony", Android's bcrypt_pbkdf, AES-CTR, and the rest of
 * the SSH-encrypted-identity pipeline are wire-compatible with the reference age CLI
 * and OpenSSH for the encrypted-PEM path.
 */
class CrossImplEncryptedFixtureTests {
    private val expectedPlaintext = "hello agepony"
    private val fixturePassphrase = "agepony-test-passphrase"

    @Test
    fun sshEd25519_encrypted_fixture_decryptsToHelloAgePony() {
        val pem = loadResourceText("/fixtures/ssh_ed25519_encrypted_identity")
        val ciphertext = loadResourceBytes("/fixtures/ssh_ed25519_encrypted_hello.age")
        val identity = SSHEd25519Identity.fromPEM(pem, fixturePassphrase)
        val plaintext = Age.decrypt(ciphertext, listOf(identity))
        assertEquals(expectedPlaintext, String(plaintext, Charsets.UTF_8))
    }

    @Test
    fun sshRSA_encrypted_fixture_decryptsToHelloAgePony() {
        val pem = loadResourceText("/fixtures/ssh_rsa_encrypted_identity")
        val ciphertext = loadResourceBytes("/fixtures/ssh_rsa_encrypted_hello.age")
        val identity = SSHRSAIdentity.fromPEM(pem, fixturePassphrase)
        val plaintext = Age.decrypt(ciphertext, listOf(identity))
        assertEquals(expectedPlaintext, String(plaintext, Charsets.UTF_8))
    }

    @Test
    fun sshEd25519_encrypted_fixture_wrongPassphrase_throws() {
        val pem = loadResourceText("/fixtures/ssh_ed25519_encrypted_identity")
        try {
            SSHEd25519Identity.fromPEM(pem, "wrong-pass")
            throw AssertionError("expected exception with wrong passphrase")
        } catch (e: Exception) {
            val msg = e.message ?: ""
            assertTrue(
                msg.contains("passphrase", ignoreCase = true) ||
                msg.contains("check", ignoreCase = true),
                "expected passphrase-related error, got: $msg"
            )
        }
    }

    private fun loadResourceText(path: String): String {
        val url = javaClass.getResource(path)
            ?: throw FileNotFoundException(
                "$path not found in classpath. " +
                "Run `bash generate-fixtures.sh` from the project root first."
            )
        return url.readText(Charsets.UTF_8)
    }

    private fun loadResourceBytes(path: String): ByteArray {
        val url = javaClass.getResource(path)
            ?: throw FileNotFoundException(
                "$path not found in classpath. " +
                "Run `bash generate-fixtures.sh` from the project root first."
            )
        return url.readBytes()
    }
}
