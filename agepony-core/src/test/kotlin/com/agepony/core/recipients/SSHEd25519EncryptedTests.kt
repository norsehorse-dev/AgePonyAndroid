package com.agepony.core.recipients

import com.agepony.core.Age
import com.agepony.core.ssh.TestPEMBuilder
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Tests for `SSHEd25519Identity.fromPEM(pem, passphrase)`.
 *
 * Verifies the passphrase overload works end-to-end: build encrypted PEM → fromPEM →
 * use the identity to decrypt an age file encrypted to the matching recipient.
 */
class SSHEd25519EncryptedTests {
    private val testSeed = ByteArray(32) { (it * 11 + 5).toByte() }
    private val testComment = "agepony@encrypted"
    private val testPassphrase = "test-passphrase-x"

    @Test
    fun fromPEM_withPassphrase_returnsCorrectIdentity() {
        val (pem, expectedPubKey) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
        )
        val identity = SSHEd25519Identity.fromPEM(pem, testPassphrase)
        assertArrayEquals(expectedPubKey, identity.edPublicKey)
        assertArrayEquals(testSeed, identity.edSeed)
    }

    @Test
    fun fromPEM_withWrongPassphrase_throws() {
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
        )
        assertThrows(Exception::class.java) {
            SSHEd25519Identity.fromPEM(pem, "definitely-not-the-right-pass")
        }
    }

    @Test
    fun fromPEM_withoutPassphrase_throwsOnEncryptedPEM() {
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
        )
        // Default-arg path: SSHEd25519Identity.fromPEM(pem) must reject encrypted PEMs
        assertThrows(Exception::class.java) {
            SSHEd25519Identity.fromPEM(pem)
        }
    }

    /** End-to-end: encrypt with the recipient derived from the identity, decrypt. */
    @Test
    fun fromPEM_endToEndDecrypts_throughAge() {
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = testPassphrase,
        )
        val identity = SSHEd25519Identity.fromPEM(pem, testPassphrase)
        val recipient = SSHEd25519Recipient(identity.edPublicKey)

        val plaintext = "hello from encrypted ed25519 PEM".toByteArray(Charsets.UTF_8)
        val ciphertext = Age.encrypt(plaintext, listOf(recipient))
        val decrypted = Age.decrypt(ciphertext, listOf(identity))

        assertArrayEquals(plaintext, decrypted)
    }
}
