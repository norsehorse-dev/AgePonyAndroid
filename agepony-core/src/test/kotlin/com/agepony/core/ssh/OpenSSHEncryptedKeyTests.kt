package com.agepony.core.ssh

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission

/**
 * Tests for [OpenSSHEncryptedKey.decryptedPem], the PEM normalizer behind RSA identity
 * storage: any OpenSSH PEM in, unencrypted `cipher=none` PEM out, byte-stable on
 * repeat. Encrypted inputs come from both TestPEMBuilder (in-test construction) and the
 * real ssh-keygen fixtures; the final test hands the output back to ssh-keygen to prove
 * OpenSSH itself accepts what we synthesize.
 */
class OpenSSHEncryptedKeyTests {
    private val fixturesDir = File("src/test/resources/fixtures")
    private val fixturePassphrase = "agepony-test-passphrase"
    private val testSeed = ByteArray(32) { (it * 7 + 13).toByte() }
    private val testComment = "test@agepony"

    private fun fixture(name: String): String {
        val f = File(fixturesDir, name)
        assertTrue(f.exists(), "fixture $name not found; run bash generate-fixtures.sh from project root")
        return f.readText()
    }

    @Test
    fun unencryptedRsaFixture_roundTrips() {
        val pem = fixture("ssh_rsa_identity")
        val original = OpenSSHPrivateKey.parse(pem) as OpenSSHPrivateKey.RSA
        val decrypted = OpenSSHEncryptedKey.decryptedPem(pem)
        val reparsed = OpenSSHPrivateKey.parse(decrypted) as OpenSSHPrivateKey.RSA
        assertEquals(original, reparsed)
        assertTrue(decrypted.endsWith("\n"), "normalized PEM must end with a newline")
    }

    @Test
    fun encryptedRsaFixture_decryptsAndParsesWithoutPassphrase() {
        val pem = fixture("ssh_rsa_encrypted_identity")
        val original = OpenSSHPrivateKey.parse(pem, fixturePassphrase) as OpenSSHPrivateKey.RSA
        val decrypted = OpenSSHEncryptedKey.decryptedPem(pem, fixturePassphrase)
        val reparsed = OpenSSHPrivateKey.parse(decrypted) as OpenSSHPrivateKey.RSA
        assertEquals(original, reparsed)
    }

    @Test
    fun encryptedEd25519_builtPem_decrypts() {
        val (pem, expectedPub) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = fixturePassphrase,
        )
        val decrypted = OpenSSHEncryptedKey.decryptedPem(pem, fixturePassphrase)
        val parsed = OpenSSHPrivateKey.parse(decrypted) as OpenSSHPrivateKey.Ed25519
        assertTrue(testSeed.contentEquals(parsed.privateKey))
        assertTrue(expectedPub.contentEquals(parsed.publicKey))
        assertEquals(testComment, parsed.comment)
    }

    @Test
    fun wrongPassphrase_throws() {
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = fixturePassphrase,
        )
        val ex = assertThrows(OpenSSHEncryptedKey.OpenSSHEncryptedKeyException::class.java) {
            OpenSSHEncryptedKey.decryptedPem(pem, "wrong-passphrase")
        }
        assertTrue(
            (ex.message ?: "").contains("wrong passphrase"),
            "expected wrong-passphrase error, got: ${ex.message}"
        )
    }

    @Test
    fun missingPassphrase_throws() {
        val (pem, _) = TestPEMBuilder.buildEncryptedEd25519PEM(
            seed = testSeed,
            comment = testComment,
            passphrase = fixturePassphrase,
        )
        val ex = assertThrows(OpenSSHEncryptedKey.OpenSSHEncryptedKeyException::class.java) {
            OpenSSHEncryptedKey.decryptedPem(pem, null)
        }
        assertTrue(
            (ex.message ?: "").contains("no passphrase provided"),
            "expected missing-passphrase error, got: ${ex.message}"
        )
    }

    @Test
    fun output_isIdempotent() {
        val pem = fixture("ssh_rsa_encrypted_identity")
        val once = OpenSSHEncryptedKey.decryptedPem(pem, fixturePassphrase)
        val twice = OpenSSHEncryptedKey.decryptedPem(once)
        assertEquals(once, twice, "a normalized PEM must survive normalization unchanged")
    }

    @Test
    fun output_acceptedBySshKeygen() {
        assumeTrue(sshKeygenAvailable(), "ssh-keygen not on PATH; skipping interop check")
        val pem = fixture("ssh_rsa_encrypted_identity")
        val expectedPub = fixture("ssh_rsa_encrypted_identity.pub")
            .trim().split(" ")
        val decrypted = OpenSSHEncryptedKey.decryptedPem(pem, fixturePassphrase)

        val tmp = Files.createTempFile("agepony-decrypted-pem", "")
        try {
            Files.write(tmp, decrypted.toByteArray(Charsets.UTF_8))
            Files.setPosixFilePermissions(
                tmp,
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            )
            val proc = ProcessBuilder("ssh-keygen", "-y", "-f", tmp.toString())
                .redirectErrorStream(true)
                .start()
            val out = proc.inputStream.bufferedReader().readText()
            assertEquals(0, proc.waitFor(), "ssh-keygen -y rejected the synthesized PEM: $out")
            val produced = out.trim().split(" ")
            assertEquals(expectedPub[0], produced[0], "key type differs")
            assertEquals(expectedPub[1], produced[1], "public key blob differs")
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    private fun sshKeygenAvailable(): Boolean = try {
        ProcessBuilder("ssh-keygen", "-Q").redirectErrorStream(true).start().waitFor()
        true
    } catch (e: Exception) {
        false
    }
}
