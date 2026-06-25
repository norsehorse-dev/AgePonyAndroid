package com.agepony.core

import com.agepony.core.recipients.SSHEd25519Identity
import com.agepony.core.recipients.SSHRSAIdentity
import com.agepony.core.recipients.X25519Identity
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Validates Android against the reference `age` CLI by decrypting fixture files
 * generated locally with `./generate-fixtures.sh`.
 *
 * Tests skip (via `assumeTrue`) if fixtures aren't generated yet. Generate them with:
 *   brew install age && bash generate-fixtures.sh
 *
 * Fixture plaintext is always "hello AgePony".
 */
class CrossImplFixtureTests {
    private val fixturesDir = File("src/test/resources/fixtures")
    private val expectedPlaintext = "hello AgePony".toByteArray()

    @Test
    fun x25519_fixture_decryptsToHelloAgePony() {
        val idFile = File(fixturesDir, "x25519_identity.txt")
        val ctFile = File(fixturesDir, "x25519_hello.age")
        assumeTrue(
            idFile.exists() && ctFile.exists(),
            "X25519 fixtures not found; run bash generate-fixtures.sh from project root"
        )

        val bech32 = idFile.readLines()
            .map { it.trim() }
            .first { it.isNotEmpty() && !it.startsWith("#") }
        val identity = X25519Identity(bech32)

        val ciphertext = ctFile.readBytes()
        val plaintext = Age.decrypt(ciphertext, listOf(identity))
        assertArrayEquals(expectedPlaintext, plaintext)
    }

    @Test
    fun sshEd25519_fixture_decryptsToHelloAgePony() {
        val idFile = File(fixturesDir, "ssh_ed25519_identity")
        val ctFile = File(fixturesDir, "ssh_ed25519_hello.age")
        assumeTrue(
            idFile.exists() && ctFile.exists(),
            "ssh-ed25519 fixtures not found; run bash generate-fixtures.sh from project root"
        )

        val pem = idFile.readText()
        val identity = SSHEd25519Identity.fromPEM(pem)

        val ciphertext = ctFile.readBytes()
        val plaintext = Age.decrypt(ciphertext, listOf(identity))
        assertArrayEquals(expectedPlaintext, plaintext)
    }

    @Test
    fun sshRSA_fixture_decryptsToHelloAgePony() {
        val idFile = File(fixturesDir, "ssh_rsa_identity")
        val ctFile = File(fixturesDir, "ssh_rsa_hello.age")
        assumeTrue(
            idFile.exists() && ctFile.exists(),
            "ssh-rsa fixtures not found; run bash generate-fixtures.sh from project root"
        )

        val pem = idFile.readText()
        val identity = SSHRSAIdentity.fromPEM(pem)

        val ciphertext = ctFile.readBytes()
        val plaintext = Age.decrypt(ciphertext, listOf(identity))
        assertArrayEquals(expectedPlaintext, plaintext)
    }
}
