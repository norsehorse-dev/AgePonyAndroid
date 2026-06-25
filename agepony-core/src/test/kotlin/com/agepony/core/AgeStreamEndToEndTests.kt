package com.agepony.core

import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.SecureRandom

/**
 * End-to-end streaming tests at the [Age] level, including interop between the streaming and
 * whole-buffer paths and a cross-impl check against the reference `age` CLI fixture.
 */
class AgeStreamEndToEndTests {
    private val rng = SecureRandom()

    @Test
    fun streamRoundTrip_singleX25519() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val plaintext = "hello AgePony streaming".toByteArray()

        val ct = ByteArrayOutputStream()
        Age.encryptStream(ByteArrayInputStream(plaintext), listOf(recipient), ct)

        val pt = ByteArrayOutputStream()
        Age.decryptStream(ByteArrayInputStream(ct.toByteArray()), listOf(identity), pt)

        assertArrayEquals(plaintext, pt.toByteArray())
    }

    @Test
    fun streamEncrypt_decryptsWithWholeBuffer() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val plaintext = ByteArray(200_000).also { rng.nextBytes(it) }

        val ct = ByteArrayOutputStream()
        Age.encryptStream(ByteArrayInputStream(plaintext), listOf(recipient), ct)

        // Cross-path: streamed ciphertext must decrypt with the whole-buffer API.
        val pt = Age.decrypt(ct.toByteArray(), listOf(identity))
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun wholeBufferEncrypt_decryptsWithStream() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val plaintext = ByteArray(200_000).also { rng.nextBytes(it) }

        val ct = Age.encrypt(plaintext, listOf(recipient))

        val pt = ByteArrayOutputStream()
        Age.decryptStream(ByteArrayInputStream(ct), listOf(identity), pt)
        assertArrayEquals(plaintext, pt.toByteArray())
    }

    @Test
    fun streamRoundTrip_emptyPlaintext() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)

        val ct = ByteArrayOutputStream()
        Age.encryptStream(ByteArrayInputStream(ByteArray(0)), listOf(recipient), ct)

        val pt = ByteArrayOutputStream()
        Age.decryptStream(ByteArrayInputStream(ct.toByteArray()), listOf(identity), pt)
        assertArrayEquals(ByteArray(0), pt.toByteArray())
    }

    @Test
    fun streamDecrypt_strangerCannotDecrypt() {
        val intended = X25519Identity.generate()
        val stranger = X25519Identity.generate()
        val ct = ByteArrayOutputStream()
        Age.encryptStream(
            ByteArrayInputStream("private".toByteArray()),
            listOf(X25519Recipient(intended.publicKey)),
            ct,
        )
        assertThrows(Age.NoMatchingIdentityException::class.java) {
            Age.decryptStream(ByteArrayInputStream(ct.toByteArray()), listOf(stranger), ByteArrayOutputStream())
        }
    }

    /**
     * Cross-impl: decrypt a fixture produced by the reference `age` CLI using the streaming path,
     * proving the streaming decoder is wire-compatible with upstream age. Skips if fixtures aren't
     * generated (run `bash generate-fixtures.sh` from project root).
     */
    @Test
    fun crossImpl_x25519Fixture_decryptsWithStream() {
        val fixturesDir = File("src/test/resources/fixtures")
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

        val pt = ByteArrayOutputStream()
        ctFile.inputStream().use { i -> Age.decryptStream(i, listOf(identity), pt) }
        assertArrayEquals("hello AgePony".toByteArray(), pt.toByteArray())
    }
}
