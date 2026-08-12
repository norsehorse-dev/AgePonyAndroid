package com.agepony.core.ssh

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Tests for parsing and serializing the OpenSSH allowed_signers format and the
 * principal+key matching used by the trusted-signers store. Ported from iOS
 * `AllowedSignersTests.swift`; the cases must stay in step so both platforms
 * pin the same parsing behavior.
 */
class AllowedSignersTests {

    private val edKeyB64 =
        "AAAAC3NzaC1lZDI1NTE5AAAAILr/NVvNaGxfkVp8Ni/Z3ubM8/k89JoVOg8oMJeid1tU"

    @Test
    fun parseSimpleLine() {
        val line = "alice@example.com ssh-ed25519 $edKeyB64"
        val signers = AllowedSigners.parse(line)
        assertEquals(1, signers.size)
        assertEquals(listOf("alice@example.com"), signers[0].principals)
        assertNull(signers[0].options)
        assertEquals("ssh-ed25519", signers[0].keyType)
        assertEquals(edKeyB64, signers[0].keyBase64)
        assertNull(signers[0].comment)
    }

    @Test
    fun parseMultiplePrincipals() {
        val line = "alice@example.com,bob@example.com ssh-ed25519 $edKeyB64 team key"
        val s = AllowedSigners.parse(line)[0]
        assertEquals(listOf("alice@example.com", "bob@example.com"), s.principals)
        assertEquals("team key", s.comment)
    }

    @Test
    fun parseWithOptions() {
        val line = "alice@example.com namespaces=\"agepony\" ssh-ed25519 $edKeyB64"
        val s = AllowedSigners.parse(line)[0]
        assertEquals("namespaces=\"agepony\"", s.options)
        assertEquals("ssh-ed25519", s.keyType)
        assertEquals(edKeyB64, s.keyBase64)
    }

    @Test
    fun skipsCommentsAndBlanks() {
        val text = """
            # this is a comment

            alice@example.com ssh-ed25519 $edKeyB64
            # another comment
        """.trimIndent()
        assertEquals(1, AllowedSigners.parse(text).size)
    }

    @Test
    fun skipsUnparseableLines() {
        val text = """
            garbage line with no key
            alice@example.com ssh-ed25519 $edKeyB64
            bob ecdsa-sha2-nistp256 not-valid-base64-!!!
        """.trimIndent()
        val signers = AllowedSigners.parse(text)
        assertEquals(1, signers.size)
        assertEquals(listOf("alice@example.com"), signers[0].principals)
    }

    @Test
    fun serializeRoundTrip() {
        val original = AllowedSigner(
            principals = listOf("alice@example.com", "bob@example.com"),
            options = "namespaces=\"agepony\"",
            keyType = "ssh-ed25519",
            keyBase64 = edKeyB64,
            comment = "shared key",
        )
        val text = AllowedSigners.serialize(listOf(original))
        val parsed = AllowedSigners.parse(text)
        assertEquals(1, parsed.size)
        assertEquals(original, parsed[0])
    }

    @Test
    fun matches() {
        val s = AllowedSigners.parse("alice@example.com ssh-ed25519 $edKeyB64")[0]
        val wire = Base64.getDecoder().decode(edKeyB64)
        assertTrue(s.matches("alice@example.com", wire))
        assertFalse(s.matches("eve@example.com", wire))
        assertFalse(s.matches("alice@example.com", byteArrayOf(0x00)))
    }

    @Test
    fun publicKeyWireDecodes() {
        val s = AllowedSigners.parse("alice@example.com ssh-ed25519 $edKeyB64")[0]
        assertArrayEquals(Base64.getDecoder().decode(edKeyB64), s.publicKeyWire)
    }

    @Test
    fun makeSignerFromPubLine() {
        val pubLine = "ssh-ed25519 $edKeyB64 agepony-test@norsehor.se"
        val signer = AllowedSigners.makeSigner(
            principals = listOf("alice@example.com"),
            sshPublicKeyLine = pubLine,
            namespaceRestricted = true,
        )
        assertNotNull(signer)
        assertEquals("ssh-ed25519", signer?.keyType)
        assertEquals(edKeyB64, signer?.keyBase64)
        assertEquals("agepony-test@norsehor.se", signer?.comment)
        assertEquals("namespaces=\"agepony\"", signer?.options)
    }

    @Test
    fun makeSignerRejectsBadLine() {
        assertNull(
            AllowedSigners.makeSigner(
                principals = listOf("x"),
                sshPublicKeyLine = "not-a-key",
            )
        )
    }
}
