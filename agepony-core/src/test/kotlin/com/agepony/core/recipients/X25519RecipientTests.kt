package com.agepony.core.recipients

import com.agepony.core.Stanza
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class X25519RecipientTests {
    private fun randomFileKey() = ByteArray(16).also { SecureRandom().nextBytes(it) }

    @Test
    fun wrap_producesX25519Stanza() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val fileKey = randomFileKey()
        val stanza = recipient.wrap(fileKey)

        assertEquals("X25519", stanza.type)
        assertEquals(1, stanza.args.size)
        // arg[0] is the ephemeral public key base64-unpadded (32 bytes → 43 chars)
        assertEquals(43, stanza.args[0].length)
        // Body is encrypted file key (16) + tag (16) = 32 bytes
        assertEquals(32, stanza.body.size)
    }

    @Test
    fun roundTrip_wrapThenUnwrap() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val fileKey = randomFileKey()
        val stanza = recipient.wrap(fileKey)
        val unwrapped = identity.unwrap(stanza)
        assertNotNull(unwrapped)
        assertArrayEquals(fileKey, unwrapped)
    }

    @Test
    fun unwrap_returnsNullForUnrelatedIdentity() {
        val recipient = X25519Recipient(X25519Identity.generate().publicKey)
        val unrelated = X25519Identity.generate()
        val fileKey = randomFileKey()
        val stanza = recipient.wrap(fileKey)
        assertNull(unrelated.unwrap(stanza))
    }

    @Test
    fun unwrap_returnsNullForWrongStanzaType() {
        val identity = X25519Identity.generate()
        val notX25519 = Stanza("scrypt", listOf("AAA", "18"), ByteArray(32))
        assertNull(identity.unwrap(notX25519))
    }

    @Test
    fun unwrap_returnsNullForWrongEphSize() {
        val identity = X25519Identity.generate()
        val badStanza = Stanza("X25519", listOf(Stanza.base64NoPad(ByteArray(16))), ByteArray(32))
        assertNull(identity.unwrap(badStanza))
    }

    @Test
    fun unwrap_returnsNullForWrongArgCount() {
        val identity = X25519Identity.generate()
        val noArgs = Stanza("X25519", emptyList(), ByteArray(32))
        assertNull(identity.unwrap(noArgs))
    }

    @Test
    fun bech32_pubKeyRoundTrip() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val bech32 = recipient.toBech32()
        assertTrue(bech32.startsWith("age1"))
        val reparsed = X25519Recipient(bech32)
        assertArrayEquals(recipient.publicKey, reparsed.publicKey)
    }

    @Test
    fun bech32_secretKeyRoundTrip() {
        val identity = X25519Identity.generate()
        val bech32 = identity.toBech32()
        assertTrue(bech32.startsWith("AGE-SECRET-KEY-1"))
        val reparsed = X25519Identity(bech32)
        assertArrayEquals(identity.privateKey, reparsed.privateKey)
        assertArrayEquals(identity.publicKey, reparsed.publicKey)
    }

    @Test
    fun bech32_rejectsWrongHRP() {
        // Bech32 "age" pubkey decoded with secret-key constructor → error
        val recipient = X25519Recipient(X25519Identity.generate().publicKey)
        assertThrows(IllegalArgumentException::class.java) {
            X25519Identity(recipient.toBech32())
        }
    }

    @Test
    fun publicKey_derivedConsistently() {
        val priv = ByteArray(32) { it.toByte() }
        val id1 = X25519Identity(priv)
        val id2 = X25519Identity(priv)
        assertArrayEquals(id1.publicKey, id2.publicKey)
    }
}
