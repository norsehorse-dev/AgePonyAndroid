package com.agepony.core.recipients

import com.agepony.core.Age
import com.agepony.core.Stanza
import com.agepony.core.crypto.SHA256
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class SSHEd25519Tests {
    private fun randomFileKey() = ByteArray(16).also { SecureRandom().nextBytes(it) }

    @Test
    fun wrap_producesSSHEd25519Stanza() {
        val identity = SSHEd25519Identity.generate()
        val recipient = SSHEd25519Recipient(identity.edPublicKey)
        val stanza = recipient.wrap(randomFileKey())
        assertEquals("ssh-ed25519", stanza.type)
        assertEquals(2, stanza.args.size)
        // arg[0] = 4-byte recipient tag → base64 unpadded = 6 chars
        assertEquals(6, stanza.args[0].length)
        // arg[1] = 32-byte ephemeral pubkey → base64 unpadded = 43 chars
        assertEquals(43, stanza.args[1].length)
        // body = encrypted 16-byte file key + 16-byte tag = 32 bytes
        assertEquals(32, stanza.body.size)
    }

    @Test
    fun recipientTag_matchesSHA256OfWireBlob() {
        val identity = SSHEd25519Identity.generate()
        val recipient = SSHEd25519Recipient(identity.edPublicKey)
        val stanza = recipient.wrap(randomFileKey())

        // Reconstruct the SSH wire blob and check tag
        val expectedBlob = byteArrayOf(0, 0, 0, 11) +
            "ssh-ed25519".toByteArray() +
            byteArrayOf(0, 0, 0, 32) +
            identity.edPublicKey
        val expectedTag = SHA256.digest(expectedBlob).copyOfRange(0, 4)
        val actualTag = Stanza.base64Decode(stanza.args[0])
        assertArrayEquals(expectedTag, actualTag)
    }

    @Test
    fun roundTrip_wrapThenUnwrap() {
        val identity = SSHEd25519Identity.generate()
        val recipient = SSHEd25519Recipient(identity.edPublicKey)
        val fileKey = randomFileKey()
        val stanza = recipient.wrap(fileKey)
        val unwrapped = identity.unwrap(stanza)
        assertNotNull(unwrapped)
        assertArrayEquals(fileKey, unwrapped)
    }

    @Test
    fun unwrap_returnsNullForUnrelatedIdentity() {
        val intended = SSHEd25519Identity.generate()
        val stranger = SSHEd25519Identity.generate()
        val recipient = SSHEd25519Recipient(intended.edPublicKey)
        val stanza = recipient.wrap(randomFileKey())
        assertNull(stranger.unwrap(stanza))
    }

    @Test
    fun unwrap_returnsNullForWrongStanzaType() {
        val identity = SSHEd25519Identity.generate()
        val notSSH = Stanza("X25519", listOf("AAAA"), ByteArray(32))
        assertNull(identity.unwrap(notSSH))
    }

    @Test
    fun unwrap_returnsNullForWrongArgCount() {
        val identity = SSHEd25519Identity.generate()
        val bad = Stanza("ssh-ed25519", listOf("only-one-arg"), ByteArray(32))
        assertNull(identity.unwrap(bad))
    }

    @Test
    fun unwrap_returnsNullForWrongTagSize() {
        val identity = SSHEd25519Identity.generate()
        // Tag should be 4 bytes (6 chars base64), but here we pass 6 bytes (8 chars)
        val tag = Stanza.base64NoPad(ByteArray(6))
        val ephPub = Stanza.base64NoPad(ByteArray(32))
        val bad = Stanza("ssh-ed25519", listOf(tag, ephPub), ByteArray(32))
        assertNull(identity.unwrap(bad))
    }

    @Test
    fun unwrap_returnsNullForWrongEphSize() {
        val identity = SSHEd25519Identity.generate()
        // Build a stanza with this identity's tag but wrong ephemeral size
        val recipient = SSHEd25519Recipient(identity.edPublicKey)
        val realStanza = recipient.wrap(randomFileKey())
        val bad = Stanza(
            "ssh-ed25519",
            listOf(realStanza.args[0], Stanza.base64NoPad(ByteArray(16))),
            realStanza.body
        )
        assertNull(identity.unwrap(bad))
    }

    @Test
    fun endToEnd_throughAge() {
        val identity = SSHEd25519Identity.generate()
        val recipient = SSHEd25519Recipient(identity.edPublicKey)
        val plaintext = "secret message for ssh key".toByteArray()
        val ct = Age.encrypt(plaintext, listOf(recipient))
        val pt = Age.decrypt(ct, listOf(identity))
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun endToEnd_largePayload_throughAge() {
        val identity = SSHEd25519Identity.generate()
        val recipient = SSHEd25519Recipient(identity.edPublicKey)
        val plaintext = ByteArray(200_000).also { SecureRandom().nextBytes(it) }
        val ct = Age.encrypt(plaintext, listOf(recipient))
        val pt = Age.decrypt(ct, listOf(identity))
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun multiRecipient_mixedSSHAndX25519() {
        val sshId = SSHEd25519Identity.generate()
        val x25519Id = X25519Identity.generate()
        val recipients = listOf(
            SSHEd25519Recipient(sshId.edPublicKey),
            X25519Recipient(x25519Id.publicKey),
        )
        val plaintext = "for both key types".toByteArray()
        val ct = Age.encrypt(plaintext, recipients)
        // Either identity can decrypt
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(sshId)))
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(x25519Id)))
    }

    @Test
    fun construct_rejectsWrongPubKeySize() {
        assertThrows(IllegalArgumentException::class.java) {
            SSHEd25519Recipient(ByteArray(16))
        }
    }

    @Test
    fun construct_rejectsWrongSeedSize() {
        assertThrows(IllegalArgumentException::class.java) {
            SSHEd25519Identity(ByteArray(16))
        }
    }
}
