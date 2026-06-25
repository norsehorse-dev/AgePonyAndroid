package com.agepony.core.recipients

import com.agepony.core.Age
import com.agepony.core.Stanza
import com.agepony.core.crypto.SHA256
import com.agepony.core.ssh.SSHMPInt
import com.agepony.core.ssh.SSHWire
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom

class SSHRSATests {
    private fun randomFileKey() = ByteArray(16).also { SecureRandom().nextBytes(it) }

    companion object {
        /**
         * Lazy shared RSA-2048 keypair — generating RSA keys takes a few hundred ms
         * each, so we reuse one across tests in this class.
         */
        private val sharedKey: RSAPrivateCrtKeyParameters by lazy {
            val gen = RSAKeyPairGenerator()
            gen.init(RSAKeyGenerationParameters(
                BigInteger.valueOf(65537), SecureRandom(), 2048, 80
            ))
            gen.generateKeyPair().private as RSAPrivateCrtKeyParameters
        }
    }

    private fun makeRecipientAndIdentity(): Pair<SSHRSARecipient, SSHRSAIdentity> {
        val priv = sharedKey
        val recipient = SSHRSARecipient(priv.modulus, priv.publicExponent)
        val identity = SSHRSAIdentity(
            priv.modulus, priv.publicExponent, priv.exponent,
            priv.p, priv.q, priv.qInv
        )
        return recipient to identity
    }

    @Test
    fun wrap_producesSSHRSAStanza() {
        val (recipient, _) = makeRecipientAndIdentity()
        val stanza = recipient.wrap(randomFileKey())
        assertEquals("ssh-rsa", stanza.type)
        // ssh-rsa has ONE arg (the recipient tag), not two
        assertEquals(1, stanza.args.size)
        // 4-byte tag → 6 chars base64 unpadded
        assertEquals(6, stanza.args[0].length)
        // Body is RSA-OAEP ciphertext = modulus byte length = 256 for RSA-2048
        assertEquals(256, stanza.body.size)
    }

    @Test
    fun recipientTag_matchesSHA256OfWireBlob() {
        val (recipient, _) = makeRecipientAndIdentity()
        val priv = sharedKey
        val stanza = recipient.wrap(randomFileKey())

        // Reconstruct the SSH wire blob: <len><"ssh-rsa"><mpint e><mpint n>
        val expectedBlob = ByteArrayOutputStream().apply {
            SSHWire.writeString(this, "ssh-rsa".toByteArray())
            SSHMPInt.write(this, priv.publicExponent)
            SSHMPInt.write(this, priv.modulus)
        }.toByteArray()
        val expectedTag = SHA256.digest(expectedBlob).copyOfRange(0, 4)
        val actualTag = Stanza.base64Decode(stanza.args[0])
        assertArrayEquals(expectedTag, actualTag)
    }

    @Test
    fun roundTrip_wrapThenUnwrap() {
        val (recipient, identity) = makeRecipientAndIdentity()
        val fileKey = randomFileKey()
        val stanza = recipient.wrap(fileKey)
        val unwrapped = identity.unwrap(stanza)
        assertNotNull(unwrapped)
        assertArrayEquals(fileKey, unwrapped)
    }

    @Test
    fun unwrap_returnsNullForUnrelatedIdentity() {
        val (recipient, _) = makeRecipientAndIdentity()
        // Generate a different keypair for the "unrelated" identity
        val gen = RSAKeyPairGenerator()
        gen.init(RSAKeyGenerationParameters(
            BigInteger.valueOf(65537), SecureRandom(), 2048, 80
        ))
        val otherPriv = gen.generateKeyPair().private as RSAPrivateCrtKeyParameters
        val unrelated = SSHRSAIdentity(
            otherPriv.modulus, otherPriv.publicExponent, otherPriv.exponent,
            otherPriv.p, otherPriv.q, otherPriv.qInv
        )

        val stanza = recipient.wrap(randomFileKey())
        assertNull(unrelated.unwrap(stanza))
    }

    @Test
    fun unwrap_returnsNullForWrongStanzaType() {
        val (_, identity) = makeRecipientAndIdentity()
        val notRSA = Stanza("X25519", listOf("AAAA"), ByteArray(32))
        assertNull(identity.unwrap(notRSA))
    }

    @Test
    fun unwrap_returnsNullForWrongArgCount() {
        val (_, identity) = makeRecipientAndIdentity()
        // ssh-rsa expects 1 arg; we give 2
        val bad = Stanza("ssh-rsa", listOf("tagAA1", "extra"), ByteArray(256))
        assertNull(identity.unwrap(bad))
    }

    @Test
    fun unwrap_returnsNullForWrongTagSize() {
        val (_, identity) = makeRecipientAndIdentity()
        // Tag should be 4 bytes (6 chars base64), we pass 8 bytes (~11 chars)
        val tag = Stanza.base64NoPad(ByteArray(8))
        val bad = Stanza("ssh-rsa", listOf(tag), ByteArray(256))
        assertNull(identity.unwrap(bad))
    }

    @Test
    fun endToEnd_throughAge() {
        val (recipient, identity) = makeRecipientAndIdentity()
        val plaintext = "secret for RSA key".toByteArray()
        val ct = Age.encrypt(plaintext, listOf(recipient))
        val pt = Age.decrypt(ct, listOf(identity))
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun endToEnd_largePayload_throughAge() {
        val (recipient, identity) = makeRecipientAndIdentity()
        val plaintext = ByteArray(150_000).also { SecureRandom().nextBytes(it) }
        val ct = Age.encrypt(plaintext, listOf(recipient))
        val pt = Age.decrypt(ct, listOf(identity))
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun multiRecipient_mixedRSAAndEd25519AndX25519() {
        val (rsaRecipient, rsaIdentity) = makeRecipientAndIdentity()
        val edIdentity = SSHEd25519Identity.generate()
        val xIdentity = X25519Identity.generate()
        val recipients = listOf(
            rsaRecipient,
            SSHEd25519Recipient(edIdentity.edPublicKey),
            X25519Recipient(xIdentity.publicKey),
        )
        val plaintext = "for three key types".toByteArray()
        val ct = Age.encrypt(plaintext, recipients)
        // Each identity independently unlocks the file
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(rsaIdentity)))
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(edIdentity)))
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(xIdentity)))
    }

    @Test
    fun construct_rejectsNonPositiveModulus() {
        assertThrows(IllegalArgumentException::class.java) {
            SSHRSARecipient(BigInteger.ZERO, BigInteger.valueOf(65537))
        }
    }

    @Test
    fun construct_rejectsNonPositiveExponent() {
        assertThrows(IllegalArgumentException::class.java) {
            SSHRSARecipient(BigInteger.valueOf(100), BigInteger.ZERO)
        }
    }
}
