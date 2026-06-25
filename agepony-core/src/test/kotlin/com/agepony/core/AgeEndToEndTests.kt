package com.agepony.core

import com.agepony.core.recipients.ScryptIdentity
import com.agepony.core.recipients.ScryptRecipient
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class AgeEndToEndTests {
    @Test
    fun roundTrip_singleX25519Recipient() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val plaintext = "hello AgePony Android".toByteArray()
        val ct = Age.encrypt(plaintext, listOf(recipient))
        val pt = Age.decrypt(ct, listOf(identity))
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun roundTrip_emptyPlaintext_X25519() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val ct = Age.encrypt(ByteArray(0), listOf(recipient))
        val pt = Age.decrypt(ct, listOf(identity))
        assertArrayEquals(ByteArray(0), pt)
    }

    @Test
    fun roundTrip_largePlaintext_X25519() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val plaintext = ByteArray(200_000).also { SecureRandom().nextBytes(it) }
        val ct = Age.encrypt(plaintext, listOf(recipient))
        val pt = Age.decrypt(ct, listOf(identity))
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun multiRecipient_anyIdentityCanDecrypt() {
        val alice = X25519Identity.generate()
        val bob = X25519Identity.generate()
        val carol = X25519Identity.generate()
        val recipients = listOf(
            X25519Recipient(alice.publicKey),
            X25519Recipient(bob.publicKey),
            X25519Recipient(carol.publicKey),
        )
        val plaintext = "message for three".toByteArray()
        val ct = Age.encrypt(plaintext, recipients)
        // Each identity should independently decrypt
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(alice)))
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(bob)))
        assertArrayEquals(plaintext, Age.decrypt(ct, listOf(carol)))
    }

    @Test
    fun multiRecipient_strangerCannotDecrypt() {
        val intended = X25519Identity.generate()
        val stranger = X25519Identity.generate()
        val ct = Age.encrypt(
            "private".toByteArray(),
            listOf(X25519Recipient(intended.publicKey))
        )
        assertThrows(Age.NoMatchingIdentityException::class.java) {
            Age.decrypt(ct, listOf(stranger))
        }
    }

    @Test
    fun roundTrip_scryptPassphrase() {
        val passphrase = "correct horse battery staple"
        val recipient = ScryptRecipient(passphrase, workFactor = 10)
        val identity = ScryptIdentity(passphrase)
        val plaintext = "secret diary entry".toByteArray()
        val ct = Age.encrypt(plaintext, listOf(recipient))
        val pt = Age.decrypt(ct, listOf(identity))
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun roundTrip_scryptWrongPassphrase() {
        val recipient = ScryptRecipient("correct", workFactor = 10)
        val identity = ScryptIdentity("incorrect")
        val ct = Age.encrypt("data".toByteArray(), listOf(recipient))
        assertThrows(Age.NoMatchingIdentityException::class.java) {
            Age.decrypt(ct, listOf(identity))
        }
    }

    @Test
    fun mixedMode_scryptPlusX25519_rejectedAtEncrypt() {
        val identity = X25519Identity.generate()
        val recipients = listOf(
            X25519Recipient(identity.publicKey),
            ScryptRecipient("pass", workFactor = 10),
        )
        assertThrows(IllegalArgumentException::class.java) {
            Age.encrypt("data".toByteArray(), recipients)
        }
    }

    @Test
    fun roundTrip_throughArmor() {
        val identity = X25519Identity.generate()
        val recipient = X25519Recipient(identity.publicKey)
        val plaintext = "armored payload".toByteArray()
        val ct = Age.encrypt(plaintext, listOf(recipient))
        val armored = Armor.encode(ct)
        val decoded = Armor.decode(armored)
        val pt = Age.decrypt(decoded, listOf(identity))
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun encrypt_requiresAtLeastOneRecipient() {
        assertThrows(IllegalArgumentException::class.java) {
            Age.encrypt("data".toByteArray(), emptyList())
        }
    }

    @Test
    fun decrypt_requiresAtLeastOneIdentity() {
        val recipient = X25519Recipient(X25519Identity.generate().publicKey)
        val ct = Age.encrypt("data".toByteArray(), listOf(recipient))
        assertThrows(IllegalArgumentException::class.java) {
            Age.decrypt(ct, emptyList())
        }
    }
}
