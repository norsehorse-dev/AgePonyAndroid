package com.agepony.core.recipients

import com.agepony.core.Stanza
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class ScryptRecipientTests {
    private fun randomFileKey() = ByteArray(16).also { SecureRandom().nextBytes(it) }

    @Test
    fun wrap_producesScryptStanza() {
        val recipient = ScryptRecipient("passphrase", workFactor = 10)
        val fileKey = randomFileKey()
        val stanza = recipient.wrap(fileKey)
        assertEquals("scrypt", stanza.type)
        assertEquals(2, stanza.args.size)
        // args[0] is base64-unpadded 16-byte salt = 22 chars
        assertEquals(22, stanza.args[0].length)
        // args[1] is decimal workfactor
        assertEquals("10", stanza.args[1])
        // body = encrypted file key (16) + tag (16)
        assertEquals(32, stanza.body.size)
    }

    @Test
    fun roundTrip_correctPassphrase() {
        val passphrase = "correct horse battery staple"
        val recipient = ScryptRecipient(passphrase, workFactor = 10)
        val identity = ScryptIdentity(passphrase)
        val fileKey = randomFileKey()
        val stanza = recipient.wrap(fileKey)
        val unwrapped = identity.unwrap(stanza)
        assertNotNull(unwrapped)
        assertArrayEquals(fileKey, unwrapped)
    }

    @Test
    fun unwrap_returnsNullForWrongPassphrase() {
        val recipient = ScryptRecipient("correct", workFactor = 10)
        val identity = ScryptIdentity("incorrect")
        val stanza = recipient.wrap(randomFileKey())
        assertNull(identity.unwrap(stanza))
    }

    @Test
    fun unwrap_returnsNullForWrongStanzaType() {
        val identity = ScryptIdentity("anything")
        val notScrypt = Stanza("X25519", listOf("ZGVm"), ByteArray(32))
        assertNull(identity.unwrap(notScrypt))
    }

    @Test
    fun unwrap_returnsNullForWorkfactorOverCap() {
        val identity = ScryptIdentity("p", maxWorkFactor = 18)
        val badStanza = Stanza(
            "scrypt",
            listOf(Stanza.base64NoPad(ByteArray(16)), "25"),
            ByteArray(32)
        )
        assertNull(identity.unwrap(badStanza))
    }

    @Test
    fun unwrap_returnsNullForWorkfactorLeadingZero() {
        val identity = ScryptIdentity("p")
        val badStanza = Stanza(
            "scrypt",
            listOf(Stanza.base64NoPad(ByteArray(16)), "018"),
            ByteArray(32)
        )
        assertNull(identity.unwrap(badStanza))
    }

    @Test
    fun unwrap_returnsNullForWorkfactorWithSign() {
        val identity = ScryptIdentity("p")
        val badStanza = Stanza(
            "scrypt",
            listOf(Stanza.base64NoPad(ByteArray(16)), "+10"),
            ByteArray(32)
        )
        assertNull(identity.unwrap(badStanza))
    }

    @Test
    fun unwrap_returnsNullForNonNumericWorkfactor() {
        val identity = ScryptIdentity("p")
        val badStanza = Stanza(
            "scrypt",
            listOf(Stanza.base64NoPad(ByteArray(16)), "ten"),
            ByteArray(32)
        )
        assertNull(identity.unwrap(badStanza))
    }

    @Test
    fun unwrap_returnsNullForWrongSaltSize() {
        val identity = ScryptIdentity("p")
        val badStanza = Stanza(
            "scrypt",
            listOf(Stanza.base64NoPad(ByteArray(8)), "10"),
            ByteArray(32)
        )
        assertNull(identity.unwrap(badStanza))
    }

    @Test
    fun unwrap_returnsNullForWrongArgCount() {
        val identity = ScryptIdentity("p")
        val tooFew = Stanza("scrypt", listOf(Stanza.base64NoPad(ByteArray(16))), ByteArray(32))
        assertNull(identity.unwrap(tooFew))
    }

    @Test
    fun construct_rejectsOutOfRangeWorkfactor() {
        assertThrows(IllegalArgumentException::class.java) {
            ScryptRecipient("p", workFactor = 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ScryptRecipient("p", workFactor = 31)
        }
    }
}
