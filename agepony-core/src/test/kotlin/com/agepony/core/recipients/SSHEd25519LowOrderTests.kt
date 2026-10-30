package com.agepony.core.recipients

import com.agepony.core.Stanza
import com.agepony.core.ssh.Ed25519Conversion
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * ssh-ed25519 keys of small order are refused (5.1.0, iOS M-1). Android already refuses them;
 * these are the same three keys the iOS tests use, so both cores pin the behavior.
 */
class SSHEd25519LowOrderTests {
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    /** y = p - 1: `EC FF..FF 7F`. */
    private val yPMinusOne = ByteArray(32) { 0xFF.toByte() }.also { it[0] = 0xEC.toByte(); it[31] = 0x7F }

    /** 32 zero bytes. */
    private val zero = ByteArray(32)

    /** A point of order 8. */
    private val order8 = hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")

    private val smallOrder = listOf(yPMinusOne, zero, order8)

    @Test
    fun smallOrderKeysAreRefusedAsRecipients() {
        for (key in smallOrder) {
            assertThrows(IllegalArgumentException::class.java) { Ed25519Conversion.publicKeyToX25519(key) }
            assertThrows(IllegalArgumentException::class.java) { SSHEd25519Recipient(key) }
            // Whatever the constructor does, nothing can be encrypted to it.
            assertThrows(IllegalArgumentException::class.java) { SSHEd25519Recipient(key).wrap(ByteArray(16)) }
        }
    }

    @Test
    fun aLowOrderEphemeralShareOpensNothing() {
        val identity = SSHEd25519Identity.generate()
        val good = SSHEd25519Recipient(identity.edPublicKey).wrap(ByteArray(16) { 1 })
        // Same tag, ephemeral share swapped for the all-zero point.
        val forged = Stanza(good.type, listOf(good.args[0], Stanza.base64NoPad(ByteArray(32))), good.body)
        assertNull(identity.unwrap(forged))
    }
}
