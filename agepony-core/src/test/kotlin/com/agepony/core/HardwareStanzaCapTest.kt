package com.agepony.core

import com.agepony.core.recipients.HardwareIdentity
import com.agepony.core.recipients.X25519Identity
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * Bounds on hardware identities while finding the file key (5.1.0, L-7) and the order of
 * on-device and external keys (5.1.0, M-4). Mirrors iOS HardwareStanzaCapTests.
 */
class HardwareStanzaCapTest {
    private class MockHardware(
        private val stanzaType: String,
        private val external: Boolean = false,
        private val error: Exception? = null,
        private val fileKey: ByteArray? = null,
    ) : HardwareIdentity {
        var unwrapCalls = 0
        override fun matches(stanza: Stanza): Boolean = stanza.type == stanzaType
        override fun unwrap(stanza: Stanza): ByteArray? {
            if (!matches(stanza)) return null
            unwrapCalls++
            error?.let { throw it }
            return fileKey
        }
        override val isExternalDevice: Boolean get() = external
    }

    private fun stanzas(type: String, n: Int) = List(n) { Stanza(type, listOf("t$it"), ByteArray(32)) }

    @Test
    fun aHundredMatchingStanzasCostAtMostFourCalls() {
        val hw = MockHardware("mock-hw")
        assertThrows<Age.NoMatchingIdentityException> { Age.unwrapFileKey(stanzas("mock-hw", 100), listOf(hw)) }
        assertEquals(Age.MAX_STANZAS_PER_HARDWARE_IDENTITY, hw.unwrapCalls)
        assertEquals(4, Age.MAX_STANZAS_PER_HARDWARE_IDENTITY)
    }

    @Test
    fun aKeyThatThrowsIsNotAskedAgain() {
        val boom = IllegalStateException("key gone")
        val hw = MockHardware("mock-hw", error = boom)
        val thrown = assertThrows<IllegalStateException> { Age.unwrapFileKey(stanzas("mock-hw", 10), listOf(hw)) }
        assertSame(boom, thrown)
        assertEquals(1, hw.unwrapCalls)
    }

    @Test
    fun aDeadDeviceKeyLeavesTheYubiKeyOnOffer() {
        val fileKey = ByteArray(16) { 7 }
        val dead = MockHardware("keystore", error = IllegalStateException("invalidated"))
        val yubiKey = MockHardware("yubikey", external = true, fileKey = fileKey)
        val header = stanzas("yubikey", 1) + stanzas("keystore", 1)
        assertArrayEquals(fileKey, Age.unwrapFileKey(header, listOf(yubiKey, dead)))
        assertEquals(1, dead.unwrapCalls)
        assertEquals(1, yubiKey.unwrapCalls)
    }

    @Test
    fun aWorkingDeviceKeyNeverAsksForTheTap() {
        val fileKey = ByteArray(16) { 9 }
        val keystore = MockHardware("keystore", fileKey = fileKey)
        val yubiKey = MockHardware("yubikey", external = true, fileKey = ByteArray(16))
        // The YubiKey's stanza comes first in the header; the device key still goes first.
        val header = stanzas("yubikey", 1) + stanzas("keystore", 1)
        assertArrayEquals(fileKey, Age.unwrapFileKey(header, listOf(yubiKey, keystore)))
        assertEquals(0, yubiKey.unwrapCalls)
    }

    @Test
    fun softwareKeysStillGoFirst() {
        val x = X25519Identity.generate()
        val pt = "software first".toByteArray()
        val ct = Age.encrypt(pt, listOf(com.agepony.core.recipients.X25519Recipient(x.publicKey)))
        val hw = MockHardware("X25519", external = true, fileKey = ByteArray(16))
        assertArrayEquals(pt, Age.decrypt(ct, listOf(hw, x)))
        assertEquals(0, hw.unwrapCalls)
    }
}
