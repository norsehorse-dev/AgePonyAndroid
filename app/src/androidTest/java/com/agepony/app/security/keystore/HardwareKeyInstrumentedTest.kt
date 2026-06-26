package com.agepony.app.security.keystore

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.publicDisplayString
import com.agepony.app.vault.toAgeIdentity
import com.agepony.app.vault.toAgeRecipient
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigVerifier
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device validation of [HardwareKeyService] against a real AndroidKeyStore. Covers the
 * no-auth signing path end to end; the biometric-gated path needs a human at the prompt
 * and is verified manually on a device with an enrolled credential.
 */
@RunWith(AndroidJUnit4::class)
class HardwareKeyInstrumentedTest {

    private val alias = HardwareKeyService.ALIAS_PREFIX + "instrumented-test"

    @After
    fun cleanup() {
        HardwareKeyService.delete(alias)
    }

    @Test
    fun generateSignVerify_noAuth() {
        val gen = HardwareKeyService.generate(alias, requireAuth = false)
        assertEquals(SSHSig.KEY_ECDSA_P256, SSHSig.readLeadingString(gen.publicWire))
        assertFalse(HardwareKeyService.isUserAuthRequired(alias))

        val msg = "device signing test".toByteArray()
        val armored = HardwareKeyService.sign(alias, msg)
        assertTrue(SSHSigVerifier.isValid(armored.toByteArray(), msg))
        assertFalse(SSHSigVerifier.isValid(armored.toByteArray(), "tampered".toByteArray()))
    }

    @Test
    fun publicWireStableAcrossReload() {
        val gen = HardwareKeyService.generate(alias, requireAuth = false)
        assertTrue(gen.publicWire.contentEquals(HardwareKeyService.publicWire(alias)))
    }

    @Test
    fun hardwareIdentityIsSigningOnlyInHydration() {
        val gen = HardwareKeyService.generate(alias, requireAuth = false)
        val identity = HardwareKeyService.toStoredIdentity("Test HW", gen)
        assertEquals(StoredIdentityType.HARDWARE_KEY, identity.type)
        assertEquals(alias, identity.keystoreAlias)
        assertThrows(IllegalStateException::class.java) { identity.toAgeRecipient() }
        assertThrows(IllegalStateException::class.java) { identity.toAgeIdentity() }
        assertTrue(identity.publicDisplayString().startsWith("ecdsa-sha2-nistp256 "))
    }
}
