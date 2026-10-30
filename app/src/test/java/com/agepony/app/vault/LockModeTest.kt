package com.agepony.app.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 5.1.0, iOS E6: the Biometrics only lock mode's stored value and its gates. */
class LockModeTest {

    @Test
    fun storedValuesAreStable() {
        // These strings are on users' phones; changing one changes how a vault opens.
        assertEquals("off", LockMode.OFF.key)
        assertEquals("device_credential", LockMode.DEVICE_CREDENTIAL.key)
        assertEquals("biometric", LockMode.BIOMETRIC.key)
        assertEquals("biometric_only", LockMode.BIOMETRIC_ONLY.key)
    }

    @Test
    fun everyModeRoundTripsThroughItsKey() {
        for (mode in LockMode.entries) assertEquals(mode, LockMode.fromKey(mode.key))
    }

    @Test
    fun unknownValueReadsAsBiometricNeverBiometricOnly() {
        assertEquals(LockMode.BIOMETRIC, LockMode.fromKey("faceIdOnly"))
        assertEquals(LockMode.BIOMETRIC, LockMode.fromKey(""))
        assertEquals(LockMode.BIOMETRIC, LockMode.fromKey("BIOMETRIC_ONLY"))
    }

    @Test
    fun onlyBiometricOnlyNeedsAnAppPassword() {
        assertTrue(LockMode.BIOMETRIC_ONLY.needsAppPassword)
        assertFalse(LockMode.BIOMETRIC.needsAppPassword)
        assertFalse(LockMode.DEVICE_CREDENTIAL.needsAppPassword)
        assertFalse(LockMode.OFF.needsAppPassword)
    }

    @Test
    fun biometricOnlyRefusedWithDuressWithoutPasswordOrWithoutBiometric() {
        assertEquals(
            LockMode.Refusal.DURESS_SET,
            LockMode.refusalFor(LockMode.BIOMETRIC_ONLY, duressSet = true, hasAppPassword = true, strongBiometricEnrolled = true),
        )
        assertEquals(
            LockMode.Refusal.NEEDS_APP_PASSWORD,
            LockMode.refusalFor(LockMode.BIOMETRIC_ONLY, duressSet = false, hasAppPassword = false, strongBiometricEnrolled = true),
        )
        assertEquals(
            LockMode.Refusal.NO_STRONG_BIOMETRIC,
            LockMode.refusalFor(LockMode.BIOMETRIC_ONLY, duressSet = false, hasAppPassword = true, strongBiometricEnrolled = false),
        )
        assertNull(LockMode.refusalFor(LockMode.BIOMETRIC_ONLY, duressSet = false, hasAppPassword = true, strongBiometricEnrolled = true))
    }

    @Test
    fun duressRefusesEveryModeOthersNeedNoPassword() {
        for (mode in LockMode.entries) {
            assertEquals(LockMode.Refusal.DURESS_SET, LockMode.refusalFor(mode, true, true, true))
        }
        for (mode in listOf(LockMode.OFF, LockMode.DEVICE_CREDENTIAL, LockMode.BIOMETRIC)) {
            assertNull(LockMode.refusalFor(mode, duressSet = false, hasAppPassword = false, strongBiometricEnrolled = false))
        }
    }

    @Test
    fun biometricOnlyListedOnlyWithBiometricAndNoDuressUnlessCurrent() {
        assertTrue(LockMode.biometricOnlyListed(LockMode.BIOMETRIC, duressSet = false, strongBiometricEnrolled = true))
        assertFalse(LockMode.biometricOnlyListed(LockMode.BIOMETRIC, duressSet = true, strongBiometricEnrolled = true))
        assertFalse(LockMode.biometricOnlyListed(LockMode.OFF, duressSet = false, strongBiometricEnrolled = false))
        // The current mode stays visible so it can be seen and left.
        assertTrue(LockMode.biometricOnlyListed(LockMode.BIOMETRIC_ONLY, duressSet = false, strongBiometricEnrolled = false))
    }
}
