package com.agepony.app.security

import com.agepony.app.security.OwnerCheckPolicy.Route
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 5.1.0: in-app owner checks (iOS H-1, L-11, M-3, E6). */
class OwnerCheckPolicyTest {

    private fun route(
        hasAppPassword: Boolean = false,
        requireAppPassword: Boolean = false,
        passwordIsOnlyUnlock: Boolean = false,
        biometricOnlyMode: Boolean = false,
        biometricOnlyUsable: Boolean = false,
        systemPromptAvailable: Boolean = false,
        deviceSecure: Boolean = false,
        legacyCredentialScreen: Boolean = false,
    ) = OwnerCheckPolicy.route(
        hasAppPassword, requireAppPassword, passwordIsOnlyUnlock, biometricOnlyMode,
        biometricOnlyUsable, systemPromptAvailable, deviceSecure, legacyCredentialScreen,
    )

    @Test
    fun passwordOnlyVaultAsksForThePasswordNotTheDeviceCredential() {
        // L-11: the device credential doesn't open the vault, so it doesn't stand in for the password.
        assertEquals(
            Route.APP_PASSWORD,
            route(hasAppPassword = true, passwordIsOnlyUnlock = true, systemPromptAvailable = true, deviceSecure = true),
        )
    }

    @Test
    fun requireAppPasswordWinsWheneverOneIsSet() {
        assertEquals(Route.APP_PASSWORD, route(hasAppPassword = true, requireAppPassword = true, systemPromptAvailable = true))
        assertEquals(
            Route.APP_PASSWORD,
            route(hasAppPassword = true, requireAppPassword = true, biometricOnlyMode = true, biometricOnlyUsable = true),
        )
    }

    @Test
    fun biometricOnlyUsesTheBoundBiometricWhileItCounts() {
        assertEquals(
            Route.BIOMETRIC_ONLY,
            route(hasAppPassword = true, biometricOnlyMode = true, biometricOnlyUsable = true, systemPromptAvailable = true, deviceSecure = true),
        )
    }

    @Test
    fun biometricOnlyAfterEnrolmentChangeAsksForThePasswordNeverTheScreenLock() {
        // M-3: a changed enrolment (or a lockout, or nothing enrolled) makes the bound key unusable.
        assertEquals(
            Route.APP_PASSWORD,
            route(hasAppPassword = true, biometricOnlyMode = true, biometricOnlyUsable = false, systemPromptAvailable = true, deviceSecure = true),
        )
        assertEquals(
            Route.REFUSE,
            route(hasAppPassword = false, biometricOnlyMode = true, biometricOnlyUsable = false, systemPromptAvailable = true, deviceSecure = true),
        )
    }

    @Test
    fun defaultUsesTheSystemPromptThenThePassword() {
        assertEquals(Route.SYSTEM_PROMPT, route(hasAppPassword = true, systemPromptAvailable = true, deviceSecure = true))
        assertEquals(Route.APP_PASSWORD, route(hasAppPassword = true, systemPromptAvailable = false, deviceSecure = true))
    }

    @Test
    fun screenLockWithNoWayToCheckIsRefusedNotPassed() {
        // H-1: only a phone with no screen lock has nothing to check.
        assertEquals(Route.REFUSE, route(deviceSecure = true))
        assertEquals(Route.DEVICE_CREDENTIAL_SCREEN, route(deviceSecure = true, legacyCredentialScreen = true))
        assertEquals(Route.PASS, route(deviceSecure = false))
    }

    @Test
    fun firstPasswordNeedsARecentCheckOutsideVaultCreation() {
        // H-1: an existing vault, a screen lock, no password yet, no recent check.
        assertFalse(OwnerCheckPolicy.firstPasswordAllowed(false, vaultExists = true, createdThisRun = false, deviceSecure = true, ownerConfirmedRecently = false))
        assertTrue(OwnerCheckPolicy.firstPasswordAllowed(false, vaultExists = true, createdThisRun = false, deviceSecure = true, ownerConfirmedRecently = true))
        // Creating a vault, or a phone with nothing to check.
        assertTrue(OwnerCheckPolicy.firstPasswordAllowed(false, vaultExists = false, createdThisRun = false, deviceSecure = true, ownerConfirmedRecently = false))
        assertTrue(OwnerCheckPolicy.firstPasswordAllowed(false, vaultExists = true, createdThisRun = true, deviceSecure = true, ownerConfirmedRecently = false))
        assertTrue(OwnerCheckPolicy.firstPasswordAllowed(false, vaultExists = true, createdThisRun = false, deviceSecure = false, ownerConfirmedRecently = false))
        // Replacing a password is not this check's business.
        assertTrue(OwnerCheckPolicy.firstPasswordAllowed(true, vaultExists = true, createdThisRun = false, deviceSecure = true, ownerConfirmedRecently = false))
    }

    @Test
    fun ownerCheckWindow() {
        val window = OwnerCheckPolicy.FIRST_PASSWORD_WINDOW_MILLIS
        assertFalse(OwnerCheckPolicy.withinWindow(0L, 10_000L, window)) // never checked
        assertTrue(OwnerCheckPolicy.withinWindow(1_000L, 1_000L + window, window))
        assertFalse(OwnerCheckPolicy.withinWindow(1_000L, 1_001L + window, window))
        assertFalse(OwnerCheckPolicy.withinWindow(5_000L, 4_000L, window)) // clock went backwards
    }
}
