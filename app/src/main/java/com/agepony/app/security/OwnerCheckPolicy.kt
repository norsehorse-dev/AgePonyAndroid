package com.agepony.app.security

/**
 * The decisions behind AgePony's in-app owner checks, kept free of Android types so host tests
 * can pin them (5.1.0, the iOS 5.1.1 follow-ups H-1, L-11, M-3 and E6).
 */
object OwnerCheckPolicy {

    /** How long a successful biometric or device-credential check lets a first password be set. */
    const val FIRST_PASSWORD_WINDOW_MILLIS = 3L * 60L * 1000L

    /** Which check an owner confirmation runs. */
    enum class Route {
        /** The app password or PIN, through the failed-attempt counter. */
        APP_PASSWORD,

        /** Biometrics only mode: a strong biometric bound to the mode's Keystore key. */
        BIOMETRIC_ONLY,

        /** The system prompt: biometric, or the device credential on API 30+. */
        SYSTEM_PROMPT,

        /** Below API 30 with a screen lock and no strong biometric: the Keyguard credential screen. */
        DEVICE_CREDENTIAL_SCREEN,

        /** Nothing can confirm it right now on a device that has a screen lock: not a pass (H-1). */
        REFUSE,

        /** No screen lock and no app password: there is nothing to check. */
        PASS,
    }

    /**
     * Pick the check. In order:
     *  - the app password when the caller requires it, or when it is the only way into the
     *    vault: the device credential doesn't open such a vault, so it doesn't stand in for the
     *    password here either (audit L-15, iOS L-11);
     *  - Biometrics only mode: the bound biometric while it still counts, otherwise the app
     *    password (after an enrolment change, a lockout, or with nothing enrolled), never the
     *    device credential (E6, M-3);
     *  - the system prompt when it can run;
     *  - the app password when one is set;
     *  - the Keyguard credential screen below API 30;
     *  - with a screen lock but no way to run any of these, refuse rather than pass (H-1);
     *  - with no screen lock and no password there is nothing to check.
     */
    fun route(
        hasAppPassword: Boolean,
        requireAppPassword: Boolean,
        passwordIsOnlyUnlock: Boolean,
        biometricOnlyMode: Boolean,
        biometricOnlyUsable: Boolean,
        systemPromptAvailable: Boolean,
        deviceSecure: Boolean,
        legacyCredentialScreen: Boolean,
    ): Route = when {
        hasAppPassword && (requireAppPassword || passwordIsOnlyUnlock) -> Route.APP_PASSWORD
        biometricOnlyMode && biometricOnlyUsable -> Route.BIOMETRIC_ONLY
        biometricOnlyMode && hasAppPassword -> Route.APP_PASSWORD
        biometricOnlyMode -> Route.REFUSE
        systemPromptAvailable -> Route.SYSTEM_PROMPT
        hasAppPassword -> Route.APP_PASSWORD
        deviceSecure && legacyCredentialScreen -> Route.DEVICE_CREDENTIAL_SCREEN
        deviceSecure -> Route.REFUSE
        else -> Route.PASS
    }

    /**
     * Whether a first app password may be written (iOS H-1). The first password is a new way
     * into the vault, and every owner check after it trusts the password, so outside vault
     * creation it needs a biometric or device-credential check in the last few minutes. A device
     * with no screen lock has nothing to check. Replacing an existing password isn't covered
     * here: that already went through an owner check that asks for the current one.
     */
    fun firstPasswordAllowed(
        hasAppPassword: Boolean,
        vaultExists: Boolean,
        createdThisRun: Boolean,
        deviceSecure: Boolean,
        ownerConfirmedRecently: Boolean,
    ): Boolean = hasAppPassword || !vaultExists || createdThisRun || !deviceSecure || ownerConfirmedRecently

    /** Whether a check recorded at [at] (0 = none) is within [window] of [now], on one monotonic clock. */
    fun withinWindow(at: Long, now: Long, window: Long): Boolean =
        at > 0L && now >= at && now - at <= window
}
