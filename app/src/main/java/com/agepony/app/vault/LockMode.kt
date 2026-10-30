package com.agepony.app.vault

/**
 * How the Keystore/OS gate protects the vault (4.1.0), replacing the pre-4.1.0
 * `biometricEnabled` boolean. The app-owned password/PIN (PasswordVault) is a second
 * way in next to the mode's own gate, not an extra step. Two exceptions (5.0.1 audit):
 * with [OFF] the password is the only way in, and with a duress secret set the vault is
 * PIN-only and is kept at [OFF].
 *
 *  - [OFF]: no OS gate. Without a password the vault opens with no prompt via the
 *    non-auth "plain" KEK; this is the only mode the silent auto-unlock path runs
 *    from. With a password there is no plain blob at all and only the password opens
 *    the vault (audit H-4).
 *  - [DEVICE_CREDENTIAL]: the phone's PIN / pattern / password is required at every
 *    unlock. On API 30+ this is a hardware-bound gate on the auth KEK
 *    (BiometricPrompt, DEVICE_CREDENTIAL only). Below API 30 the Cipher-bound
 *    CryptoObject form of device credential does not exist, so it is a
 *    KeyguardManager confirm in front of the non-auth KEK: a real per-unlock OS
 *    check, but not hardware-bound crypto.
 *  - [BIOMETRIC]: biometric with device-credential fallback (API 30+), or biometric
 *    alone (pre-30). Hardware-bound gate on the auth KEK.
 *  - [BIOMETRIC_ONLY] (5.1.0, iOS E6 "Face ID only"): a strong biometric and nothing else.
 *    The vault key sits under its own Keystore key that accepts BIOMETRIC_STRONG only and is
 *    invalidated when a biometric is added or removed. The device credential never opens the
 *    vault in this mode. The app password is the way back in, so the mode needs one, and it
 *    can't be chosen while a duress secret is set.
 */
enum class LockMode(val key: String) {
    OFF("off"),
    DEVICE_CREDENTIAL("device_credential"),
    BIOMETRIC("biometric"),
    BIOMETRIC_ONLY("biometric_only");

    /** True for the mode that needs an app password as its way back in (iOS E6). */
    val needsAppPassword: Boolean get() = this == BIOMETRIC_ONLY

    /** Why a switch to a lock mode is refused before anything is touched. */
    enum class Refusal { DURESS_SET, NEEDS_APP_PASSWORD, NO_STRONG_BIOMETRIC }

    companion object {
        /**
         * Parse a stored key; unknown values fall back to the safest gate that still opens a
         * vault written by any version, [BIOMETRIC]. Never [BIOMETRIC_ONLY]: a value this
         * build doesn't know must not turn the device credential off.
         */
        fun fromKey(key: String): LockMode = entries.firstOrNull { it.key == key } ?: BIOMETRIC

        /**
         * Whether switching to [target] is refused, and why. A duress secret keeps the vault
         * PIN-only (audit H-1), Biometrics only needs an app password as the way back in and a
         * strong biometric enrolled now.
         */
        fun refusalFor(
            target: LockMode,
            duressSet: Boolean,
            hasAppPassword: Boolean,
            strongBiometricEnrolled: Boolean,
        ): Refusal? = when {
            duressSet -> Refusal.DURESS_SET
            target == BIOMETRIC_ONLY && !hasAppPassword -> Refusal.NEEDS_APP_PASSWORD
            target == BIOMETRIC_ONLY && !strongBiometricEnrolled -> Refusal.NO_STRONG_BIOMETRIC
            else -> null
        }

        /**
         * Whether Lock settings lists Biometrics only: a strong biometric is enrolled and no
         * duress secret is set, or it is the current mode (so the user can see and leave it).
         */
        fun biometricOnlyListed(current: LockMode, duressSet: Boolean, strongBiometricEnrolled: Boolean): Boolean =
            current == BIOMETRIC_ONLY || (!duressSet && strongBiometricEnrolled)
    }
}
