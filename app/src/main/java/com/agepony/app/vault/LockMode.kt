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
 */
enum class LockMode(val key: String) {
    OFF("off"),
    DEVICE_CREDENTIAL("device_credential"),
    BIOMETRIC("biometric");

    companion object {
        /** Parse a stored key; unknown values fall back to the safest gate. */
        fun fromKey(key: String): LockMode = entries.firstOrNull { it.key == key } ?: BIOMETRIC
    }
}
