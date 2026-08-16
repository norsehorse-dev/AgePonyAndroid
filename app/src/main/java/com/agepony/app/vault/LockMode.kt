package com.agepony.app.vault

/**
 * How the Keystore/OS gate protects the vault (4.1.0), replacing the pre-4.1.0
 * `biometricEnabled` boolean. Orthogonal to the app-owned password/PIN
 * (PasswordVault): when a password is set it is its own gate, whatever this mode is.
 *
 *  - [OFF]: no OS gate. The vault opens with no prompt via the non-auth "plain"
 *    KEK. This is the only mode the silent auto-unlock path runs from. If an app
 *    password is set, that password is the real gate; with neither, the app opens
 *    unprotected.
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
