package com.agepony.app.security

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.agepony.app.R
import com.agepony.app.vault.KeystoreMasterKey
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.Signature
import java.util.concurrent.Executor
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

//
// The Android counterpart of iOS's BiometricGate.swift (LocalAuthentication
// wrapper). Wraps androidx.biometric.BiometricPrompt in a suspend API. When a
// CryptoObject is supplied, the authenticated Cipher is returned so the caller
// can wrap/unwrap the vault key — this is the cryptographic gate, not just a
// UI confirmation.
//
// Authenticators: strong biometric on all supported API levels, plus device
// credential on API 30+ (matching iOS's biometric + passcode fallback). The
// CryptoObject + DEVICE_CREDENTIAL combination is only valid on API 30+, so
// pre-30 we use BIOMETRIC_STRONG and show a Cancel button.
//
// 5.1.0 (iOS E6, M-3, L-11): the in-app prompts follow the vault's lock policy, which the
// Vault publishes through [ownerPolicy]. In Biometrics only mode they offer a strong biometric
// alone, bound to the mode's own Keystore key, so a fingerprint or face enrolled since that key
// was made can't pass them (Keystore invalidates the key on any enrolment change). A vault the
// app password alone opens reports no system prompt here, so callers ask for the password.
//

class BiometricGateException(val code: Int, message: String) : Exception(message)

object BiometricGate {

    /** AgePony's own [BiometricGateException] codes, outside BiometricPrompt's range. */
    const val CODE_NO_RESULT = -1

    /** Biometrics only: a biometric was added or removed since the mode's key was made. */
    const val CODE_ENROLMENT_CHANGED = -10

    /** Biometrics only: no strong biometric can run right now. */
    const val CODE_UNAVAILABLE = -11

    /** Which in-app prompt the vault's lock state calls for. */
    enum class OwnerPolicy {
        /** Biometric or device credential (the device credential alone below API 30 via Keyguard). */
        DEFAULT,

        /** Only the app password opens the vault, so the device credential doesn't stand in for it (L-11). */
        APP_PASSWORD_ONLY,

        /** Biometrics only (E6): a strong biometric of the enrolment the vault was locked to, or the app password. */
        BIOMETRIC_ONLY,
    }

    /** Set by the Vault on creation; DEFAULT until then and whenever no vault exists. */
    @Volatile var ownerPolicy: () -> OwnerPolicy = { OwnerPolicy.DEFAULT }

    private fun currentPolicy(): OwnerPolicy = runCatching { ownerPolicy() }.getOrDefault(OwnerPolicy.DEFAULT)

    private fun defaultAuthenticators(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        }

    /** What an in-app prompt may offer under the current policy. */
    private fun inAppAuthenticators(): Int =
        if (currentPolicy() == OwnerPolicy.BIOMETRIC_ONLY) BiometricManager.Authenticators.BIOMETRIC_STRONG
        else defaultAuthenticators()

    /**
     * True if an in-app owner check can use the system prompt right now. Follows the vault's
     * policy: false for a vault only the app password opens (L-11), and in Biometrics only
     * mode true only while a strong biometric is enrolled and the mode's key still accepts it
     * (M-3). Callers then fall back to the app password.
     */
    fun canAuthenticate(activity: FragmentActivity): Boolean = when (currentPolicy()) {
        OwnerPolicy.APP_PASSWORD_ONLY -> false
        OwnerPolicy.BIOMETRIC_ONLY -> biometricOnlyUsable(activity)
        OwnerPolicy.DEFAULT -> canAuthenticateDefault(activity)
    }

    /** True if the device can run the default biometric-or-credential prompt, whatever the vault's policy. */
    fun canAuthenticateDefault(context: Context): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(defaultAuthenticators()) == BiometricManager.BIOMETRIC_SUCCESS

    /**
     * Biometrics only: a strong biometric is enrolled and the mode's Keystore key still
     * accepts it, so an in-app prompt can count.
     */
    fun biometricOnlyUsable(context: Context): Boolean =
        hasBiometric(context) &&
            KeystoreMasterKey.biometricOnlyKeyState() == KeystoreMasterKey.BiometricOnlyKeyState.VALID

    /**
     * Show the system biometric prompt and suspend until it resolves.
     * Returns the authenticated Cipher (the one inside [cryptoObject]) on
     * success. Throws [BiometricGateException] on error or user cancellation.
     * [biometricOnly] offers a strong biometric alone, with a Cancel button and no way to the
     * device credential (E6).
     */
    suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String?,
        cryptoObject: BiometricPrompt.CryptoObject,
        deviceCredentialOnly: Boolean = false,
        biometricOnly: Boolean = false,
    ): Cipher = suspendCancellableCoroutine { cont ->
        val authenticators = when {
            deviceCredentialOnly -> BiometricManager.Authenticators.DEVICE_CREDENTIAL
            biometricOnly -> BiometricManager.Authenticators.BIOMETRIC_STRONG
            else -> defaultAuthenticators()
        }
        val executor: Executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val cipher = result.cryptoObject?.cipher
                if (!cont.isActive) return
                if (cipher != null) {
                    cont.resume(cipher)
                } else {
                    cont.resumeWithException(
                        BiometricGateException(CODE_NO_RESULT, "Authentication returned no cipher")
                    )
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (cont.isActive) {
                    cont.resumeWithException(BiometricGateException(errorCode, errString.toString()))
                }
            }
            // onAuthenticationFailed (a single non-matching attempt) leaves the
            // prompt up for a retry, so it is intentionally not handled here.
        }

        val prompt = BiometricPrompt(activity, executor, callback)
        val infoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(authenticators)
        if (subtitle != null) infoBuilder.setSubtitle(subtitle)
        if (authenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL == 0) {
            // A negative button is required when DEVICE_CREDENTIAL is not allowed.
            infoBuilder.setNegativeButtonText(activity.getString(R.string.action_cancel))
        }

        prompt.authenticate(infoBuilder.build(), cryptoObject)
    }

    /**
     * Signature variant of [authenticate]. Shows the system biometric prompt and suspends
     * until it resolves, returning the authenticated [Signature] (the one inside
     * [cryptoObject]) so the caller can `update`/`sign`. Used by hardware-backed SSHSIG
     * signing keys. Throws [BiometricGateException] on error or cancellation. In Biometrics
     * only mode the prompt offers a strong biometric alone (E6).
     */
    suspend fun authenticateSignature(
        activity: FragmentActivity,
        title: String,
        subtitle: String?,
        cryptoObject: BiometricPrompt.CryptoObject
    ): Signature = suspendCancellableCoroutine { cont ->
        val authenticators = inAppAuthenticators()
        val executor: Executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val signature = result.cryptoObject?.signature
                if (!cont.isActive) return
                if (signature != null) {
                    cont.resume(signature)
                } else {
                    cont.resumeWithException(
                        BiometricGateException(CODE_NO_RESULT, "Authentication returned no signature")
                    )
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (cont.isActive) {
                    cont.resumeWithException(BiometricGateException(errorCode, errString.toString()))
                }
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)
        val infoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(authenticators)
        if (subtitle != null) infoBuilder.setSubtitle(subtitle)
        if (authenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL == 0) {
            infoBuilder.setNegativeButtonText(activity.getString(R.string.action_cancel))
        }

        prompt.authenticate(infoBuilder.build(), cryptoObject)
    }

    /**
     * Plain confirmation prompt, used as a defense-in-depth re-auth for sensitive in-app
     * actions while the vault is already unlocked (e.g. revealing a private key), mirroring
     * iOS's reveal-time biometric. Returns true on success; throws [BiometricGateException] on
     * error/cancel.
     *
     * In Biometrics only mode it is a strong biometric alone, bound to the mode's Keystore key
     * (E6, M-3): after a biometric was added or removed it throws [CODE_ENROLMENT_CHANGED]
     * without showing a prompt, and [CODE_UNAVAILABLE] when no strong biometric can run, so
     * the caller asks for the app password instead.
     */
    suspend fun confirm(
        activity: FragmentActivity,
        title: String,
        subtitle: String?
    ): Boolean {
        if (currentPolicy() == OwnerPolicy.BIOMETRIC_ONLY) {
            confirmBiometricOnly(activity, title, subtitle)
        } else {
            confirmDefault(activity, title, subtitle)
        }
        noteOwnerConfirmed()
        return true
    }

    private suspend fun confirmDefault(
        activity: FragmentActivity,
        title: String,
        subtitle: String?
    ): Boolean = suspendCancellableCoroutine { cont ->
        val executor: Executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (cont.isActive) cont.resume(true)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (cont.isActive) {
                    cont.resumeWithException(BiometricGateException(errorCode, errString.toString()))
                }
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)
        val infoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(defaultAuthenticators())
        if (subtitle != null) infoBuilder.setSubtitle(subtitle)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            infoBuilder.setNegativeButtonText(activity.getString(R.string.action_cancel))
        }

        prompt.authenticate(infoBuilder.build())
    }

    /**
     * Biometrics only: a strong-biometric prompt with the mode's Keystore key as its
     * CryptoObject, and one operation under that key afterwards. The key only allows the
     * operation after a biometric of the enrolment it was made under, so this can't be passed
     * by a fingerprint or face added later (5.1.0, iOS M-3).
     */
    private suspend fun confirmBiometricOnly(activity: FragmentActivity, title: String, subtitle: String?) {
        if (!hasBiometric(activity)) {
            throw BiometricGateException(CODE_UNAVAILABLE, activity.getString(R.string.security_biometric_unavailable))
        }
        val cipher = try {
            KeystoreMasterKey.wrapCipherBiometricOnly()
        } catch (_: Exception) {
            // Invalidated by an enrolment change, or missing: never a pass.
            throw BiometricGateException(CODE_ENROLMENT_CHANGED, activity.getString(R.string.security_biometric_changed))
        }
        val authed = authenticate(activity, title, subtitle, BiometricPrompt.CryptoObject(cipher), biometricOnly = true)
        try {
            authed.doFinal(ByteArray(16)).fill(0)
        } catch (_: Exception) {
            throw BiometricGateException(CODE_ENROLMENT_CHANGED, activity.getString(R.string.security_biometric_changed))
        }
    }

    /**
     * True for a [BiometricGateException] code that means the biometric can't run right now
     * (changed, locked out, none enrolled, no hardware) rather than a cancel or a failure. In
     * Biometrics only mode those go to the app password.
     */
    fun isUnavailableCode(code: Int): Boolean = when (code) {
        CODE_ENROLMENT_CHANGED,
        CODE_UNAVAILABLE,
        BiometricPrompt.ERROR_LOCKOUT,
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_HW_NOT_PRESENT -> true
        else -> false
    }

    /** True for the codes a user's own cancel produces, which callers treat as no answer. */
    fun isCancelCode(code: Int): Boolean =
        code == BiometricPrompt.ERROR_USER_CANCELED || code == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
            code == BiometricPrompt.ERROR_CANCELED

    // MARK: - Owner check window (5.1.0, iOS H-1)
    //
    // Setting the first app password needs a biometric or device-credential check first.
    // Typing and confirming a password takes a while, so the time of the last successful
    // in-app check is kept. Only a time, never a key; locking the vault clears it.

    @Volatile private var lastOwnerCheckAt: Long = 0L

    /** Record a successful in-app biometric or device-credential check, now. */
    fun noteOwnerConfirmed() {
        lastOwnerCheckAt = SystemClock.elapsedRealtime().coerceAtLeast(1L)
    }

    /** Forget the last check (on lock). */
    fun forgetOwnerCheck() {
        lastOwnerCheckAt = 0L
    }

    /** Whether an in-app biometric or device-credential check succeeded within [withinMillis]. */
    fun ownerConfirmed(withinMillis: Long): Boolean =
        OwnerCheckPolicy.withinWindow(lastOwnerCheckAt, SystemClock.elapsedRealtime(), withinMillis)

    /** True if the device has a secure lock screen (PIN, pattern, or password) set. */
    fun isDeviceSecure(context: Context): Boolean =
        (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure

    /** True if a strong biometric is enrolled and usable right now. */
    fun hasBiometric(context: Context): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    /** True if the device has any biometric hardware at all (fingerprint, face or iris). */
    fun hasBiometricHardware(context: Context): Boolean {
        val pm = context.packageManager
        return pm.hasSystemFeature(FEATURE_FINGERPRINT) || pm.hasSystemFeature(FEATURE_FACE) ||
            pm.hasSystemFeature(FEATURE_IRIS)
    }

    /**
     * True when the only biometric this device has is a fingerprint reader, so the lock mode can
     * say "Fingerprint only" instead of "Biometrics only".
     */
    fun fingerprintOnlyHardware(context: Context): Boolean {
        val pm = context.packageManager
        return pm.hasSystemFeature(FEATURE_FINGERPRINT) && !pm.hasSystemFeature(FEATURE_FACE) &&
            !pm.hasSystemFeature(FEATURE_IRIS)
    }

    // PackageManager.FEATURE_FACE and FEATURE_IRIS are API 29 constants; the strings are stable.
    private const val FEATURE_FINGERPRINT = "android.hardware.fingerprint"
    private const val FEATURE_FACE = "android.hardware.biometrics.face"
    private const val FEATURE_IRIS = "android.hardware.biometrics.iris"

    /**
     * Pre-30 device-credential prompt intent (KeyguardManager). Launch it for a result;
     * RESULT_OK means the credential was confirmed. Returns null if no secure lock screen
     * is set. Deprecated on newer APIs in favor of BiometricPrompt's DEVICE_CREDENTIAL,
     * but that form needs a CryptoObject binding unavailable below API 30, so this is the
     * pre-30 path.
     */
    @Suppress("DEPRECATION")
    fun deviceCredentialIntent(context: Context, title: String, description: String?): Intent? =
        (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager)
            .createConfirmDeviceCredentialIntent(title, description)
}
