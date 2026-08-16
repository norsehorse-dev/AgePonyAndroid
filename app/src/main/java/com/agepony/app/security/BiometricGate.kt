package com.agepony.app.security

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
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

class BiometricGateException(val code: Int, message: String) : Exception(message)

object BiometricGate {

    private fun allowedAuthenticators(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        }

    /** True if the device can satisfy our auth requirements right now. */
    fun canAuthenticate(activity: FragmentActivity): Boolean =
        BiometricManager.from(activity)
            .canAuthenticate(allowedAuthenticators()) == BiometricManager.BIOMETRIC_SUCCESS

    /**
     * Show the system biometric prompt and suspend until it resolves.
     * Returns the authenticated Cipher (the one inside [cryptoObject]) on
     * success. Throws [BiometricGateException] on error or user cancellation.
     */
    suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String?,
        cryptoObject: BiometricPrompt.CryptoObject,
        deviceCredentialOnly: Boolean = false,
    ): Cipher = suspendCancellableCoroutine { cont ->
        val authenticators =
            if (deviceCredentialOnly) BiometricManager.Authenticators.DEVICE_CREDENTIAL
            else allowedAuthenticators()
        val executor: Executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val cipher = result.cryptoObject?.cipher
                if (!cont.isActive) return
                if (cipher != null) {
                    cont.resume(cipher)
                } else {
                    cont.resumeWithException(
                        BiometricGateException(-1, "Authentication returned no cipher")
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
            infoBuilder.setNegativeButtonText("Cancel")
        }

        prompt.authenticate(infoBuilder.build(), cryptoObject)
    }

    /**
     * Signature variant of [authenticate]. Shows the system biometric prompt and suspends
     * until it resolves, returning the authenticated [Signature] (the one inside
     * [cryptoObject]) so the caller can `update`/`sign`. Used by hardware-backed SSHSIG
     * signing keys. Throws [BiometricGateException] on error or cancellation.
     */
    suspend fun authenticateSignature(
        activity: FragmentActivity,
        title: String,
        subtitle: String?,
        cryptoObject: BiometricPrompt.CryptoObject
    ): Signature = suspendCancellableCoroutine { cont ->
        val executor: Executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val signature = result.cryptoObject?.signature
                if (!cont.isActive) return
                if (signature != null) {
                    cont.resume(signature)
                } else {
                    cont.resumeWithException(
                        BiometricGateException(-1, "Authentication returned no signature")
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
            .setAllowedAuthenticators(allowedAuthenticators())
        if (subtitle != null) infoBuilder.setSubtitle(subtitle)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            infoBuilder.setNegativeButtonText("Cancel")
        }

        prompt.authenticate(infoBuilder.build(), cryptoObject)
    }

    /**
     * Plain confirmation prompt with no CryptoObject — used as a defense-in-depth
     * re-auth for sensitive in-app actions while the vault is already unlocked
     * (e.g. revealing a private key), mirroring iOS's reveal-time biometric.
     * Returns true on success; throws [BiometricGateException] on error/cancel.
     */
    suspend fun confirm(
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
            .setAllowedAuthenticators(allowedAuthenticators())
        if (subtitle != null) infoBuilder.setSubtitle(subtitle)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            infoBuilder.setNegativeButtonText("Cancel")
        }

        prompt.authenticate(infoBuilder.build())
    }

    /** True if the device has a secure lock screen (PIN, pattern, or password) set. */
    fun isDeviceSecure(context: Context): Boolean =
        (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure

    /** True if a strong biometric is enrolled and usable right now. */
    fun hasBiometric(context: Context): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

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
