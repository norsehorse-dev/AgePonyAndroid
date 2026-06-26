package com.agepony.app.security.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.agepony.app.security.BiometricGate
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.b64e
import com.agepony.core.signing.SSHSig
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Hardware-backed SSHSIG signing keys in the AndroidKeyStore. The private key is a
 * non-exportable EC P-256 key; only the public wire is ever surfaced. Signing produces a
 * detached SSHSIG over the AgePony signed-data via a Keystore `Signature`
 * (`SHA256withECDSA`), then hands the DER to [KeystoreEcdsa] for `ecdsa-sha2-nistp256`
 * assembly.
 *
 * Auth is decided per key at creation. A key generated with `requireAuth = true` is gated
 * behind biometric / device-credential and must sign through [signAuthenticated]; a key
 * generated with `requireAuth = false` signs headless through [sign]. [sign] inspects the
 * key's [KeyInfo] and refuses if the key actually requires auth, so the wrong path fails
 * clearly rather than at the opaque Keystore layer.
 */
object HardwareKeyService {
    class HardwareKeyException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val ALIAS_PREFIX = "com.agepony.app.signing.ec."
    private const val SIGN_ALGO = "SHA256withECDSA"
    private const val CURVE = "secp256r1"

    /** Result of generating a key: its alias, public wire, auth policy, and backing. */
    data class Generated(
        val alias: String,
        val publicWire: ByteArray,
        val requireAuth: Boolean,
        val strongBox: Boolean,
    )

    fun newAlias(): String = ALIAS_PREFIX + UUID.randomUUID().toString()

    fun exists(alias: String): Boolean = keystore().containsAlias(alias)

    fun delete(alias: String) {
        val ks = keystore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    /**
     * Generate a non-exportable EC P-256 signing key. StrongBox when the device supports
     * it, TEE otherwise. [requireAuth] fixes the key's auth policy for its lifetime.
     */
    fun generate(alias: String, requireAuth: Boolean): Generated {
        delete(alias)
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        var strongBox = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                kpg.initialize(buildSpec(alias, requireAuth, strongBox = true))
                kpg.generateKeyPair()
                strongBox = true
            } catch (_: Exception) {
                // StrongBox unavailable on this device — regenerate in the TEE.
            }
        }
        if (!strongBox) {
            kpg.initialize(buildSpec(alias, requireAuth, strongBox = false))
            kpg.generateKeyPair()
        }
        return Generated(alias, KeystoreEcdsa.publicWire(loadPublicKey(alias)), requireAuth, strongBox)
    }

    /** The `ecdsa-sha2-nistp256` SSHSIG public wire for an existing key. */
    fun publicWire(alias: String): ByteArray = KeystoreEcdsa.publicWire(loadPublicKey(alias))

    /** Whether the key was generated requiring user authentication to sign. */
    fun isUserAuthRequired(alias: String): Boolean = keyInfo(alias).isUserAuthenticationRequired

    /** Best-effort: whether the private key lives in secure hardware (TEE/StrongBox). */
    @Suppress("DEPRECATION")
    fun isHardwareBacked(alias: String): Boolean = keyInfo(alias).isInsideSecureHardware

    /**
     * Sign [message] without an auth prompt. Throws if the key requires auth (use
     * [signAuthenticated] for those). Returns the armored SSHSIG.
     */
    fun sign(
        alias: String,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
    ): String {
        if (isUserAuthRequired(alias)) throw HardwareKeyException(
            "key '$alias' requires user authentication; call signAuthenticated"
        )
        val sig = Signature.getInstance(SIGN_ALGO).apply { initSign(privateEntry(alias).privateKey) }
        sig.update(KeystoreEcdsa.signedData(message, namespace))
        val der = try {
            sig.sign()
        } catch (e: Exception) {
            throw HardwareKeyException("hardware signing failed for '$alias'", e)
        }
        return KeystoreEcdsa.assemble(loadPublicKey(alias), der, message, namespace)
    }

    /**
     * Sign [message] behind a biometric / device-credential prompt, for auth-gated keys.
     * Suspends until the prompt resolves. Returns the armored SSHSIG.
     */
    suspend fun signAuthenticated(
        activity: FragmentActivity,
        alias: String,
        message: ByteArray,
        title: String,
        subtitle: String? = null,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
    ): String {
        val sig = Signature.getInstance(SIGN_ALGO).apply { initSign(privateEntry(alias).privateKey) }
        val authed = BiometricGate.authenticateSignature(
            activity, title, subtitle, BiometricPrompt.CryptoObject(sig)
        )
        authed.update(KeystoreEcdsa.signedData(message, namespace))
        val der = try {
            authed.sign()
        } catch (e: Exception) {
            throw HardwareKeyException("hardware signing failed for '$alias'", e)
        }
        return KeystoreEcdsa.assemble(loadPublicKey(alias), der, message, namespace)
    }

    /** Build a vault [StoredIdentity] for a freshly generated hardware key. */
    fun toStoredIdentity(name: String, generated: Generated, comment: String? = null): StoredIdentity =
        StoredIdentity(
            id = UUID.randomUUID().toString(),
            name = name,
            type = StoredIdentityType.HARDWARE_KEY,
            publicKeyB64 = b64e(generated.publicWire),
            privateKeyB64 = "",
            sshComment = comment,
            keystoreAlias = generated.alias,
            createdAt = System.currentTimeMillis(),
        )

    // --- internals ---

    private fun buildSpec(alias: String, requireAuth: Boolean, strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (requireAuth) {
            b.setUserAuthenticationRequired(true)
            b.setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                b.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
            }
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            b.setIsStrongBoxBacked(true)
        }
        return b.build()
    }

    private fun keystore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun privateEntry(alias: String): KeyStore.PrivateKeyEntry =
        keystore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw HardwareKeyException("no private key for alias '$alias'")

    private fun loadPublicKey(alias: String): ECPublicKey {
        val cert = keystore().getCertificate(alias)
            ?: throw HardwareKeyException("no certificate for alias '$alias'")
        return cert.publicKey as? ECPublicKey
            ?: throw HardwareKeyException("key '$alias' is not EC")
    }

    private fun keyInfo(alias: String): KeyInfo {
        val priv = privateEntry(alias).privateKey
        val factory = KeyFactory.getInstance(priv.algorithm, ANDROID_KEYSTORE)
        return factory.getKeySpec(priv, KeyInfo::class.java) as KeyInfo
    }
}
