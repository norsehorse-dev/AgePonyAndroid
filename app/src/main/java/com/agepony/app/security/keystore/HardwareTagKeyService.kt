package com.agepony.app.security.keystore

import android.os.Build
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.annotation.RequiresApi
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.b64e
import com.agepony.core.crypto.MLKEM768
import com.agepony.core.crypto.P256Curve
import com.agepony.core.crypto.P256KeyAgreement
import com.agepony.core.recipients.TagIdentity
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.KeyAgreement

/**
 * Hardware-bound age decryption keys: a non-exportable P-256 key in the Android Keystore with
 * PURPOSE_AGREE_KEY, exposed as an age `age1tag1...` recipient (or `age1tagpq1...` with a
 * software ML-KEM-768 half). Decryption is a Keystore ECDH; the private key never leaves the
 * TEE or StrongBox.
 *
 * Requires API 31 (Keystore key agreement). Older devices can still encrypt *to* tag
 * recipients; they just cannot hold one.
 *
 * Auth: a key made with requireAuth needs biometric or device credential within
 * [AUTH_WINDOW_SECONDS] before each ECDH. The prompt comes from [HardwareAuthBroker] when the
 * Keystore reports the user isn't authenticated, so every decrypt path gets it without changes.
 * Biometric re-enrollment does not invalidate these keys (it would destroy access to every file
 * encrypted to them), but removing the device screen lock does: that is Android's rule for
 * auth-bound keys, and the UI says so before the user opts in.
 */
object HardwareTagKeyService {
    class HardwareTagException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val ALIAS_PREFIX = "com.agepony.app.decrypt.p256."
    private const val CURVE = "secp256r1"
    const val AUTH_WINDOW_SECONDS = 30

    val isSupported: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    data class Generated(
        val alias: String,
        /** 65-byte uncompressed SEC1 public point. */
        val publicUncompressed: ByteArray,
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
     * Generate a non-exportable P-256 key-agreement key. StrongBox when the device has one and
     * it can actually do ECDH (probed once with a throwaway key), the TEE otherwise.
     */
    @RequiresApi(Build.VERSION_CODES.S)
    fun generate(alias: String, requireAuth: Boolean): Generated {
        delete(alias)
        val useStrongBox = strongBoxCanAgree()
        if (useStrongBox) {
            try {
                return generateIn(alias, requireAuth, strongBox = true)
            } catch (_: Exception) {
                delete(alias)
            }
        }
        return generateIn(alias, requireAuth, strongBox = false)
    }

    @RequiresApi(Build.VERSION_CODES.S)
    private fun generateIn(alias: String, requireAuth: Boolean, strongBox: Boolean): Generated {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        kpg.initialize(buildSpec(alias, requireAuth, strongBox))
        kpg.generateKeyPair()
        return Generated(alias, publicUncompressed(alias), requireAuth, strongBox)
    }

    @Volatile private var strongBoxProbe: Boolean? = null

    /** Some StrongBox chips generate agreement keys but fail the ECDH itself. Probe once. */
    @RequiresApi(Build.VERSION_CODES.S)
    private fun strongBoxCanAgree(): Boolean {
        strongBoxProbe?.let { return it }
        val probeAlias = ALIAS_PREFIX + "probe." + UUID.randomUUID()
        val ok = try {
            generateIn(probeAlias, requireAuth = false, strongBox = true)
            val peer = P256Curve.randomPublicUncompressed()
            keyAgreement(probeAlias).sharedX(peer).size == 32
        } catch (_: Throwable) {
            false
        } finally {
            runCatching { delete(probeAlias) }
        }
        strongBoxProbe = ok
        return ok
    }

    /** The key's public point, 65-byte uncompressed. */
    fun publicUncompressed(alias: String): ByteArray {
        val pub = keystore().getCertificate(alias)?.publicKey as? ECPublicKey
            ?: throw HardwareTagException("no EC public key for '$alias'")
        val x = fixed32(pub.w.affineX)
        val y = fixed32(pub.w.affineY)
        return byteArrayOf(0x04) + x + y
    }

    fun isUserAuthRequired(alias: String): Boolean = keyInfo(alias).isUserAuthenticationRequired

    @Suppress("DEPRECATION")
    fun isInsideSecureHardware(alias: String): Boolean = keyInfo(alias).isInsideSecureHardware

    fun isStrongBox(alias: String): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            keyInfo(alias).securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX

    /**
     * ECDH through the Keystore. Blocks for a user prompt via [HardwareAuthBroker] when the key
     * needs authentication, so it must never run on the main thread.
     */
    fun keyAgreement(alias: String): P256KeyAgreement = P256KeyAgreement { peerUncompressed ->
        check(Looper.myLooper() != Looper.getMainLooper()) { "hardware ECDH must run off the main thread" }
        try {
            ecdh(alias, peerUncompressed)
        } catch (e: UserNotAuthenticatedException) {
            HardwareAuthBroker.awaitAuthentication(
                title = "Decrypt with your hardware key",
                subtitle = "Confirm it's you to use this key",
            )
            ecdh(alias, peerUncompressed)
        }
    }

    private fun ecdh(alias: String, peerUncompressed: ByteArray): ByteArray {
        val priv = privateKey(alias)
        val ka = KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE)
        ka.init(priv)
        ka.doPhase(peerPublicKey(alias, peerUncompressed), true)
        val secret = ka.generateSecret()
        if (secret.size != 32) throw HardwareTagException("unexpected ECDH output size ${secret.size}")
        return secret
    }

    private fun peerPublicKey(alias: String, uncompressed: ByteArray): java.security.PublicKey {
        val (x, y) = P256Curve.affineXY(uncompressed)
        val params = (keystore().getCertificate(alias).publicKey as ECPublicKey).params
        val spec = ECPublicKeySpec(ECPoint(x, y), params)
        return KeyFactory.getInstance("EC").generatePublic(spec)
    }

    // ---- vault records ----

    /** A classic `age1tag1` identity. Public key stored compressed (the recipient bytes). */
    fun toStoredClassic(name: String, g: Generated): StoredIdentity = StoredIdentity(
        id = UUID.randomUUID().toString(),
        name = name,
        type = StoredIdentityType.HARDWARE_TAG,
        publicKeyB64 = b64e(P256Curve.toCompressed(g.publicUncompressed)),
        privateKeyB64 = "",
        keystoreAlias = g.alias,
        createdAt = System.currentTimeMillis(),
    )

    /**
     * A hybrid `age1tagpq1` identity: the P-256 half in the Keystore, the ML-KEM-768 half as a
     * 64-byte seed in the (encrypted) vault. Public key stored as the 1249-byte recipient.
     */
    fun toStoredHybrid(name: String, g: Generated): StoredIdentity {
        val seed = ByteArray(MLKEM768.SEED_SIZE).also { SecureRandom().nextBytes(it) }
        val mlkem = MLKEM768.keyPairFromSeed(seed)
        return StoredIdentity(
            id = UUID.randomUUID().toString(),
            name = name,
            type = StoredIdentityType.HARDWARE_TAG_PQ,
            publicKeyB64 = b64e(mlkem.encapsulationKey + g.publicUncompressed),
            privateKeyB64 = b64e(seed),
            keystoreAlias = g.alias,
            createdAt = System.currentTimeMillis(),
        )
    }

    /** Hydrate a stored hardware tag identity into an age identity backed by the Keystore. */
    fun toTagIdentity(stored: StoredIdentity): TagIdentity {
        val alias = stored.keystoreAlias ?: throw HardwareTagException("hardware identity has no keystore alias")
        val pub = java.util.Base64.getDecoder().decode(stored.publicKeyB64)
        return when (stored.type) {
            StoredIdentityType.HARDWARE_TAG -> TagIdentity.classic(pub, keyAgreement(alias))
            StoredIdentityType.HARDWARE_TAG_PQ -> TagIdentity.hybrid(
                mlkemSeed = java.util.Base64.getDecoder().decode(stored.privateKeyB64),
                p256Public = pub.copyOfRange(MLKEM768.ENCAPS_KEY_SIZE, pub.size),
                p256 = keyAgreement(alias),
            )
            else -> throw HardwareTagException("not a hardware tag identity")
        }
    }

    // ---- internals ----

    @RequiresApi(Build.VERSION_CODES.S)
    private fun buildSpec(alias: String, requireAuth: Boolean, strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE))
        if (requireAuth) {
            b.setUserAuthenticationRequired(true)
            b.setInvalidatedByBiometricEnrollment(false)
            b.setUserAuthenticationParameters(
                AUTH_WINDOW_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        }
        if (strongBox) b.setIsStrongBoxBacked(true)
        return b.build()
    }

    private fun keystore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun privateKey(alias: String): PrivateKey =
        (keystore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.privateKey
            ?: throw HardwareTagException("This hardware key is gone from the device keystore.")

    private fun keyInfo(alias: String): KeyInfo {
        val priv = privateKey(alias)
        return KeyFactory.getInstance(priv.algorithm, ANDROID_KEYSTORE).getKeySpec(priv, KeyInfo::class.java)
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == 32 -> b
            b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
            else -> ByteArray(32 - b.size) + b
        }
    }
}
