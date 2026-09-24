package com.agepony.app.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * The device-bound half of the app password KEK (audit M-2): a non-exportable HMAC-SHA256
 * key in the AndroidKeyStore. PasswordVault v2 blobs are sealed under
 * HMAC(this key, label ‖ scrypt(secret)), so a copy of vault.key.pw taken off the phone
 * can't be guessed offline; every guess has to run through this device's Keystore.
 *
 * No user-authentication requirement: this key is the password path's own binding, not a
 * biometric gate, and it must work on a phone with no screen lock at all (the
 * password-only vault exists for exactly those devices).
 *
 * StrongBox when the device has it, TEE otherwise, same fallback as KeystoreMasterKey.
 *
 * setUnlockedDeviceRequired is deliberately NOT set. Every use happens with AgePony in the
 * foreground on an unlocked phone, so it would add little, and the password blob is often
 * the only wrap of the vault key: an unlocked-device-required key has had platform bugs on
 * devices with no secure lock screen, and around adding or removing one, and losing this key
 * loses the vault. The Keystore binding plus the failed-attempt backoff is the protection.
 *
 * Deleted on reset and on the duress wipe (Vault.reset), which makes any stray old copy of
 * a password or duress blob permanently unopenable.
 */
object PasswordDeviceKey : PasswordVault.DeviceBinding {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "com.agepony.app.vault.password.bind"
    private const val MAC_ALGORITHM = "HmacSHA256"

    @Synchronized
    override fun ensureKey(): Boolean {
        if (keyStore().containsAlias(ALIAS)) return false
        generate()
        return true
    }

    @Synchronized
    override fun mac(data: ByteArray): ByteArray {
        val mac = Mac.getInstance(MAC_ALGORITHM)
        mac.init(loadKey())
        return mac.doFinal(data)
    }

    @Synchronized
    fun delete() {
        val ks = keyStore()
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun loadKey(): SecretKey {
        val entry = keyStore().getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry
            ?: throw IllegalStateException("The app password device key is missing.")
        return entry.secretKey
    }

    private fun generate() {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                kg.init(buildSpec(strongBox = true))
                kg.generateKey()
                return
            } catch (_: Exception) {
                // StrongBox unavailable on this device: generate in the TEE instead.
            }
        }
        kg.init(buildSpec(strongBox = false))
        kg.generateKey()
    }

    private fun buildSpec(strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            b.setIsStrongBoxBacked(true)
        }
        return b.build()
    }
}
