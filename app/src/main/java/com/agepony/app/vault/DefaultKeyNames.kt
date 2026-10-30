package com.agepony.app.vault

import android.content.Context
import com.agepony.app.R

/**
 * Names for keys that arrive without one: an import with the name left blank, a pasted or
 * fetched SSH recipient with no comment, an unnamed key in a backup or transfer. They are read
 * from resources when the key is created, so they are stored in the user's language (5.1.0, UI
 * plan U5). Keys already in the vault keep the names they were saved with.
 */
interface DefaultKeyNames {
    /** An imported identity of [type] with no name. */
    fun identity(type: StoredIdentityType): String

    /** An SSH recipient line with no comment. */
    fun sshRecipient(rsa: Boolean): String

    /** One of several keys fetched for a GitHub [user], numbered from 1. */
    fun gitHubKey(user: String, number: Int): String

    /** An unnamed key read from a backup or transfer, numbered from 1. */
    fun restoredKey(number: Int): String

    companion object {
        fun from(context: Context): DefaultKeyNames = ResourceKeyNames(context.applicationContext)
    }
}

private class ResourceKeyNames(private val context: Context) : DefaultKeyNames {
    override fun identity(type: StoredIdentityType): String = context.getString(
        when (type) {
            StoredIdentityType.X25519 -> R.string.identities_default_name_x25519
            StoredIdentityType.MLKEM768X25519 -> R.string.identities_default_name_quantum_safe
            StoredIdentityType.SSH_ED25519 -> R.string.identities_default_name_ssh
            StoredIdentityType.SSH_RSA -> R.string.identities_default_name_ssh_rsa
            StoredIdentityType.HARDWARE_KEY -> R.string.identities_default_name_hardware
            StoredIdentityType.HARDWARE_TAG, StoredIdentityType.HARDWARE_TAG_PQ ->
                R.string.identities_default_name_hardware_decrypt
            StoredIdentityType.SK_ED25519, StoredIdentityType.SK_ECDSA_P256 -> R.string.identities_default_name_security
            StoredIdentityType.YUBIKEY_PIV -> R.string.identities_default_name_yubikey_plain
        }
    )

    override fun sshRecipient(rsa: Boolean): String =
        context.getString(if (rsa) R.string.identities_default_name_ssh_rsa else R.string.identities_default_name_ssh)

    override fun gitHubKey(user: String, number: Int): String =
        context.getString(R.string.identities_default_name_github_key, user, number)

    override fun restoredKey(number: Int): String =
        context.getString(R.string.identities_default_name_restored, number)
}
