package com.agepony.app.vault

/** Plain default names for host tests, which have no resources. */
object TestKeyNames : DefaultKeyNames {
    override fun identity(type: StoredIdentityType): String = "unnamed ${type.name}"
    override fun sshRecipient(rsa: Boolean): String = if (rsa) "unnamed rsa" else "unnamed ed25519"
    override fun gitHubKey(user: String, number: Int): String = "$user $number"
    override fun restoredKey(number: Int): String = "restored $number"
}
