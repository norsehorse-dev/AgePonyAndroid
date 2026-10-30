package com.agepony.app.vault

import com.agepony.core.piv.YubiKeyPinPolicy

/**
 * Store a YubiKey identity's learned PIN policy (5.1.0 item 1), in place: same id, same position,
 * the active identity unchanged. Does nothing when the policy is already stored, the identity is
 * gone, or it isn't a YubiKey. Main thread only, like every other vault change.
 *
 * Vault has no general update, so this swaps the record and lets [Vault.renameIdentity] (same
 * name) persist it. Once Vault grows `setYubiKeyPinPolicy`, this should call that instead.
 */
fun Vault.setYubiKeyPinPolicy(identityId: String, policy: YubiKeyPinPolicy) {
    val idx = identities.indexOfFirst { it.id == identityId }
    if (idx < 0) return
    val current = identities[idx]
    if (current.type != StoredIdentityType.YUBIKEY_PIV) return
    val updated = current.withYubiKeyPinPolicy(policy)
    if (updated == current) return
    identities[idx] = updated
    renameIdentity(identityId, updated.name)
}
