package com.agepony.app.vault

import android.util.Base64
import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.AgeRecipient
import com.agepony.core.recipients.SSHEd25519Identity
import com.agepony.core.recipients.SSHEd25519Recipient
import com.agepony.core.recipients.SSHRSARecipient
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.ssh.OpenSSHPublicKey
import java.io.ByteArrayOutputStream

//
// Hydration helpers: turn persisted records back into agepony-core types and
// render display strings. Android counterpart of iOS's StoredIdentity /
// StoredRecipient hydration.
//
// Android storage shapes (differ from iOS, chosen to match the Android core
// constructors directly):
//   x25519        identity: priv = 32-byte scalar;  pub = 32-byte X25519 pub
//   ssh-ed25519   identity: priv = 32-byte seed;    pub = 32-byte ed25519 pub
//   ssh-ed25519   recipient:                         pub = 32-byte ed25519 pub
//   ssh-rsa       recipient:                         pub = UTF-8 bytes of the
//                                                     `ssh-rsa BASE64 [comment]` line
// ssh-rsa *identity* import is deferred (the core exposes RSA params but no
// PEM re-serializer; needs a param blob — landing in a later sub-phase).
//

internal fun b64d(s: String): ByteArray = Base64.decode(s, Base64.NO_WRAP)
internal fun b64e(b: ByteArray): String = Base64.encodeToString(b, Base64.NO_WRAP)

private const val RSA_IDENTITY_PENDING =
    "SSH RSA private-key import lands in a later sub-phase"

/** Build a one-line `ssh-ed25519 BASE64 [comment]` string from the raw 32-byte key. */
internal fun sshEd25519Line(edPublicKey: ByteArray, comment: String?): String {
    val out = ByteArrayOutputStream()
    fun sshString(b: ByteArray) {
        val n = b.size
        out.write((n ushr 24) and 0xFF)
        out.write((n ushr 16) and 0xFF)
        out.write((n ushr 8) and 0xFF)
        out.write(n and 0xFF)
        out.write(b)
    }
    sshString("ssh-ed25519".toByteArray(Charsets.US_ASCII))
    sshString(edPublicKey)
    val b64 = Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
    val c = comment?.trim().orEmpty()
    return if (c.isEmpty()) "ssh-ed25519 $b64" else "ssh-ed25519 $b64 $c"
}

// MARK: - Identity

fun StoredIdentity.toAgeIdentity(): AgeIdentity = when (type) {
    StoredIdentityType.X25519 -> X25519Identity(b64d(privateKeyB64))
    StoredIdentityType.SSH_ED25519 -> SSHEd25519Identity(b64d(privateKeyB64))
    StoredIdentityType.SSH_RSA -> throw NotImplementedError(RSA_IDENTITY_PENDING)
}

fun StoredIdentity.toAgeRecipient(): AgeRecipient = when (type) {
    StoredIdentityType.X25519 -> X25519Recipient(b64d(publicKeyB64))
    StoredIdentityType.SSH_ED25519 -> SSHEd25519Recipient(b64d(publicKeyB64))
    StoredIdentityType.SSH_RSA -> throw NotImplementedError(RSA_IDENTITY_PENDING)
}

fun StoredIdentity.publicDisplayString(): String = when (type) {
    StoredIdentityType.X25519 -> X25519Recipient(b64d(publicKeyB64)).toBech32()
    StoredIdentityType.SSH_ED25519 -> sshEd25519Line(b64d(publicKeyB64), sshComment)
    StoredIdentityType.SSH_RSA -> "(SSH RSA)"
}

fun StoredIdentity.privateDisplayString(): String = when (type) {
    StoredIdentityType.X25519 -> X25519Identity(b64d(privateKeyB64)).toBech32()
    StoredIdentityType.SSH_ED25519 ->
        "(SSH Ed25519 — private key stored in the vault; not exportable as text)"
    StoredIdentityType.SSH_RSA -> "(SSH RSA)"
}

// MARK: - Recipient

fun StoredRecipient.toAgeRecipient(): AgeRecipient = when (type) {
    StoredRecipientType.X25519 -> X25519Recipient(b64d(publicKeyB64))
    StoredRecipientType.SSH_ED25519 -> SSHEd25519Recipient(b64d(publicKeyB64))
    StoredRecipientType.SSH_RSA -> {
        val line = String(b64d(publicKeyB64), Charsets.UTF_8)
        when (val parsed = OpenSSHPublicKey.parse(line)) {
            is OpenSSHPublicKey.RSA -> SSHRSARecipient(parsed)
            else -> throw IllegalStateException("stored ssh-rsa recipient did not parse as RSA")
        }
    }
}

fun StoredRecipient.publicDisplayString(): String = when (type) {
    StoredRecipientType.X25519 -> X25519Recipient(b64d(publicKeyB64)).toBech32()
    StoredRecipientType.SSH_ED25519 -> sshEd25519Line(b64d(publicKeyB64), sshComment)
    StoredRecipientType.SSH_RSA -> String(b64d(publicKeyB64), Charsets.UTF_8)
}
