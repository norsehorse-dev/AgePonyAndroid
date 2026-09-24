package com.agepony.core.signing

import com.agepony.core.Stanza
import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.HKDF
import java.security.SecureRandom

/**
 * AgePony's signature stanza, "agepony.com/sig v1".
 *
 * A signed-and-encrypted file carries its SSHSIG in an extra age header stanza rather than in a
 * wrapper around the payload (the older approach is [com.agepony.core.archive.SignedBundle]). The
 * signature is encrypted under a key derived from the file key, so:
 *
 *   - plain age ignores the unrecognized stanza and hands back the bare payload (no wrapper
 *     surprise, which is what confused a YubiKey tester on issue #10),
 *   - only a recipient who can unwrap the file key can read or verify the signature, so the
 *     signer's identity stays out of the cleartext header,
 *   - the age header MAC already covers every stanza, so the signature cannot be swapped for
 *     another without AgePony's decrypt noticing.
 *
 * The age spec requires an scrypt stanza to be the only stanza in a header, so this is used only
 * for public-key recipients. Passphrase (scrypt) files keep the [com.agepony.core.archive.SignedBundle]
 * wrapper.
 *
 * Body layout: a 12-byte random nonce, then ChaCha20-Poly1305(key, nonce) over the armored SSHSIG.
 * key = HKDF-SHA256(ikm = fileKey, salt = empty, info = "agepony.com/sig-v1", L = 32). The info
 * label is distinct from age's own "header" and "payload" labels, so this key never collides with
 * the header-MAC key or the payload-stream key.
 */
object SignatureStanza {
    const val TYPE = "agepony.com/sig"
    const val VERSION = "v1"

    private const val KEY_INFO = "agepony.com/sig-v1"
    private const val KEY_LEN = 32
    private const val NONCE_LEN = 12
    private val EMPTY_SALT = ByteArray(0)

    /** Build the stanza carrying [signatureArmored] (an armored SSHSIG), sealed under [fileKey]. */
    fun build(fileKey: ByteArray, signatureArmored: String): Stanza {
        val key = HKDF.derive(fileKey, EMPTY_SALT, KEY_INFO.toByteArray(Charsets.UTF_8), KEY_LEN)
        val nonce = ByteArray(NONCE_LEN).also { SecureRandom().nextBytes(it) }
        val sealed = ChaChaPoly.encrypt(key, nonce, signatureArmored.toByteArray(Charsets.UTF_8))
        return Stanza(TYPE, listOf(VERSION), nonce + sealed)
    }

    /** The signature stanza among [stanzas], or null if there is none. */
    fun find(stanzas: List<Stanza>): Stanza? = stanzas.firstOrNull { it.type == TYPE }

    /**
     * Recover the armored SSHSIG from [stanza] using [fileKey], or null if [stanza] is not a v1
     * signature stanza, is malformed, or does not authenticate under the derived key.
     */
    fun open(fileKey: ByteArray, stanza: Stanza): String? {
        if (stanza.type != TYPE) return null
        if (stanza.args.firstOrNull() != VERSION) return null
        if (stanza.body.size < NONCE_LEN) return null
        val nonce = stanza.body.copyOfRange(0, NONCE_LEN)
        val sealed = stanza.body.copyOfRange(NONCE_LEN, stanza.body.size)
        val key = HKDF.derive(fileKey, EMPTY_SALT, KEY_INFO.toByteArray(Charsets.UTF_8), KEY_LEN)
        return try {
            String(ChaChaPoly.decrypt(key, nonce, sealed), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }
}
