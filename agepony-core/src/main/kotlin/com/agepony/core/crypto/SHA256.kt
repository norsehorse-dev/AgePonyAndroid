package com.agepony.core.crypto

import org.bouncycastle.crypto.digests.SHA256Digest

/**
 * SHA-256 wrapper. Used by the ssh-ed25519 recipient to compute the 4-byte recipient
 * tag (first 4 bytes of SHA-256 over the SSH wire blob).
 */
object SHA256 {
    fun digest(data: ByteArray): ByteArray {
        val md = SHA256Digest()
        md.update(data, 0, data.size)
        val out = ByteArray(md.digestSize)
        md.doFinal(out, 0)
        return out
    }
}
