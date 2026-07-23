package com.agepony.core.crypto

import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHAKEDigest

/**
 * SHA-3 / SHAKE256 wrappers used by the MLKEM768-X25519 hybrid KEM
 * (age-encryption.org/mlkem768x25519).
 *
 *   - `shake256` is the XOF used to expand the 32-byte identity seed into the
 *     ML-KEM key seed and the X25519 scalar (draft-ietf-hpke-pq DeriveKeyPair).
 *   - `sha3_256` is the hybrid KEM shared-secret combiner
 *     `SHA3-256(ss_PQ || ss_T || ct_T || ek_T || label)`.
 */
object Sha3 {
    /** Fixed-output SHA3-256. */
    fun sha3_256(data: ByteArray): ByteArray {
        val d = SHA3Digest(256)
        d.update(data, 0, data.size)
        val out = ByteArray(d.digestSize)
        d.doFinal(out, 0)
        return out
    }

    /** SHAKE256 XOF: absorb `data`, squeeze exactly `outLen` bytes. */
    fun shake256(data: ByteArray, outLen: Int): ByteArray {
        val d = SHAKEDigest(256)
        d.update(data, 0, data.size)
        val out = ByteArray(outLen)
        d.doFinal(out, 0, outLen)
        return out
    }
}
