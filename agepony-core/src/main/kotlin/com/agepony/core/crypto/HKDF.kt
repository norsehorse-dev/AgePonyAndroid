package com.agepony.core.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

/**
 * HKDF-SHA256 wrapper.
 *
 * age uses HKDF-SHA256 for:
 *   - The header MAC key (salt=empty, info="header", ikm=fileKey, length=32)
 *   - The payload key (salt=16B-nonce, info="payload", ikm=fileKey, length=32)
 *   - X25519 stanza wrap key (salt=ephShare||recipientPub, info=label, ikm=shared, length=32)
 */
object HKDF {
    fun derive(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters(ikm, salt, info))
        val output = ByteArray(length)
        generator.generateBytes(output, 0, length)
        return output
    }
}
