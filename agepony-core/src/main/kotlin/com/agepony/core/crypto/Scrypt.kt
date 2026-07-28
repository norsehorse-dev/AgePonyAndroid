package com.agepony.core.crypto

import org.bouncycastle.crypto.generators.SCrypt

/**
 * scrypt KDF wrapper.
 *
 * age uses scrypt for the passphrase recipient ("scrypt stanza") with:
 *   - r = 8, p = 1
 *   - N = 2^workfactor (workfactor stored in the stanza args; default 18 → N=262144)
 *   - salt = "age-encryption.org/v1/scrypt" || random_16B
 *   - dkLen = 32
 */
object Scrypt {
    /**
     * Bytes scrypt allocates for these parameters, in one block: 128 * N * r.
     *
     * At age's default work factor 18 with r=8 that is 256 MiB, whatever the size of the file
     * being encrypted. This is why a passphrase encrypt can fail on a device where a recipient
     * encrypt of the very same file succeeds.
     */
    fun memoryBytes(n: Int, r: Int): Long = 128L * n * r

    fun derive(passphrase: ByteArray, salt: ByteArray, n: Int, r: Int, p: Int, length: Int): ByteArray {
        require(n > 0 && (n and (n - 1)) == 0) { "N must be a positive power of 2" }
        return SCrypt.generate(passphrase, salt, n, r, p, length)
    }
}
