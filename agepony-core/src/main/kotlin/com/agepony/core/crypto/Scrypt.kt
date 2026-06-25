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
    fun derive(passphrase: ByteArray, salt: ByteArray, n: Int, r: Int, p: Int, length: Int): ByteArray {
        require(n > 0 && (n and (n - 1)) == 0) { "N must be a positive power of 2" }
        return SCrypt.generate(passphrase, salt, n, r, p, length)
    }
}
