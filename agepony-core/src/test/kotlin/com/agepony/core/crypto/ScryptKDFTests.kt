package com.agepony.core.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ScryptKDFTests {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    /**
     * RFC 7914 §12 first vector: passphrase="", salt="", N=16, r=1, p=1, dkLen=64.
     * Fastest of the RFC vectors; runs in <100ms.
     */
    @Test
    fun rfc7914_smallVector() {
        val out = Scrypt.derive(ByteArray(0), ByteArray(0), 16, 1, 1, 64)
        val expected = "77d6576238657b203b19ca42c18a0497" +
                       "f16b4844e3074ae8dfdffa3fede21442" +
                       "fcd0069ded0948f8326a753a0fc81f17" +
                       "e8d3e0fb2e0d3628cf35e20c38d18906"
        assertEquals(expected, hex(out))
    }

    /**
     * RFC 7914 §12 second vector: passphrase="password", salt="NaCl", N=1024, r=8, p=16, dkLen=64.
     * Slower (~1-2s); kept enabled because it exercises r and p > 1.
     */
    @Test
    fun rfc7914_passwordNaCl() {
        val out = Scrypt.derive(
            "password".toByteArray(), "NaCl".toByteArray(), 1024, 8, 16, 64
        )
        val expected = "fdbabe1c9d3472007856e7190d01e9fe" +
                       "7c6ad7cbc8237830e77376634b373162" +
                       "2eaf30d92e22a3886ff109279d9830da" +
                       "c727afb94a83ee6d8360cbdfa2cc0640"
        assertEquals(expected, hex(out))
    }
}
