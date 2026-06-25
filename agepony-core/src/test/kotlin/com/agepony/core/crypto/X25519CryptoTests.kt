package com.agepony.core.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class X25519CryptoTests {
    private fun fromHex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun generatePrivateKey_returns32Bytes() {
        val priv = X25519Crypto.generatePrivateKey()
        assertEquals(32, priv.size)
    }

    @Test
    fun generatePrivateKey_isRandom() {
        val a = X25519Crypto.generatePrivateKey()
        val b = X25519Crypto.generatePrivateKey()
        // Astronomically unlikely to be equal
        assertNotEquals(a.toList(), b.toList())
    }

    @Test
    fun publicKey_returns32Bytes() {
        val priv = X25519Crypto.generatePrivateKey()
        val pub = X25519Crypto.publicKey(priv)
        assertEquals(32, pub.size)
    }

    @Test
    fun keyExchange_symmetric() {
        val aPriv = X25519Crypto.generatePrivateKey()
        val aPub = X25519Crypto.publicKey(aPriv)
        val bPriv = X25519Crypto.generatePrivateKey()
        val bPub = X25519Crypto.publicKey(bPriv)
        val shared1 = X25519Crypto.keyExchange(aPriv, bPub)
        val shared2 = X25519Crypto.keyExchange(bPriv, aPub)
        assertArrayEquals(shared1, shared2)
        assertEquals(32, shared1.size)
    }

    /** RFC 7748 §6.1 X25519 test vector. */
    @Test
    fun rfc7748_testVector() {
        // Alice's private key
        val alicePriv = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        // Bob's public key
        val bobPub = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        // Expected shared secret
        val expected = fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        val shared = X25519Crypto.keyExchange(alicePriv, bobPub)
        assertArrayEquals(expected, shared)
    }

    @Test
    fun keyExchange_rejectsWrongSize() {
        val priv = X25519Crypto.generatePrivateKey()
        assertThrows(IllegalArgumentException::class.java) {
            X25519Crypto.keyExchange(priv, ByteArray(16))
        }
    }
}
