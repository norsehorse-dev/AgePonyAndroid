package com.agepony.core.fido

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** authData vectors from cbor2 + python cryptography (rpIdHash = SHA-256("ssh:")). */
class AuthenticatorDataTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val rpIdHashSsh = "e30610e8a162115960fe1ec223e6529c9f4b6e80200dcb5e5c321c8af1e2b1bf"
    private val credId = "abababababababababababababababab"
    private val ed25519Pub = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    private val authDataMc = "e30610e8a162115960fe1ec223e6529c9f4b6e80200dcb5e5c321c8af1e2b1bf4100000007000000000000000000000000000000000010ababababababababababababababababa401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    private val authDataGa = "e30610e8a162115960fe1ec223e6529c9f4b6e80200dcb5e5c321c8af1e2b1bf0100000007"

    @Test
    fun parsesMakeCredentialAuthData() {
        val p = AuthenticatorData.parse(unhex(authDataMc))
        assertEquals(rpIdHashSsh, hex(p.rpIdHash))
        assertEquals(0x41, p.flags)
        assertTrue(p.userPresent)
        assertTrue(p.hasAttestedCredential)
        assertFalse(p.userVerified)
        assertEquals(7L, p.signCount)
        assertEquals(credId, hex(p.credentialId!!))
        val pub = p.credentialPublicKey
        assertTrue(pub is CoseKey.Decoded.Ed25519)
        assertEquals(ed25519Pub, hex((pub as CoseKey.Decoded.Ed25519).raw32))
    }

    @Test
    fun parsesGetAssertionAuthData() {
        val p = AuthenticatorData.parse(unhex(authDataGa))
        assertEquals(rpIdHashSsh, hex(p.rpIdHash))
        assertEquals(0x01, p.flags)
        assertTrue(p.userPresent)
        assertFalse(p.hasAttestedCredential)
        assertEquals(7L, p.signCount)
        assertNull(p.credentialId)
        assertNull(p.credentialPublicKey)
    }
}
