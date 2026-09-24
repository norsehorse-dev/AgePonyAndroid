package com.agepony.core.signing

import com.agepony.core.Stanza
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class SignatureStanzaTest {

    private fun fileKey() = ByteArray(16).also { SecureRandom().nextBytes(it) }

    @Test
    fun roundTripsUnderTheSameFileKey() {
        val fk = fileKey()
        val sig = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
        val stanza = SignatureStanza.build(fk, sig)
        assertEquals(SignatureStanza.TYPE, stanza.type)
        assertEquals(listOf(SignatureStanza.VERSION), stanza.args)
        assertEquals(sig, SignatureStanza.open(fk, stanza))
    }

    @Test
    fun aDifferentFileKeyCannotOpenIt() {
        val stanza = SignatureStanza.build(fileKey(), "signature")
        assertNull(SignatureStanza.open(fileKey(), stanza))
    }

    @Test
    fun theSignatureIsNotInCleartext() {
        val sig = "-----BEGIN SSH SIGNATURE-----\nSIGNERPUBLICKEY\n-----END SSH SIGNATURE-----\n"
        val stanza = SignatureStanza.build(fileKey(), sig)
        val body = String(stanza.body, Charsets.ISO_8859_1)
        assertFalse(body.contains("SIGNERPUBLICKEY"))
    }

    @Test
    fun openReturnsNullForANonSignatureStanza() {
        assertNull(SignatureStanza.open(fileKey(), Stanza("X25519", listOf("abc"), ByteArray(32))))
    }

    @Test
    fun findLocatesTheStanza() {
        val fk = fileKey()
        val stanzas = listOf(
            Stanza("X25519", listOf("abc"), ByteArray(32)),
            SignatureStanza.build(fk, "sig"),
        )
        val found = SignatureStanza.find(stanzas)
        assertEquals("sig", found?.let { SignatureStanza.open(fk, it) })
        assertNull(SignatureStanza.find(listOf(Stanza("scrypt", listOf("s", "18"), ByteArray(16)))))
    }

    @Test
    fun eachBuildUsesAFreshNonce() {
        val fk = fileKey()
        val a = SignatureStanza.build(fk, "sig")
        val b = SignatureStanza.build(fk, "sig")
        assertNotEquals(a.body.toList(), b.body.toList())
    }
}
