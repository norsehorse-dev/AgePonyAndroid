package com.agepony.app.security.keystore

import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.isSigningOnly
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigVerifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * JVM-side validation of the device-independent hardware-signing logic. Uses an ordinary
 * software EC P-256 key (no AndroidKeyStore) to run the exact point-encoding, public-wire,
 * and DER -> SSHSIG assembly path the on-device [HardwareKeyService] uses, and verifies
 * the result with [SSHSigVerifier]. The real Keystore path is covered by the instrumented
 * test.
 */
class KeystoreEcdsaTest {

    private fun softwareKey(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        return kpg.generateKeyPair()
    }

    @Test
    fun uncompressedPointIs65ByteUncompressed() {
        val pub = softwareKey().public as ECPublicKey
        val q = KeystoreEcdsa.uncompressedPoint(pub)
        assertEquals(65, q.size)
        assertEquals(0x04.toByte(), q[0])
    }

    @Test
    fun publicWireIsEcdsaP256() {
        val pub = softwareKey().public as ECPublicKey
        assertEquals(SSHSig.KEY_ECDSA_P256, SSHSig.readLeadingString(KeystoreEcdsa.publicWire(pub)))
    }

    @Test
    fun assembleProducesVerifiableSignature() {
        val kp = softwareKey()
        val msg = "hardware-style ecdsa".toByteArray()
        val signedData = KeystoreEcdsa.signedData(msg)

        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(kp.private)
        sig.update(signedData)
        val der = sig.sign()

        val armored = KeystoreEcdsa.assemble(kp.public as ECPublicKey, der, msg)
        assertTrue(SSHSigVerifier.isValid(armored.toByteArray(), msg))
        assertFalse(SSHSigVerifier.isValid(armored.toByteArray(), "tampered".toByteArray()))
    }

    @Test
    fun hardwareKeyTypeIsSigningOnly() {
        assertTrue(StoredIdentityType.HARDWARE_KEY.isSigningOnly)
        assertFalse(StoredIdentityType.X25519.isSigningOnly)
        assertFalse(StoredIdentityType.SSH_ED25519.isSigningOnly)
        assertFalse(StoredIdentityType.SSH_RSA.isSigningOnly)
    }
}
