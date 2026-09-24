package com.agepony.app.signing

import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.StoredSigner
import com.agepony.app.vault.StoredSignerSource
import com.agepony.app.vault.b64e
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner
import com.agepony.core.signing.SignatureStanza
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * FileVerifier trust classification. Uses a known ed25519 seed (0x00..0x1f) and its public
 * key to produce a real SSHSIG via SSHSigner, then checks the trusted / valid-unknown /
 * invalid outcomes. No Android dependencies, so it runs as a host unit test.
 */
class FileVerifierTest {
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val seed32 = ByteArray(32) { it.toByte() }
    private val pub32 = unhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
    private val message = "agepony detached signature test".toByteArray()

    private fun identity(name: String) = StoredIdentity(
        id = "id-$name",
        name = name,
        type = StoredIdentityType.SSH_ED25519,
        publicKeyB64 = b64e(pub32),
        privateKeyB64 = b64e(seed32),
        createdAt = 0L,
    )

    private fun signature(): ByteArray =
        SSHSigner.signEd25519(seed32, pub32, message).toByteArray(Charsets.UTF_8)

    @Test
    fun trustedWhenSignerIsAKnownIdentity() {
        val r = FileVerifier().verify(signature(), message, listOf(identity("Work key")))
        assertEquals(FileVerifier.Trust.TRUSTED, r.trust)
        assertEquals("Work key", r.signerName)
        assertNull(r.reason)
    }

    @Test
    fun validUnknownWhenSignerNotInVault() {
        val r = FileVerifier().verify(signature(), message, emptyList())
        assertEquals(FileVerifier.Trust.VALID_UNKNOWN, r.trust)
        assertNull(r.signerName)
    }

    private fun signer(options: String?) = StoredSigner(
        id = "s1",
        name = "Alice",
        keyType = "ssh-ed25519",
        publicKeyWireB64 = b64e(SSHSig.ed25519PublicWire(pub32)),
        source = StoredSignerSource.IMPORT_ALLOWED_SIGNERS,
        createdAt = 0L,
        options = options,
    )

    @Test
    fun storedSignerWithoutOptionsIsTrusted() {
        val r = FileVerifier().verify(signature(), message, emptyList(), listOf(signer(null)))
        assertEquals(FileVerifier.Trust.TRUSTED, r.trust)
        assertEquals("Alice", r.signerName)
    }

    // audit L-6: imported allowed_signers options are enforced, never silently dropped.
    @Test
    fun expiredStoredSignerIsValidButNotTrusted() {
        val r = FileVerifier().verify(signature(), message, emptyList(), listOf(signer("valid-before=\"20200101Z\"")))
        assertEquals(FileVerifier.Trust.VALID_UNKNOWN, r.trust)
        assertNull(r.signerName)
        assertEquals("Alice", r.untrustedSignerName)
        assertNotNull(r.untrustedReason)
    }

    @Test
    fun otherNamespaceStoredSignerIsNotTrusted() {
        val r = FileVerifier().verify(signature(), message, emptyList(), listOf(signer("namespaces=\"git\"")))
        assertEquals(FileVerifier.Trust.VALID_UNKNOWN, r.trust)
        assertEquals("Alice", r.untrustedSignerName)
    }

    @Test
    fun certAuthorityAndUnknownOptionsAreNotTrusted() {
        for (opts in listOf("cert-authority", "frobnicate")) {
            val r = FileVerifier().verify(signature(), message, emptyList(), listOf(signer(opts)))
            assertEquals(opts, FileVerifier.Trust.VALID_UNKNOWN, r.trust)
        }
    }

    @Test
    fun ageponyRestrictionAlsoPermitsTheV2Namespace() {
        val hash = SSHSig.hashMessage(message)
        val v2 = SSHSigner.signEd25519Hashed(seed32, pub32, hash, SignatureStanza.NAMESPACE_V2).toByteArray(Charsets.UTF_8)
        val r = FileVerifier().verifyHashed(v2, emptyList(), listOf(signer("namespaces=\"agepony\"")), SignatureStanza.NAMESPACE_V2) { hash }
        assertEquals(FileVerifier.Trust.TRUSTED, r.trust)
    }

    @Test
    fun malformedSignatureIsInvalidNotAnException() {
        val r = FileVerifier().verify("not a signature".toByteArray(), message, listOf(identity("Work key")))
        assertEquals(FileVerifier.Trust.INVALID, r.trust)
        assertNotNull(r.reason)
        val huge = FileVerifier().verify(ByteArray(20_000), message, emptyList())
        assertEquals(FileVerifier.Trust.INVALID, huge.trust)
    }

    @Test
    fun wrongNamespaceIsInvalid() {
        val r = FileVerifier().verify(signature(), message, listOf(identity("Work key")), namespace = SignatureStanza.NAMESPACE_V2)
        assertEquals(FileVerifier.Trust.INVALID, r.trust)
    }

    @Test
    fun invalidWhenMessageTampered() {
        val r = FileVerifier().verify(signature(), "different bytes".toByteArray(), listOf(identity("Work key")))
        assertEquals(FileVerifier.Trust.INVALID, r.trust)
        assertNotNull(r.reason)
    }
}
