package com.agepony.app.vault

import com.agepony.core.crypto.P256Curve
import com.agepony.core.recipients.SSHEd25519Identity
import com.agepony.core.recipients.YubiKeyStub
import com.agepony.core.signing.SSHSig
import com.agepony.core.ssh.AllowedSigners
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.time.ZoneOffset

/**
 * Host tests for the 5.0.1 import checks: identity consistency on transfer (audit AS-2), the
 * allowed_signers import review (audit L-6) and the GitHub username rule. No Android APIs.
 */
class TransferTrustTest {
    private fun sshEd25519(name: String, id: SSHEd25519Identity = SSHEd25519Identity.generate()) = StoredIdentity(
        id = "id-$name",
        name = name,
        type = StoredIdentityType.SSH_ED25519,
        publicKeyB64 = b64e(id.edPublicKey),
        privateKeyB64 = b64e(id.edSeed),
        createdAt = 0L,
    )

    @Test
    fun ed25519SeedMustDeriveStoredPublicKey() {
        val good = sshEd25519("a")
        assertTrue(KeyPortability.isConsistent(good))
        val other = SSHEd25519Identity.generate()
        assertFalse(KeyPortability.isConsistent(good.copy(publicKeyB64 = b64e(other.edPublicKey))))
    }

    @Test
    fun yubiKeyStubTagMustMatchPublicKey() {
        val pub = P256Curve.toCompressed(P256Curve.randomPublicUncompressed())
        val stub = YubiKeyStub(12345, 0x82, YubiKeyStub.staticTag(pub))
        val yk = StoredIdentity("y", "yk", StoredIdentityType.YUBIKEY_PIV, b64e(pub), b64e(stub.toBytes()), createdAt = 0L)
        assertTrue(KeyPortability.isConsistent(yk))
        val other = P256Curve.toCompressed(P256Curve.randomPublicUncompressed())
        assertFalse(KeyPortability.isConsistent(yk.copy(publicKeyB64 = b64e(other))))
    }

    @Test
    fun securityKeyPublicWireMustBeWellFormed() {
        val pub = SSHEd25519Identity.generate().edPublicKey
        val wire = SSHSig.skEd25519PublicWire(pub, "ssh:")
        val sk = StoredIdentity("s", "sk", StoredIdentityType.SK_ED25519, b64e(wire), b64e(ByteArray(64) { 1 }), createdAt = 0L)
        assertTrue(KeyPortability.isConsistent(sk))
        assertFalse(KeyPortability.isConsistent(sk.copy(type = StoredIdentityType.SK_ECDSA_P256)))
        assertFalse(KeyPortability.isConsistent(sk.copy(publicKeyB64 = b64e(wire + byteArrayOf(0)))))
        assertFalse(KeyPortability.isConsistent(sk.copy(privateKeyB64 = "")))
        val offCurve = SSHSig.skEd25519PublicWire(ByteArray(32) { 0xff.toByte() }, "ssh:")
        assertFalse(KeyPortability.isConsistent(sk.copy(publicKeyB64 = b64e(offCurve))))
    }

    @Test
    fun deviceBoundIdentitiesAreNeverConsistent() {
        assertFalse(KeyPortability.isConsistent(sshEd25519("h").copy(type = StoredIdentityType.HARDWARE_TAG)))
    }

    @Test
    fun readBundleDropsInconsistentIdentitiesAndMismatchedSigners() {
        val good = sshEd25519("good")
        val forged = sshEd25519("forged").copy(publicKeyB64 = b64e(SSHEd25519Identity.generate().edPublicKey))
        val wire = b64e(SSHSig.ed25519PublicWire(b64d(good.publicKeyB64)))
        val signer = StoredSigner("x", "alice", "ssh-ed25519", wire, null, StoredSignerSource.PASTE_KEY, 0L)
        val bundle = KeyPortability.buildBundle(listOf(good, forged), emptyList(), listOf(signer, signer.copy(keyType = "ssh-rsa")))
        val inc = KeyPortability.readBundle(bundle)
        assertEquals(listOf("good"), inc.identities.map { it.name })
        assertEquals(1, inc.signers.size)
    }

    @Test
    fun allowedSignersReviewRefusesWhatItCannotEnforce() {
        fun key() = b64e(SSHSig.ed25519PublicWire(SSHEd25519Identity.generate().edPublicKey))
        val text = """
            git@x namespaces="git" ssh-ed25519 ${key()}
            old@x valid-before="20250101Z" ssh-ed25519 ${key()}
            ca@x cert-authority ssh-ed25519 ${key()}
            odd@x foo=bar ssh-ed25519 ${key()}
            ok@x namespaces="agepony",no-touch-required ssh-ed25519 ${key()}
            plain@x ssh-ed25519 ${key()}
        """.trimIndent()
        val now = Instant.parse("2026-09-23T00:00:00Z")
        val rows = AllowedSigners.parse(text).map {
            AllowedSignerReview.of(it, StoredSignerSource.IMPORT_ALLOWED_SIGNERS, emptyList(), now)
        }
        assertEquals(listOf(true, true, false, false, true, true), rows.map { it.importable })
        assertEquals(listOf(false, false, false, false, true, true), rows.map { it.checkedByDefault })
        assertNotNull(rows[0].warning)
        assertNotNull(rows[1].warning)
        assertNotNull(rows[2].blocked)
        assertNotNull(rows[3].blocked)
        assertNull(rows[4].warning)
        // Imported options are exported unchanged.
        assertEquals("namespaces=\"agepony\",no-touch-required", rows[4].signer!!.toAllowedSigner().options)
    }

    @Test
    fun describesOptionsInPlainWords() {
        val words = StoredSigner.describeOptions("namespaces=\"git\",valid-before=\"20250101Z\"", ZoneOffset.UTC)
        assertEquals(listOf("git only", "valid until 2025-01-01"), words)
    }

    @Test
    fun gitHubUsernamesAreAsciiLettersDigitsAndHyphens() {
        assertTrue(RecipientImport.isValidGitHubUsername("octo-cat1"))
        assertTrue(RecipientImport.isValidGitHubUsername("a".repeat(39)))
        assertFalse(RecipientImport.isValidGitHubUsername(""))
        assertFalse(RecipientImport.isValidGitHubUsername("-octo"))
        assertFalse(RecipientImport.isValidGitHubUsername("octo_cat"))
        assertFalse(RecipientImport.isValidGitHubUsername("a".repeat(40)))
        assertFalse(RecipientImport.isValidGitHubUsername("élodie"))
        assertFalse(RecipientImport.isValidGitHubUsername("octo/../x"))
    }
}
