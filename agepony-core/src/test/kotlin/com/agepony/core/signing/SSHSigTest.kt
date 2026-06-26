package com.agepony.core.signing

import com.agepony.core.ssh.OpenSSHPrivateKey
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.math.BigInteger
import java.security.SecureRandom

/**
 * SSHSIG signing/verification for the in-app SSH key path (ed25519, rsa-sha2-512) plus
 * software ecdsa-sha2-nistp256.
 *
 * Two kinds of proof:
 *   1. Fixtures produced by the reference `ssh-keygen -Y sign` (namespace `agepony`) are
 *      accepted by [SSHSigVerifier], proving our verifier matches OpenSSH's signer.
 *   2. Signatures we produce round-trip through our own verifier, and (when `ssh-keygen`
 *      is on PATH) are accepted by `ssh-keygen -Y verify`, proving our envelope matches
 *      OpenSSH's verifier byte-for-byte.
 *
 * Regenerate fixtures with: bash generate-fixtures.sh
 */
class SSHSigTest {
    private val fixturesDir = File("src/test/resources/fixtures")
    private val rng = SecureRandom()

    private fun message(): ByteArray =
        File(fixturesDir, "sshsig_message.txt").readBytes()

    // --- ssh-keygen fixtures verify with our verifier ---

    @Test
    fun ed25519_sshKeygenFixture_verifies() {
        val sigFile = File(fixturesDir, "sshsig_ed25519_hello.sig")
        val msgFile = File(fixturesDir, "sshsig_message.txt")
        assumeTrue(
            sigFile.exists() && msgFile.exists(),
            "SSHSIG ed25519 fixtures not found; run bash generate-fixtures.sh from project root"
        )
        val result = SSHSigVerifier.verify(sigFile.readBytes(), msgFile.readBytes())
        assertTrue(result.valid, "ssh-keygen ed25519 signature should verify")
        assertEquals(SSHSig.KEY_ED25519, result.keyType)
        assertEquals(SSHSig.NAMESPACE_AGEPONY, result.namespace)
    }

    @Test
    fun rsa_sshKeygenFixture_verifies() {
        val sigFile = File(fixturesDir, "sshsig_rsa_hello.sig")
        val msgFile = File(fixturesDir, "sshsig_message.txt")
        assumeTrue(
            sigFile.exists() && msgFile.exists(),
            "SSHSIG rsa fixtures not found; run bash generate-fixtures.sh from project root"
        )
        val result = SSHSigVerifier.verify(sigFile.readBytes(), msgFile.readBytes())
        assertTrue(result.valid, "ssh-keygen rsa signature should verify")
        assertEquals(SSHSig.KEY_RSA, result.keyType)
    }

    @Test
    fun fixtureRejectsTamperedMessage() {
        val sigFile = File(fixturesDir, "sshsig_ed25519_hello.sig")
        val msgFile = File(fixturesDir, "sshsig_message.txt")
        assumeTrue(sigFile.exists() && msgFile.exists(), "fixtures not found")
        val tampered = msgFile.readBytes() + 0x21.toByte()
        assertFalse(SSHSigVerifier.isValid(sigFile.readBytes(), tampered))
    }

    // --- Software signing round-trips through our verifier ---

    @Test
    fun ed25519_signRoundTrip() {
        val key = loadPrivate("ssh_ed25519_identity") as OpenSSHPrivateKey.Ed25519
        val msg = "round-trip ed25519".toByteArray()
        val sig = SSHSigner.sign(key, msg).toByteArray()
        assertTrue(SSHSigVerifier.isValid(sig, msg))
        assertFalse(SSHSigVerifier.isValid(sig, "different message".toByteArray()))
        assertFalse(SSHSigVerifier.verify(sig, msg, expectedNamespace = "other").valid)
    }

    @Test
    fun rsa_signRoundTrip() {
        val key = loadPrivate("ssh_rsa_identity") as OpenSSHPrivateKey.RSA
        val msg = "round-trip rsa".toByteArray()
        val sig = SSHSigner.signRsaSha512(key.n, key.e, key.d, msg).toByteArray()
        assertTrue(SSHSigVerifier.isValid(sig, msg))
        assertFalse(SSHSigVerifier.isValid(sig, "tampered".toByteArray()))
    }

    @Test
    fun ecdsaP256_signRoundTrip() {
        val d = randomScalar()
        val msg = "round-trip ecdsa".toByteArray()
        val sig = SSHSigner.signEcdsaP256(d, msg).toByteArray()
        val result = SSHSigVerifier.verify(sig, msg)
        assertTrue(result.valid)
        assertEquals(SSHSig.KEY_ECDSA_P256, result.keyType)
        assertFalse(SSHSigVerifier.isValid(sig, "tampered".toByteArray()))
    }

    // --- Envelope plumbing ---

    @Test
    fun armorRoundTrips() {
        val key = loadPrivate("ssh_ed25519_identity") as OpenSSHPrivateKey.Ed25519
        val armored = SSHSigner.sign(key, "abc".toByteArray())
        val blob = SSHSig.dearmor(armored)
        assertEquals(armored.trim(), SSHSig.armor(blob).trim())
        val decoded = SSHSig.decode(blob)
        assertEquals(SSHSig.SIG_VERSION, decoded.version)
        assertEquals(SSHSig.NAMESPACE_AGEPONY, decoded.namespace)
        assertEquals(SSHSig.HASH_SHA512, decoded.hashAlgorithm)
        assertEquals(SSHSig.KEY_ED25519, decoded.keyType)
    }

    @Test
    fun signedDataIsStableAndNamespaceScoped() {
        val mh = SSHSig.hashMessage("x".toByteArray())
        val a = SSHSig.signedData("agepony", SSHSig.HASH_SHA512, mh)
        val b = SSHSig.signedData("agepony", SSHSig.HASH_SHA512, mh)
        val c = SSHSig.signedData("other", SSHSig.HASH_SHA512, mh)
        assertTrue(a.contentEquals(b))
        assertFalse(a.contentEquals(c))
    }

    // --- Optional cross-check: our signature must satisfy ssh-keygen -Y verify ---

    @Test
    fun ed25519_ourSignatureVerifiesWithSshKeygen() {
        assumeTrue(sshKeygenAvailable(), "ssh-keygen not on PATH; skipping cross-check")
        val pubFile = File(fixturesDir, "ssh_ed25519_identity.pub")
        assumeTrue(pubFile.exists(), "ssh_ed25519_identity.pub not found")

        val key = loadPrivate("ssh_ed25519_identity") as OpenSSHPrivateKey.Ed25519
        val msg = "cross-check ed25519".toByteArray()
        val armored = SSHSigner.sign(key, msg)

        val tmp = File.createTempFile("agepony-xcheck", "").apply { delete(); mkdirs() }
        try {
            val sigFile = File(tmp, "m.sig").apply { writeText(armored) }
            val msgFile = File(tmp, "m.txt").apply { writeBytes(msg) }
            val pubParts = pubFile.readText().trim().split(Regex("\\s+"))
            val allowed = File(tmp, "allowed_signers").apply {
                writeText("agepony@test ${pubParts[0]} ${pubParts[1]}\n")
            }
            val rc = ProcessBuilder(
                "ssh-keygen", "-Y", "verify",
                "-f", allowed.absolutePath,
                "-I", "agepony@test",
                "-n", "agepony",
                "-s", sigFile.absolutePath,
            ).redirectInput(msgFile).redirectErrorStream(true).start().waitFor()
            assertEquals(0, rc, "ssh-keygen should accept our SSHSIG signature")
        } finally {
            tmp.deleteRecursively()
        }
    }

    // --- helpers ---

    private fun loadPrivate(name: String): OpenSSHPrivateKey {
        val f = File(fixturesDir, name)
        assumeTrue(f.exists(), "$name not found; run bash generate-fixtures.sh from project root")
        return OpenSSHPrivateKey.parse(f.readText())
    }

    private fun randomScalar(): BigInteger {
        val n = SSHSigner.p256Domain().n
        var d: BigInteger
        do {
            d = BigInteger(n.bitLength(), rng)
        } while (d < BigInteger.ONE || d >= n)
        return d
    }

    private fun sshKeygenAvailable(): Boolean = try {
        ProcessBuilder("ssh-keygen", "-Y").redirectErrorStream(true).start().waitFor()
        true
    } catch (e: Exception) {
        false
    }
}
