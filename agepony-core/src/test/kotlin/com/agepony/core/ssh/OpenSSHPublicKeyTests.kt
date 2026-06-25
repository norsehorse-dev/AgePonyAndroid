package com.agepony.core.ssh

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64

class OpenSSHPublicKeyTests {
    private fun newEdPubKey(): ByteArray {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    }

    private fun buildEd25519Line(pubKey: ByteArray, comment: String? = null): String {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, "ssh-ed25519".toByteArray())
        SSHWire.writeString(out, pubKey)
        val b64 = Base64.getEncoder().encodeToString(out.toByteArray())
        return if (comment != null) "ssh-ed25519 $b64 $comment" else "ssh-ed25519 $b64"
    }

    private fun buildRSALine(n: BigInteger, e: BigInteger, comment: String? = null): String {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, "ssh-rsa".toByteArray())
        SSHMPInt.write(out, e)
        SSHMPInt.write(out, n)
        val b64 = Base64.getEncoder().encodeToString(out.toByteArray())
        return if (comment != null) "ssh-rsa $b64 $comment" else "ssh-rsa $b64"
    }

    // --- Ed25519 cases ---

    @Test
    fun parse_validEd25519_withComment() {
        val pubKey = newEdPubKey()
        val parsed = OpenSSHPublicKey.parse(buildEd25519Line(pubKey, "alice@host"))
        assertTrue(parsed is OpenSSHPublicKey.Ed25519)
        parsed as OpenSSHPublicKey.Ed25519
        assertEquals("ssh-ed25519", parsed.keyType)
        assertArrayEquals(pubKey, parsed.publicKey)
        assertEquals("alice@host", parsed.comment)
    }

    @Test
    fun parse_validEd25519_withoutComment() {
        val pubKey = newEdPubKey()
        val parsed = OpenSSHPublicKey.parse(buildEd25519Line(pubKey, null))
        assertTrue(parsed is OpenSSHPublicKey.Ed25519)
        parsed as OpenSSHPublicKey.Ed25519
        assertArrayEquals(pubKey, parsed.publicKey)
        assertNull(parsed.comment)
    }

    @Test
    fun parse_acceptsLeadingTrailingWhitespace() {
        val pubKey = newEdPubKey()
        val parsed = OpenSSHPublicKey.parse("   " + buildEd25519Line(pubKey, "x") + "   \n")
            as OpenSSHPublicKey.Ed25519
        assertArrayEquals(pubKey, parsed.publicKey)
    }

    @Test
    fun parse_commentMayContainSpaces() {
        val pubKey = newEdPubKey()
        val parsed = OpenSSHPublicKey.parse(buildEd25519Line(pubKey, "test key for agepony"))
            as OpenSSHPublicKey.Ed25519
        assertEquals("test key for agepony", parsed.comment)
    }

    @Test
    fun parse_rejectsEmptyInput() {
        assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java) {
            OpenSSHPublicKey.parse("")
        }
    }

    @Test
    fun parse_rejectsMissingBase64Part() {
        assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java) {
            OpenSSHPublicKey.parse("ssh-ed25519")
        }
    }

    @Test
    fun parse_rejectsInvalidBase64() {
        assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java) {
            OpenSSHPublicKey.parse("ssh-ed25519 not_base64_!@#$ host")
        }
    }

    @Test
    fun parse_rejectsKeytypeMismatch_Ed25519() {
        // Wire blob says "ssh-rsa" but outer says "ssh-ed25519"
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, "ssh-rsa".toByteArray())
        SSHWire.writeString(out, ByteArray(32))
        val b64 = Base64.getEncoder().encodeToString(out.toByteArray())
        assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java) {
            OpenSSHPublicKey.parse("ssh-ed25519 $b64")
        }
    }

    @Test
    fun parse_rejectsUnsupportedKeyType() {
        // ECDSA — not supported
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, "ecdsa-sha2-nistp256".toByteArray())
        SSHWire.writeString(out, ByteArray(65))
        val b64 = Base64.getEncoder().encodeToString(out.toByteArray())
        assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java) {
            OpenSSHPublicKey.parse("ecdsa-sha2-nistp256 $b64")
        }
    }

    @Test
    fun parse_rejectsTruncatedWireBlob() {
        val truncated = byteArrayOf(0, 0, 0, 11)
        val b64 = Base64.getEncoder().encodeToString(truncated)
        assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java) {
            OpenSSHPublicKey.parse("ssh-ed25519 $b64")
        }
    }

    @Test
    fun parse_rejectsWrongEd25519PubkeySize() {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, "ssh-ed25519".toByteArray())
        SSHWire.writeString(out, ByteArray(16))   // wrong size
        val b64 = Base64.getEncoder().encodeToString(out.toByteArray())
        assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java) {
            OpenSSHPublicKey.parse("ssh-ed25519 $b64")
        }
    }

    // --- RSA cases ---

    @Test
    fun parse_validRSA_withComment() {
        // Use small test values for parsing — we're not doing crypto here
        val n = BigInteger("00ff0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f", 16)
        val e = BigInteger.valueOf(65537)
        val parsed = OpenSSHPublicKey.parse(buildRSALine(n, e, "rsa@host"))
        assertTrue(parsed is OpenSSHPublicKey.RSA)
        parsed as OpenSSHPublicKey.RSA
        assertEquals("ssh-rsa", parsed.keyType)
        assertEquals(n, parsed.modulus)
        assertEquals(e, parsed.exponent)
        assertEquals("rsa@host", parsed.comment)
    }

    @Test
    fun parse_validRSA_largeModulus() {
        // Generate a real RSA-2048 keypair so the modulus has high bit set
        val gen = RSAKeyPairGenerator()
        gen.init(RSAKeyGenerationParameters(
            BigInteger.valueOf(65537), SecureRandom(), 2048, 80
        ))
        val keyPair = gen.generateKeyPair()
        val pub = keyPair.public as RSAKeyParameters
        val n = pub.modulus
        val e = pub.exponent
        val parsed = OpenSSHPublicKey.parse(buildRSALine(n, e, "real@rsa"))
            as OpenSSHPublicKey.RSA
        assertEquals(n, parsed.modulus)
        assertEquals(e, parsed.exponent)
    }

    @Test
    fun parse_rejectsRSA_keytypeMismatch() {
        // Wire blob says "ssh-ed25519" but outer says "ssh-rsa"
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, "ssh-ed25519".toByteArray())
        SSHWire.writeString(out, ByteArray(32))
        val b64 = Base64.getEncoder().encodeToString(out.toByteArray())
        assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java) {
            OpenSSHPublicKey.parse("ssh-rsa $b64")
        }
    }

    @Test
    fun parse_rejectsRSA_zeroModulus() {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, "ssh-rsa".toByteArray())
        SSHMPInt.write(out, BigInteger.valueOf(65537))
        SSHMPInt.write(out, BigInteger.ZERO)    // n = 0, invalid
        val b64 = Base64.getEncoder().encodeToString(out.toByteArray())
        assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java) {
            OpenSSHPublicKey.parse("ssh-rsa $b64")
        }
    }
}
