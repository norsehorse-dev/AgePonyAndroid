package com.agepony.core.ssh

import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
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

class OpenSSHPrivateKeyTests {

    // --- PEM construction helpers ---

    private fun buildEd25519PEM(seed: ByteArray, comment: String = "test@agepony"): String {
        require(seed.size == 32)
        val edPriv = Ed25519PrivateKeyParameters(seed, 0)
        val pubKey = edPriv.generatePublicKey().encoded

        val pubKeyBlob = ByteArrayOutputStream().apply {
            SSHWire.writeString(this, "ssh-ed25519".toByteArray())
            SSHWire.writeString(this, pubKey)
        }.toByteArray()

        val privSection = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x12, 0x34, 0x56, 0x78))
            write(byteArrayOf(0x12, 0x34, 0x56, 0x78))
            SSHWire.writeString(this, "ssh-ed25519".toByteArray())
            SSHWire.writeString(this, pubKey)
            SSHWire.writeString(this, seed + pubKey)
            SSHWire.writeString(this, comment.toByteArray())
            val padLen = (8 - size() % 8) % 8
            for (i in 1..padLen) write(i)
        }.toByteArray()

        return wrapInPEM(pubKeyBlob, privSection)
    }

    private fun buildRSAPEM(
        n: BigInteger, e: BigInteger, d: BigInteger,
        p: BigInteger, q: BigInteger, iqmp: BigInteger,
        comment: String = "test@agepony",
    ): String {
        val pubKeyBlob = ByteArrayOutputStream().apply {
            SSHWire.writeString(this, "ssh-rsa".toByteArray())
            SSHMPInt.write(this, e)
            SSHMPInt.write(this, n)
        }.toByteArray()

        val privSection = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x12, 0x34, 0x56, 0x78))
            write(byteArrayOf(0x12, 0x34, 0x56, 0x78))
            SSHWire.writeString(this, "ssh-rsa".toByteArray())
            SSHMPInt.write(this, n)
            SSHMPInt.write(this, e)
            SSHMPInt.write(this, d)
            SSHMPInt.write(this, iqmp)
            SSHMPInt.write(this, p)
            SSHMPInt.write(this, q)
            SSHWire.writeString(this, comment.toByteArray())
            val padLen = (8 - size() % 8) % 8
            for (i in 1..padLen) write(i)
        }.toByteArray()

        return wrapInPEM(pubKeyBlob, privSection)
    }

    private fun wrapInPEM(pubKeyBlob: ByteArray, privSection: ByteArray): String {
        val blob = ByteArrayOutputStream().apply {
            write("openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII))
            SSHWire.writeString(this, "none".toByteArray())
            SSHWire.writeString(this, "none".toByteArray())
            SSHWire.writeString(this, ByteArray(0))
            write(byteArrayOf(0, 0, 0, 1))
            SSHWire.writeString(this, pubKeyBlob)
            SSHWire.writeString(this, privSection)
        }.toByteArray()
        val b64 = Base64.getEncoder().encodeToString(blob)
        val wrapped = b64.chunked(70).joinToString("\n")
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n$wrapped\n-----END OPENSSH PRIVATE KEY-----\n"
    }

    private fun genRSAKey(): RSAPrivateCrtKeyParameters {
        val gen = RSAKeyPairGenerator()
        gen.init(RSAKeyGenerationParameters(
            BigInteger.valueOf(65537), SecureRandom(), 2048, 80
        ))
        return gen.generateKeyPair().private as RSAPrivateCrtKeyParameters
    }

    // --- Ed25519 cases ---

    @Test
    fun parse_validEd25519_unencryptedKey() {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val parsed = OpenSSHPrivateKey.parse(buildEd25519PEM(seed, "alice@host"))
        assertTrue(parsed is OpenSSHPrivateKey.Ed25519)
        parsed as OpenSSHPrivateKey.Ed25519
        assertEquals("ssh-ed25519", parsed.keyType)
        assertArrayEquals(seed, parsed.privateKey)
        assertEquals(32, parsed.publicKey.size)
        assertEquals("alice@host", parsed.comment)
    }

    @Test
    fun parse_ed25519_emptyComment() {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val parsed = OpenSSHPrivateKey.parse(buildEd25519PEM(seed, ""))
            as OpenSSHPrivateKey.Ed25519
        assertNull(parsed.comment)
    }

    @Test
    fun parse_acceptsCRLF() {
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val pem = buildEd25519PEM(seed).replace("\n", "\r\n")
        val parsed = OpenSSHPrivateKey.parse(pem) as OpenSSHPrivateKey.Ed25519
        assertArrayEquals(seed, parsed.privateKey)
    }

    @Test
    fun parse_rejectsMissingBeginMarker() {
        val seed = ByteArray(32)
        val pem = buildEd25519PEM(seed).removePrefix("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(pem)
        }
    }

    @Test
    fun parse_rejectsMissingEndMarker() {
        val seed = ByteArray(32)
        val pem = buildEd25519PEM(seed).removeSuffix("-----END OPENSSH PRIVATE KEY-----\n")
        assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(pem)
        }
    }

    @Test
    fun parse_rejectsEncryptedPEM_withCipherNotNone() {
        val seed = ByteArray(32)
        val edPriv = Ed25519PrivateKeyParameters(seed, 0)
        val pubKey = edPriv.generatePublicKey().encoded
        val pubKeyBlob = ByteArrayOutputStream().apply {
            SSHWire.writeString(this, "ssh-ed25519".toByteArray())
            SSHWire.writeString(this, pubKey)
        }.toByteArray()
        val blob = ByteArrayOutputStream().apply {
            write("openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII))
            SSHWire.writeString(this, "aes256-ctr".toByteArray())
            SSHWire.writeString(this, "bcrypt".toByteArray())
            SSHWire.writeString(this, ByteArray(24))
            write(byteArrayOf(0, 0, 0, 1))
            SSHWire.writeString(this, pubKeyBlob)
            SSHWire.writeString(this, ByteArray(128))
        }.toByteArray()
        val b64 = Base64.getEncoder().encodeToString(blob).chunked(70).joinToString("\n")
        val pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n$b64\n-----END OPENSSH PRIVATE KEY-----\n"

        val ex = assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(pem)
        }
        assert(ex.message!!.contains("encrypted", ignoreCase = true))
    }

    @Test
    fun parse_rejectsWrongMagic() {
        val blob = ByteArrayOutputStream().apply {
            write("wrong-magic\u0000....".toByteArray(Charsets.US_ASCII).copyOf(15))
            SSHWire.writeString(this, "none".toByteArray())
        }.toByteArray()
        val b64 = Base64.getEncoder().encodeToString(blob).chunked(70).joinToString("\n")
        val pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n$b64\n-----END OPENSSH PRIVATE KEY-----\n"
        assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(pem)
        }
    }

    // --- RSA cases ---

    @Test
    fun parse_validRSA_2048() {
        val priv = genRSAKey()
        val pem = buildRSAPEM(
            priv.modulus, priv.publicExponent, priv.exponent,
            priv.p, priv.q, priv.qInv, comment = "rsa@host"
        )
        val parsed = OpenSSHPrivateKey.parse(pem)
        assertTrue(parsed is OpenSSHPrivateKey.RSA)
        parsed as OpenSSHPrivateKey.RSA
        assertEquals(priv.modulus, parsed.n)
        assertEquals(priv.publicExponent, parsed.e)
        assertEquals(priv.exponent, parsed.d)
        assertEquals(priv.p, parsed.p)
        assertEquals(priv.q, parsed.q)
        assertEquals(priv.qInv, parsed.iqmp)
        assertEquals("rsa@host", parsed.comment)
    }

    @Test
    fun parse_rejectsRSA_pqMismatch_violatesInvariant() {
        val priv = genRSAKey()
        // Corrupt: use wrong q so p*q != n
        val badQ = priv.q.add(BigInteger.ONE)
        val pem = buildRSAPEM(
            priv.modulus, priv.publicExponent, priv.exponent,
            priv.p, badQ, priv.qInv
        )
        val ex = assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(pem)
        }
        assert(ex.message!!.contains("p*q != n"))
    }
}
