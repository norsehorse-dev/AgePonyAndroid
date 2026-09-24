package com.agepony.core.ssh

import com.agepony.core.Stanza
import com.agepony.core.crypto.BcryptPBKDF
import com.agepony.core.crypto.RSAOAEP
import com.agepony.core.crypto.SHA256
import com.agepony.core.recipients.MIN_RSA_RECIPIENT_BITS
import com.agepony.core.recipients.SSHEd25519Recipient
import com.agepony.core.recipients.SSHRSAIdentity
import com.agepony.core.recipients.SSHRSARecipient
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64

/**
 * Negative tests for the SSH key parsers and conversions (audit L-4, L-10, and the key
 * consistency and redaction findings).
 */
class SSHKeyHardeningTests {
    private val rng = SecureRandom()

    // --- Builders (cipher=none unless kdf options are given) ---

    private fun blob(block: ByteArrayOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().apply(block).toByteArray()

    private fun pem(
        pubKeyBlob: ByteArray,
        privSection: ByteArray,
        cipher: String = "none",
        kdf: String = "none",
        kdfOpts: ByteArray = ByteArray(0),
    ): String {
        val outer = blob {
            write("openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII))
            SSHWire.writeString(this, cipher.toByteArray())
            SSHWire.writeString(this, kdf.toByteArray())
            SSHWire.writeString(this, kdfOpts)
            write(byteArrayOf(0, 0, 0, 1))
            SSHWire.writeString(this, pubKeyBlob)
            SSHWire.writeString(this, privSection)
        }
        val body = Base64.getEncoder().encodeToString(outer).chunked(70).joinToString("\n")
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n$body\n-----END OPENSSH PRIVATE KEY-----\n"
    }

    private fun ed25519Pem(seed: ByteArray, pub: ByteArray, padding: ((Int) -> ByteArray)? = null): String {
        val pubBlob = blob {
            SSHWire.writeString(this, "ssh-ed25519".toByteArray())
            SSHWire.writeString(this, pub)
        }
        val priv = blob {
            write(byteArrayOf(1, 2, 3, 4, 1, 2, 3, 4))
            SSHWire.writeString(this, "ssh-ed25519".toByteArray())
            SSHWire.writeString(this, pub)
            SSHWire.writeString(this, seed + pub)
            SSHWire.writeString(this, "c".toByteArray())
            val padLen = (8 - size() % 8) % 8
            write(padding?.invoke(padLen) ?: ByteArray(padLen) { (it + 1).toByte() })
        }
        return pem(pubBlob, priv)
    }

    private fun rsaPem(n: BigInteger, e: BigInteger, d: BigInteger, p: BigInteger, q: BigInteger, iqmp: BigInteger): String {
        val pubBlob = blob {
            SSHWire.writeString(this, "ssh-rsa".toByteArray())
            SSHMPInt.write(this, e)
            SSHMPInt.write(this, n)
        }
        val priv = blob {
            write(byteArrayOf(1, 2, 3, 4, 1, 2, 3, 4))
            SSHWire.writeString(this, "ssh-rsa".toByteArray())
            for (v in listOf(n, e, d, iqmp, p, q)) SSHMPInt.write(this, v)
            SSHWire.writeString(this, "c".toByteArray())
            val padLen = (8 - size() % 8) % 8
            for (i in 1..padLen) write(i)
        }
        return pem(pubBlob, priv)
    }

    private fun rsaKey(bits: Int): RSAPrivateCrtKeyParameters {
        val gen = RSAKeyPairGenerator()
        gen.init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), rng, bits, 80))
        return gen.generateKeyPair().private as RSAPrivateCrtKeyParameters
    }

    private fun seed() = ByteArray(32).also { rng.nextBytes(it) }
    private fun pubOf(seed: ByteArray) = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded

    // --- L-10: bcrypt_pbkdf cost caps ---

    private fun encryptedPem(rounds: Int, salt: ByteArray = ByteArray(16)): String {
        val s = seed()
        val pubBlob = blob {
            SSHWire.writeString(this, "ssh-ed25519".toByteArray())
            SSHWire.writeString(this, pubOf(s))
        }
        val kdfOpts = blob {
            SSHWire.writeString(this, salt)
            write(byteArrayOf((rounds ushr 24).toByte(), (rounds ushr 16).toByte(), (rounds ushr 8).toByte(), rounds.toByte()))
        }
        return pem(pubBlob, ByteArray(64), cipher = "aes256-ctr", kdf = "bcrypt", kdfOpts = kdfOpts)
    }

    @Test
    fun hugeBcryptRoundsAreRefusedBeforeAnyWork() {
        val started = System.nanoTime()
        for (rounds in listOf(Int.MAX_VALUE, 1_000_000, BcryptPBKDF.MAX_ROUNDS + 1)) {
            val e1 = assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
                OpenSSHPrivateKey.parse(encryptedPem(rounds), "pw")
            }
            assertTrue(e1.message!!.contains("rounds"), e1.message)
            val e2 = assertThrows(OpenSSHEncryptedKey.OpenSSHEncryptedKeyException::class.java) {
                OpenSSHEncryptedKey.decryptedPem(encryptedPem(rounds), "pw")
            }
            assertTrue(e2.message!!.contains("rounds"), e2.message)
        }
        assertTrue(System.nanoTime() - started < 5_000_000_000L, "refusal should not run the KDF")
        assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(encryptedPem(16, salt = ByteArray(BcryptPBKDF.MAX_SALT_LEN + 1)), "pw")
        }
        assertThrows(OpenSSHEncryptedKey.OpenSSHEncryptedKeyException::class.java) {
            OpenSSHEncryptedKey.decryptedPem(encryptedPem(16, salt = ByteArray(BcryptPBKDF.MAX_SALT_LEN + 1)), "pw")
        }
        assertThrows(BcryptPBKDF.BcryptPBKDFException::class.java) {
            BcryptPBKDF.derive("pw".toByteArray(), ByteArray(16), BcryptPBKDF.MAX_ROUNDS + 1, 48)
        }
        assertThrows(BcryptPBKDF.BcryptPBKDFException::class.java) {
            BcryptPBKDF.derive("pw".toByteArray(), ByteArray(16), 1, BcryptPBKDF.MAX_KEY_LEN + 1)
        }
        assertThrows(BcryptPBKDF.BcryptPBKDFException::class.java) {
            BcryptPBKDF.derive("pw".toByteArray(), ByteArray(BcryptPBKDF.MAX_SALT_LEN + 1), 1, 48)
        }
        assertEquals(1024, BcryptPBKDF.MAX_KEY_LEN)
    }

    // --- Private key consistency ---

    @Test
    fun validEd25519KeyStillParses() {
        val s = seed()
        val k = OpenSSHPrivateKey.parse(ed25519Pem(s, pubOf(s))) as OpenSSHPrivateKey.Ed25519
        assertArrayEquals(s, k.privateKey)
    }

    @Test
    fun ed25519SeedMustDeriveTheStoredPublicKey() {
        val e = assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(ed25519Pem(seed(), pubOf(seed())))
        }
        assertTrue(e.message!!.contains("seed"), e.message)
    }

    @Test
    fun paddingMustBeSequential() {
        val s = seed()
        // The comment "c" leaves padding bytes to write; make sure the case is exercised.
        assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(ed25519Pem(s, pubOf(s)) { n -> ByteArray(maxOf(n, 1)) })
        }
        assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(ed25519Pem(s, pubOf(s)) { n -> ByteArray(n + 8) { (it + 2).toByte() } })
        }
        // Extra whole blocks of correct padding are fine (OpenSSH only checks the sequence).
        OpenSSHPrivateKey.parse(ed25519Pem(s, pubOf(s)) { n -> ByteArray(n + 8) { (it + 1).toByte() } })
    }

    @Test
    fun rsaInvariantsAreChecked() {
        val k = rsaKey(2048)
        val good = OpenSSHPrivateKey.parse(rsaPem(k.modulus, k.publicExponent, k.exponent, k.p, k.q, k.qInv))
        assertTrue(good is OpenSSHPrivateKey.RSA)

        // d that does not invert e.
        val badD = k.exponent.add(BigInteger.TWO)
        assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(rsaPem(k.modulus, k.publicExponent, badD, k.p, k.q, k.qInv))
        }
        // p = 1, q = n satisfies p*q == n but is not a factorization.
        assertThrows(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException::class.java) {
            OpenSSHPrivateKey.parse(rsaPem(k.modulus, k.publicExponent, k.exponent, BigInteger.ONE, k.modulus, BigInteger.ONE))
        }
        // d taken mod phi(n) instead of lambda(n) is still a valid key.
        val phi = k.p.subtract(BigInteger.ONE).multiply(k.q.subtract(BigInteger.ONE))
        val dPhi = k.publicExponent.modInverse(phi)
        OpenSSHPrivateKey.parse(rsaPem(k.modulus, k.publicExponent, dPhi, k.p, k.q, k.qInv))
    }

    @Test
    fun rsaPrivateKeyToStringIsRedacted() {
        val k = rsaKey(1024)
        val parsed = OpenSSHPrivateKey.parse(rsaPem(k.modulus, k.publicExponent, k.exponent, k.p, k.q, k.qInv))
        val text = parsed.toString()
        for (secret in listOf(k.exponent, k.p, k.q, k.qInv)) {
            assertFalse(text.contains(secret.toString()), "toString leaks a private value")
            assertFalse(text.contains(secret.toString(16)), "toString leaks a private value")
        }
        assertTrue(text.contains("bits=1024"), text)
    }

    // --- L-4: RSA exponent and size ---

    private fun rsaPubLine(n: BigInteger, e: BigInteger): String {
        val wire = blob {
            SSHWire.writeString(this, "ssh-rsa".toByteArray())
            SSHMPInt.write(this, e)
            SSHMPInt.write(this, n)
        }
        return "ssh-rsa " + Base64.getEncoder().encodeToString(wire) + " test"
    }

    @Test
    fun rsaPublicExponentIsBounded() {
        val n = rsaKey(1024).modulus
        for (e in listOf(3L, 35L, 65537L, 0xFFFFFFFFL)) {
            OpenSSHPublicKey.parse(rsaPubLine(n, BigInteger.valueOf(e)))
        }
        for (e in listOf(BigInteger.ONE, BigInteger.valueOf(65536), BigInteger.ONE.shiftLeft(32).add(BigInteger.ONE),
                         BigInteger.ONE.shiftLeft(4096).add(BigInteger.ONE))) {
            assertThrows(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException::class.java, {
                OpenSSHPublicKey.parse(rsaPubLine(n, e))
            }, "exponent $e")
        }
    }

    @Test
    fun smallRsaRecipientsAreRefusedButSmallIdentitiesStillDecrypt() {
        val small = rsaKey(1024)
        val recipient = SSHRSARecipient(small.modulus, small.publicExponent)
        assertTrue(recipient.isBelowMinimumSize)
        val e = assertThrows(IllegalArgumentException::class.java) { recipient.wrap(ByteArray(16)) }
        assertTrue(e.message!!.contains("$MIN_RSA_RECIPIENT_BITS"), e.message)

        // A file made for the small key before this release (built here by hand, since the
        // encryptor now refuses) still opens with the matching identity.
        val fileKey = ByteArray(16).also { rng.nextBytes(it) }
        val wire = blob {
            SSHWire.writeString(this, "ssh-rsa".toByteArray())
            SSHMPInt.write(this, small.publicExponent)
            SSHMPInt.write(this, small.modulus)
        }
        val tag = SHA256.digest(wire).copyOfRange(0, 4)
        val body = RSAOAEP.encrypt(small.modulus, small.publicExponent, "age-encryption.org/v1/ssh-rsa".toByteArray(), fileKey)
        val stanza = Stanza("ssh-rsa", listOf(Stanza.base64NoPad(tag)), body)
        val identity = SSHRSAIdentity(small.modulus, small.publicExponent, small.exponent, small.p, small.q, small.qInv)
        assertArrayEquals(fileKey, identity.unwrap(stanza))

        val ok = rsaKey(2048)
        SSHRSARecipient(ok.modulus, ok.publicExponent).wrap(fileKey)

        // Go compares byte lengths: a 2041-bit modulus is 256 bytes and allowed, 2040 is not.
        assertFalse(SSHRSARecipient(BigInteger.ONE.shiftLeft(2040).add(BigInteger.ONE), BigInteger.valueOf(65537)).isBelowMinimumSize)
        assertTrue(SSHRSARecipient(BigInteger.ONE.shiftLeft(2039).add(BigInteger.ONE), BigInteger.valueOf(65537)).isBelowMinimumSize)
    }

    // --- Ed25519 -> X25519 conversion ---

    private val p25519: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

    private fun le32(v: BigInteger): ByteArray {
        val be = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        val out = ByteArray(32)
        for (i in be.indices) out[i] = be[be.size - 1 - i]
        return out
    }

    @Test
    fun invalidEd25519RecipientKeysFailCleanly() {
        val identityPoint = le32(BigInteger.ONE)                    // y = 1: 1 - y has no inverse
        val nonCanonical = le32(p25519.add(BigInteger.valueOf(2)))  // y >= p
        var offCurve: ByteArray? = null
        var y = 2L
        while (offCurve == null) {
            val enc = le32(BigInteger.valueOf(y++))
            if (!Ed25519.validatePublicKeyPartial(enc, 0)) offCurve = enc
        }
        for (bad in listOf(identityPoint, nonCanonical, offCurve!!, le32(BigInteger.ZERO), le32(p25519.subtract(BigInteger.ONE)))) {
            assertThrows(IllegalArgumentException::class.java) { Ed25519Conversion.publicKeyToX25519(bad) }
            assertThrows(IllegalArgumentException::class.java) { SSHEd25519Recipient(bad) }
        }
        // A real key still converts.
        Ed25519Conversion.publicKeyToX25519(pubOf(seed()))
    }
}
