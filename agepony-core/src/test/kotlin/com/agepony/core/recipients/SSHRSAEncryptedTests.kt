package com.agepony.core.recipients

import com.agepony.core.Age
import com.agepony.core.ssh.TestPEMBuilder
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Tests for `SSHRSAIdentity.fromPEM(pem, passphrase)`.
 *
 * Generates one shared 2048-bit RSA keypair (~100-500ms, amortized across all tests in
 * this class via `lazy`) and uses it to build encrypted PEMs.
 */
class SSHRSAEncryptedTests {
    private val testComment = "agepony@encrypted-rsa"
    private val testPassphrase = "rsa-test-pass"

    companion object {
        // 2048-bit RSA keypair shared across all tests in this class.
        // Lazy initialization runs once on first access.
        private val sharedKey: RSAPrivateCrtKeyParameters by lazy {
            val gen = RSAKeyPairGenerator()
            gen.init(
                RSAKeyGenerationParameters(
                    BigInteger.valueOf(65537),
                    SecureRandom(),
                    2048,
                    80,
                )
            )
            gen.generateKeyPair().private as RSAPrivateCrtKeyParameters
        }
    }

    @Test
    fun fromPEM_withPassphrase_returnsCorrectIdentity() {
        val k = sharedKey
        val pem = TestPEMBuilder.buildEncryptedRSAPEM(
            n = k.modulus,
            e = k.publicExponent,
            d = k.exponent,
            p = k.p,
            q = k.q,
            iqmp = k.qInv,
            comment = testComment,
            passphrase = testPassphrase,
        )
        val identity = SSHRSAIdentity.fromPEM(pem, testPassphrase)
        assertEquals(k.modulus, identity.n)
        assertEquals(k.publicExponent, identity.e)
        assertEquals(k.exponent, identity.d)
        assertEquals(k.p, identity.p)
        assertEquals(k.q, identity.q)
        assertEquals(k.qInv, identity.iqmp)
    }

    @Test
    fun fromPEM_withWrongPassphrase_throws() {
        val k = sharedKey
        val pem = TestPEMBuilder.buildEncryptedRSAPEM(
            n = k.modulus, e = k.publicExponent, d = k.exponent,
            p = k.p, q = k.q, iqmp = k.qInv,
            comment = testComment,
            passphrase = testPassphrase,
        )
        assertThrows(Exception::class.java) {
            SSHRSAIdentity.fromPEM(pem, "nope-wrong-pass")
        }
    }

    @Test
    fun fromPEM_endToEndDecrypts_throughAge() {
        val k = sharedKey
        val pem = TestPEMBuilder.buildEncryptedRSAPEM(
            n = k.modulus, e = k.publicExponent, d = k.exponent,
            p = k.p, q = k.q, iqmp = k.qInv,
            comment = testComment,
            passphrase = testPassphrase,
        )
        val identity = SSHRSAIdentity.fromPEM(pem, testPassphrase)
        val recipient = SSHRSARecipient(identity.n, identity.e)

        val plaintext = "hello from encrypted RSA PEM".toByteArray(Charsets.UTF_8)
        val ciphertext = Age.encrypt(plaintext, listOf(recipient))
        val decrypted = Age.decrypt(ciphertext, listOf(identity))

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun fromPEM_withoutPassphrase_throwsOnEncryptedPEM() {
        val k = sharedKey
        val pem = TestPEMBuilder.buildEncryptedRSAPEM(
            n = k.modulus, e = k.publicExponent, d = k.exponent,
            p = k.p, q = k.q, iqmp = k.qInv,
            comment = testComment,
            passphrase = testPassphrase,
        )
        assertThrows(Exception::class.java) {
            SSHRSAIdentity.fromPEM(pem)
        }
    }
}
