package com.agepony.core.ssh

import com.agepony.core.crypto.AESCTR
import com.agepony.core.crypto.BcryptPBKDF
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.util.Base64

/**
 * Test-only helpers for constructing OpenSSH-format passphrase-encrypted PEMs.
 *
 * Lives in the test source tree, not production. Used by `OpenSSHPrivateKeyEncryptedTests`,
 * `SSHEd25519EncryptedTests`, and `SSHRSAEncryptedTests` to round-trip encrypted PEMs
 * through `OpenSSHPrivateKey.parse` and the identity-level `fromPEM` factories.
 */
object TestPEMBuilder {

    /**
     * Builds an encrypted ed25519 PEM with the given seed and passphrase.
     * Returns Pair<pemString, expectedPubKey>.
     */
    fun buildEncryptedEd25519PEM(
        seed: ByteArray,
        comment: String,
        passphrase: String,
        cipherName: String = "aes256-ctr",
        kdfName: String = "bcrypt",
        rounds: Int = 16,
        salt: ByteArray = ByteArray(16) { (it * 3 + 1).toByte() },
    ): Pair<String, ByteArray> {
        require(seed.size == 32)
        require(salt.size == 16)

        val edPriv = Ed25519PrivateKeyParameters(seed, 0)
        val pubKey = edPriv.generatePublicKey().encoded

        val pubKeyBlob = ByteArrayOutputStream().run {
            writeSSHString(this, "ssh-ed25519".toByteArray(Charsets.US_ASCII))
            writeSSHString(this, pubKey)
            toByteArray()
        }

        val privSection = ByteArrayOutputStream().apply {
            val check = 0xdeadbeef.toInt()
            writeUInt32BE(this, check)
            writeUInt32BE(this, check)
            writeSSHString(this, "ssh-ed25519".toByteArray(Charsets.US_ASCII))
            writeSSHString(this, pubKey)
            writeSSHString(this, seed + pubKey)
            writeSSHString(this, comment.toByteArray(Charsets.US_ASCII))
            padToBlockSize(this)
        }.toByteArray()

        val encryptedPrivSection = encryptPrivSection(passphrase, salt, rounds, privSection)
        val outerBlob = assembleOuterBlob(
            cipherName, kdfName, salt, rounds, pubKeyBlob, encryptedPrivSection
        )
        return pemEncode(outerBlob) to pubKey
    }

    /**
     * Builds an encrypted ssh-rsa PEM from CRT parameters.
     */
    fun buildEncryptedRSAPEM(
        n: BigInteger,
        e: BigInteger,
        d: BigInteger,
        p: BigInteger,
        q: BigInteger,
        iqmp: BigInteger,
        comment: String,
        passphrase: String,
        rounds: Int = 16,
        salt: ByteArray = ByteArray(16) { (it * 5 + 2).toByte() },
    ): String {
        require(salt.size == 16)

        // Public-key blob: <"ssh-rsa"><e><n>  (note: e BEFORE n in pubkey)
        val pubKeyBlob = ByteArrayOutputStream().run {
            writeSSHString(this, "ssh-rsa".toByteArray(Charsets.US_ASCII))
            writeMPInt(this, e)
            writeMPInt(this, n)
            toByteArray()
        }

        // Private section: <check1><check2><"ssh-rsa"><n><e><d><iqmp><p><q><comment><pad>
        // Note: in the private section, n comes BEFORE e (opposite of pubkey).
        val privSection = ByteArrayOutputStream().apply {
            val check = 0xcafebabe.toInt()
            writeUInt32BE(this, check)
            writeUInt32BE(this, check)
            writeSSHString(this, "ssh-rsa".toByteArray(Charsets.US_ASCII))
            writeMPInt(this, n)
            writeMPInt(this, e)
            writeMPInt(this, d)
            writeMPInt(this, iqmp)
            writeMPInt(this, p)
            writeMPInt(this, q)
            writeSSHString(this, comment.toByteArray(Charsets.US_ASCII))
            padToBlockSize(this)
        }.toByteArray()

        val encryptedPrivSection = encryptPrivSection(passphrase, salt, rounds, privSection)
        val outerBlob = assembleOuterBlob(
            "aes256-ctr", "bcrypt", salt, rounds, pubKeyBlob, encryptedPrivSection
        )
        return pemEncode(outerBlob)
    }

    // ----- shared internals -------------------------------------------------------

    private fun encryptPrivSection(
        passphrase: String,
        salt: ByteArray,
        rounds: Int,
        privSection: ByteArray,
    ): ByteArray {
        val derived = BcryptPBKDF.derive(
            passphrase.toByteArray(Charsets.UTF_8),
            salt, rounds, 48
        )
        val aesKey = derived.copyOfRange(0, 32)
        val iv = derived.copyOfRange(32, 48)
        return AESCTR.encrypt(aesKey, iv, privSection)
    }

    private fun assembleOuterBlob(
        cipherName: String,
        kdfName: String,
        salt: ByteArray,
        rounds: Int,
        pubKeyBlob: ByteArray,
        encryptedPrivSection: ByteArray,
    ): ByteArray {
        val kdfOpts = ByteArrayOutputStream().run {
            writeSSHString(this, salt)
            writeUInt32BE(this, rounds)
            toByteArray()
        }
        return ByteArrayOutputStream().run {
            write("openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII))
            writeSSHString(this, cipherName.toByteArray(Charsets.US_ASCII))
            writeSSHString(this, kdfName.toByteArray(Charsets.US_ASCII))
            writeSSHString(this, kdfOpts)
            writeUInt32BE(this, 1) // numKeys
            writeSSHString(this, pubKeyBlob)
            writeSSHString(this, encryptedPrivSection)
            toByteArray()
        }
    }

    private fun pemEncode(blob: ByteArray): String {
        val b64 = Base64.getEncoder().encodeToString(blob)
        return buildString {
            appendLine("-----BEGIN OPENSSH PRIVATE KEY-----")
            b64.chunked(70).forEach { appendLine(it) }
            append("-----END OPENSSH PRIVATE KEY-----")
        }
    }

    private fun padToBlockSize(out: ByteArrayOutputStream) {
        val mod = out.size() % 16
        if (mod != 0) {
            val padLen = 16 - mod
            for (i in 1..padLen) out.write(i)
        }
    }

    private fun writeUInt32BE(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 24) and 0xff)
        out.write((v ushr 16) and 0xff)
        out.write((v ushr 8) and 0xff)
        out.write(v and 0xff)
    }

    private fun writeSSHString(out: ByteArrayOutputStream, bytes: ByteArray) {
        writeUInt32BE(out, bytes.size)
        out.write(bytes)
    }

    private fun writeMPInt(out: ByteArrayOutputStream, value: BigInteger) {
        if (value.signum() == 0) {
            writeUInt32BE(out, 0)
            return
        }
        val bytes = value.toByteArray() // BigInteger gives big-endian with sign byte if high bit set
        writeUInt32BE(out, bytes.size)
        out.write(bytes)
    }
}
