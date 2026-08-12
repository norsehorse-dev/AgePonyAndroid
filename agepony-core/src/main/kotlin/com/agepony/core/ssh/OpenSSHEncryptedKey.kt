package com.agepony.core.ssh

import com.agepony.core.crypto.AESCTR
import com.agepony.core.crypto.BcryptPBKDF
import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * Normalizes an OpenSSH private-key PEM to its unencrypted form.
 *
 * Android counterpart of iOS `OpenSSHEncryptedKey.decryptedPEM`: the encrypted private
 * section is decrypted once and re-wrapped in a `cipher=none, kdf=none` envelope,
 * producing a PEM that [OpenSSHPrivateKey.parse] (and OpenSSH itself) reads without a
 * passphrase. This is the PEM re-serializer the RSA identity storage was waiting on
 * (see the deferral note in the app's Hydration.kt): the vault stores exactly this
 * normalized PEM, so decrypt and signing paths never need the import passphrase again.
 *
 * An already-unencrypted PEM round-trips: the same sections are re-encoded, which also
 * normalizes line endings and base64 wrapping. The decrypted private section is reused
 * verbatim, padding included; its sequential padding bytes remain valid because the
 * unencrypted block size (8) divides the encrypted one (16).
 *
 * The envelope layout being read and rewritten here is documented on
 * [OpenSSHPrivateKey]; the outer decode below deliberately mirrors that parser (as the
 * iOS twin mirrors its own) rather than sharing internals, so each stays readable on
 * its own.
 */
object OpenSSHEncryptedKey {
    class OpenSSHEncryptedKeyException(message: String) : Exception(message)

    private val MAGIC = "openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII)
    private const val PEM_LINE_LENGTH = 70

    /**
     * Return [pem] with any passphrase protection removed, as a normalized
     * `cipher=none, kdf=none` OpenSSH PEM (LF line endings, trailing newline).
     *
     * If [pem] is encrypted, [passphrase] is required and verified: the result is fully
     * parsed before being returned, so a wrong passphrase throws here rather than
     * producing a garbage PEM. If [pem] is unencrypted, [passphrase] is ignored.
     */
    fun decryptedPem(pem: String, passphrase: String? = null): String {
        val normalized = pem.replace("\r\n", "\n").trim()
        val lines = normalized.split('\n').map { it.trimEnd() }
        if (lines.size < 3) throw OpenSSHEncryptedKeyException("PEM too short")
        if (lines.first() != OpenSSHPrivateKey.BEGIN_MARKER) {
            throw OpenSSHEncryptedKeyException("missing BEGIN marker")
        }
        if (lines.last() != OpenSSHPrivateKey.END_MARKER) {
            throw OpenSSHEncryptedKeyException("missing END marker")
        }
        val blob = try {
            Base64.getDecoder().decode(lines.subList(1, lines.size - 1).joinToString(""))
        } catch (e: IllegalArgumentException) {
            throw OpenSSHEncryptedKeyException("invalid base64: ${e.message}")
        }

        val buf = SSHWire.wrapForRead(blob)
        if (buf.remaining() < MAGIC.size) {
            throw OpenSSHEncryptedKeyException("blob too short for magic")
        }
        val magic = ByteArray(MAGIC.size)
        buf.get(magic)
        if (!magic.contentEquals(MAGIC)) {
            throw OpenSSHEncryptedKeyException("wrong magic; expected 'openssh-key-v1\\0'")
        }

        val cipherName = readString(buf, "cipherName")
        val kdfName = readString(buf, "kdfName")
        val kdfOpts = readBytes(buf, "kdfOpts")

        val isEncrypted = cipherName != OpenSSHPrivateKey.CIPHER_NONE
        if (isEncrypted) {
            if (passphrase == null) throw OpenSSHEncryptedKeyException(
                "encrypted PEM (cipher='$cipherName') but no passphrase provided"
            )
            if (cipherName != OpenSSHPrivateKey.CIPHER_AES256_CTR) {
                throw OpenSSHEncryptedKeyException(
                    "unsupported cipher: '$cipherName' " +
                    "(only '${OpenSSHPrivateKey.CIPHER_AES256_CTR}' supported)"
                )
            }
            if (kdfName != OpenSSHPrivateKey.KDF_BCRYPT) {
                throw OpenSSHEncryptedKeyException(
                    "unsupported KDF: '$kdfName' " +
                    "(only '${OpenSSHPrivateKey.KDF_BCRYPT}' supported)"
                )
            }
        } else {
            if (kdfName != OpenSSHPrivateKey.KDF_NONE) throw OpenSSHEncryptedKeyException(
                "unencrypted PEM must have kdfName='none', got '$kdfName'"
            )
            if (kdfOpts.isNotEmpty()) throw OpenSSHEncryptedKeyException(
                "unencrypted PEM must have empty kdfOpts, got ${kdfOpts.size} bytes"
            )
        }

        val numKeys = try {
            SSHWire.readUInt32(buf)
        } catch (e: SSHWire.SSHWireException) {
            throw OpenSSHEncryptedKeyException("missing keyCount: ${e.message}")
        }
        if (numKeys != 1) throw OpenSSHEncryptedKeyException(
            "expected exactly 1 key, got $numKeys"
        )

        val pubKeyBlob = readBytes(buf, "pubKeyBlob")
        val privSectionRaw = readBytes(buf, "privateSection")

        val privSection = if (isEncrypted) {
            decryptPrivateSection(kdfOpts, passphrase!!, privSectionRaw)
        } else {
            privSectionRaw
        }

        val synthesized = synthesizeUnencryptedPem(pubKeyBlob, privSection)

        // Full validation before handing the PEM back: field structure, check1/check2,
        // key-type invariants. A wrong passphrase decrypts to noise and fails here.
        try {
            OpenSSHPrivateKey.parse(synthesized)
        } catch (e: OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException) {
            if (isEncrypted && (e.message ?: "").contains("check1/check2")) {
                throw OpenSSHEncryptedKeyException(
                    "wrong passphrase (check1/check2 mismatch after decryption)"
                )
            }
            throw OpenSSHEncryptedKeyException(
                "decrypted key failed to parse: ${e.message}"
            )
        }
        return synthesized
    }

    /** Wrap public blob + (decrypted) private section in a cipher=none envelope. */
    private fun synthesizeUnencryptedPem(
        pubKeyBlob: ByteArray,
        privSection: ByteArray,
    ): String {
        val out = ByteArrayOutputStream()
        out.write(MAGIC)
        SSHWire.writeString(out, OpenSSHPrivateKey.CIPHER_NONE.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, OpenSSHPrivateKey.KDF_NONE.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, ByteArray(0))
        out.write(byteArrayOf(0, 0, 0, 1))
        SSHWire.writeString(out, pubKeyBlob)
        SSHWire.writeString(out, privSection)
        val body = Base64.getEncoder().encodeToString(out.toByteArray())
            .chunked(PEM_LINE_LENGTH)
            .joinToString("\n")
        return "${OpenSSHPrivateKey.BEGIN_MARKER}\n$body\n${OpenSSHPrivateKey.END_MARKER}\n"
    }

    /** Same derivation as OpenSSHPrivateKey's private decrypt path. */
    private fun decryptPrivateSection(
        kdfOpts: ByteArray,
        passphrase: String,
        ciphertext: ByteArray,
    ): ByteArray {
        val kdfBuf = SSHWire.wrapForRead(kdfOpts)
        val salt = readBytes(kdfBuf, "bcrypt salt")
        if (salt.isEmpty()) throw OpenSSHEncryptedKeyException("bcrypt salt must be non-empty")
        val rounds = try {
            SSHWire.readUInt32(kdfBuf)
        } catch (e: SSHWire.SSHWireException) {
            throw OpenSSHEncryptedKeyException("malformed bcrypt rounds: ${e.message}")
        }
        if (rounds < 1) throw OpenSSHEncryptedKeyException(
            "bcrypt rounds must be >= 1, got $rounds"
        )
        if (kdfBuf.hasRemaining()) throw OpenSSHEncryptedKeyException(
            "trailing bytes in kdfOpts: ${kdfBuf.remaining()}"
        )

        val derived = try {
            BcryptPBKDF.derive(passphrase.toByteArray(Charsets.UTF_8), salt, rounds, 48)
        } catch (e: BcryptPBKDF.BcryptPBKDFException) {
            throw OpenSSHEncryptedKeyException("bcrypt_pbkdf failed: ${e.message}")
        }
        val key = derived.copyOfRange(0, 32)
        val iv = derived.copyOfRange(32, 48)

        return try {
            AESCTR.decrypt(key, iv, ciphertext)
        } catch (e: AESCTR.AESCTRException) {
            throw OpenSSHEncryptedKeyException("AES-CTR decrypt failed: ${e.message}")
        }
    }

    private fun readBytes(buf: java.nio.ByteBuffer, field: String): ByteArray = try {
        SSHWire.readString(buf)
    } catch (e: SSHWire.SSHWireException) {
        throw OpenSSHEncryptedKeyException("malformed $field: ${e.message}")
    }

    private fun readString(buf: java.nio.ByteBuffer, field: String): String =
        String(readBytes(buf, field), Charsets.US_ASCII)
}
