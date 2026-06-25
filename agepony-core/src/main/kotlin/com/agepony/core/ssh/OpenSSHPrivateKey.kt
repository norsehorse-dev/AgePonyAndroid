package com.agepony.core.ssh

import com.agepony.core.crypto.AESCTR
import com.agepony.core.crypto.BcryptPBKDF
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.Base64

/**
 * Parsed OpenSSH private key. Sealed hierarchy.
 *
 * Outer: PEM block with `-----BEGIN OPENSSH PRIVATE KEY-----` framing.
 *
 * `openssh-key-v1` blob layout:
 * ```
 * "openssh-key-v1\x00"
 * <len><cipherName>     # "none" unencrypted, "aes256-ctr" encrypted
 * <len><kdfName>        # "none" unencrypted, "bcrypt" encrypted
 * <len><kdfOpts>        # empty unencrypted; <len><salt><uint32 rounds> for bcrypt
 * <uint32 keyCount>     # always 1
 * <len><publicKeyBlob>
 * <len><privateSection> # AES-256-CTR-encrypted if cipherName != "none"
 * ```
 *
 * For encrypted PEMs:
 *   1. Read kdfOpts as `<len><salt(16B)><uint32 rounds>`.
 *   2. Derive 48 bytes via `BcryptPBKDF.derive(passphrase, salt, rounds, 48)`.
 *   3. key = bytes[0..32], iv = bytes[32..48].
 *   4. AES-CTR-decrypt the privateSection.
 *   5. Verify `check1 == check2` (wrong passphrase produces random bytes → mismatch).
 *   6. Parse the decrypted private section like an unencrypted one.
 */
sealed class OpenSSHPrivateKey {
    abstract val keyType: String
    abstract val comment: String?

    /** ssh-ed25519 private key. `privateKey` is the 32-byte seed. */
    class Ed25519(
        val publicKey: ByteArray,
        val privateKey: ByteArray,
        override val comment: String?,
    ) : OpenSSHPrivateKey() {
        override val keyType: String = KEYTYPE_ED25519

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Ed25519) return false
            return publicKey.contentEquals(other.publicKey)
                && privateKey.contentEquals(other.privateKey)
                && comment == other.comment
        }
        override fun hashCode(): Int {
            var h = publicKey.contentHashCode()
            h = 31 * h + privateKey.contentHashCode()
            h = 31 * h + (comment?.hashCode() ?: 0)
            return h
        }
        override fun toString(): String =
            "OpenSSHPrivateKey.Ed25519(publicKey=[${publicKey.size}B], " +
            "privateKey=[${privateKey.size}B], comment=$comment)"
    }

    /** ssh-rsa private key. */
    data class RSA(
        val n: BigInteger,
        val e: BigInteger,
        val d: BigInteger,
        val iqmp: BigInteger,
        val p: BigInteger,
        val q: BigInteger,
        override val comment: String?,
    ) : OpenSSHPrivateKey() {
        override val keyType: String = KEYTYPE_RSA
    }

    companion object {
        class OpenSSHPrivateKeyException(message: String) : Exception(message)

        const val BEGIN_MARKER = "-----BEGIN OPENSSH PRIVATE KEY-----"
        const val END_MARKER = "-----END OPENSSH PRIVATE KEY-----"
        private val MAGIC = "openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII)
        const val KEYTYPE_ED25519 = "ssh-ed25519"
        const val KEYTYPE_RSA = "ssh-rsa"
        const val CIPHER_NONE = "none"
        const val CIPHER_AES256_CTR = "aes256-ctr"
        const val KDF_NONE = "none"
        const val KDF_BCRYPT = "bcrypt"

        /**
         * Parse a PEM. If the PEM is encrypted (cipher != "none"), `passphrase` must be
         * provided. Throws if encrypted and `passphrase` is null, or if the passphrase
         * is wrong (detected via check1 != check2 after decryption).
         */
        fun parse(pem: String, passphrase: String? = null): OpenSSHPrivateKey {
            val normalized = pem.replace("\r\n", "\n").trim()
            val lines = normalized.split('\n').map { it.trimEnd() }
            if (lines.size < 3) throw OpenSSHPrivateKeyException("PEM too short")
            if (lines.first() != BEGIN_MARKER) throw OpenSSHPrivateKeyException(
                "missing BEGIN marker"
            )
            if (lines.last() != END_MARKER) throw OpenSSHPrivateKeyException(
                "missing END marker"
            )
            val b64 = lines.subList(1, lines.size - 1).joinToString("")
            val blob = try {
                Base64.getDecoder().decode(b64)
            } catch (e: IllegalArgumentException) {
                throw OpenSSHPrivateKeyException("invalid base64: ${e.message}")
            }

            val buf = SSHWire.wrapForRead(blob)

            if (buf.remaining() < MAGIC.size) throw OpenSSHPrivateKeyException(
                "blob too short for magic"
            )
            val magic = ByteArray(MAGIC.size)
            buf.get(magic)
            if (!magic.contentEquals(MAGIC)) throw OpenSSHPrivateKeyException(
                "wrong magic; expected 'openssh-key-v1\\0'"
            )

            val cipherName = readWireString(buf, "cipherName")
            val kdfName = readWireString(buf, "kdfName")
            val kdfOpts = readWireBytes(buf, "kdfOpts")

            val isEncrypted = cipherName != CIPHER_NONE
            if (isEncrypted) {
                if (passphrase == null) throw OpenSSHPrivateKeyException(
                    "encrypted PEM (cipher='$cipherName') but no passphrase provided"
                )
                if (cipherName != CIPHER_AES256_CTR) throw OpenSSHPrivateKeyException(
                    "unsupported cipher: '$cipherName' (only '$CIPHER_AES256_CTR' supported)"
                )
                if (kdfName != KDF_BCRYPT) throw OpenSSHPrivateKeyException(
                    "unsupported KDF: '$kdfName' (only '$KDF_BCRYPT' supported)"
                )
            } else {
                if (kdfName != KDF_NONE) throw OpenSSHPrivateKeyException(
                    "unencrypted PEM must have kdfName='none', got '$kdfName'"
                )
                if (kdfOpts.isNotEmpty()) throw OpenSSHPrivateKeyException(
                    "unencrypted PEM must have empty kdfOpts, got ${kdfOpts.size} bytes"
                )
            }

            val numKeys = try {
                SSHWire.readUInt32(buf)
            } catch (e: SSHWire.SSHWireException) {
                throw OpenSSHPrivateKeyException("missing keyCount: ${e.message}")
            }
            if (numKeys != 1) throw OpenSSHPrivateKeyException(
                "expected exactly 1 key, got $numKeys"
            )

            val pubKeyBlob = readWireBytes(buf, "pubKeyBlob")
            val pubBuf = SSHWire.wrapForRead(pubKeyBlob)
            val pubKeyType = readWireString(pubBuf, "outer pubKeyType")

            val privSectionRaw = readWireBytes(buf, "privateSection")

            // Decrypt if needed
            val privSection = if (isEncrypted) {
                decryptPrivateSection(kdfOpts, passphrase!!, privSectionRaw)
            } else {
                privSectionRaw
            }

            val privBuf = SSHWire.wrapForRead(privSection)

            // Use a local raw uint32 reader for check1/check2 rather than SSHWire.readUInt32,
            // because the latter is hardened against length-prefix attacks (rejects values
            // with the high bit set, since those would be ridiculous lengths). check1 and
            // check2 are arbitrary random uint32s and can be in the full [0, 2^32) range.
            val check1 = readRawUInt32(privBuf, "check1")
            val check2 = readRawUInt32(privBuf, "check2")
            if (check1 != check2) {
                if (isEncrypted) {
                    throw OpenSSHPrivateKeyException(
                        "check1/check2 mismatch after decryption ($check1 vs $check2); " +
                        "most likely cause: wrong passphrase"
                    )
                } else {
                    throw OpenSSHPrivateKeyException(
                        "check1/check2 mismatch ($check1 vs $check2); integrity failure"
                    )
                }
            }

            val privKeyType = readWireString(privBuf, "inner privKeyType")
            if (privKeyType != pubKeyType) throw OpenSSHPrivateKeyException(
                "outer keytype '$pubKeyType' doesn't match inner '$privKeyType'"
            )

            return when (privKeyType) {
                KEYTYPE_ED25519 -> parseEd25519Body(pubBuf, privBuf)
                KEYTYPE_RSA -> parseRSABody(pubBuf, privBuf)
                else -> throw OpenSSHPrivateKeyException(
                    "unsupported key type: '$privKeyType' " +
                    "(supported: ssh-ed25519, ssh-rsa)"
                )
            }
        }

        /**
         * Decrypt the AES-256-CTR-encrypted private section using a key+IV derived from
         * the passphrase via bcrypt_pbkdf.
         */
        private fun decryptPrivateSection(
            kdfOpts: ByteArray,
            passphrase: String,
            ciphertext: ByteArray,
        ): ByteArray {
            // kdfOpts = <len><salt> <uint32 rounds>
            val kdfBuf = SSHWire.wrapForRead(kdfOpts)
            val salt = readWireBytes(kdfBuf, "bcrypt salt")
            if (salt.isEmpty()) throw OpenSSHPrivateKeyException(
                "bcrypt salt must be non-empty"
            )
            val rounds = try {
                SSHWire.readUInt32(kdfBuf)
            } catch (e: SSHWire.SSHWireException) {
                throw OpenSSHPrivateKeyException("malformed bcrypt rounds: ${e.message}")
            }
            if (rounds < 1) throw OpenSSHPrivateKeyException(
                "bcrypt rounds must be >= 1, got $rounds"
            )
            if (kdfBuf.hasRemaining()) throw OpenSSHPrivateKeyException(
                "trailing bytes in kdfOpts: ${kdfBuf.remaining()}"
            )

            // Derive 48 bytes: 32-byte AES-256 key + 16-byte IV
            val derived = try {
                BcryptPBKDF.derive(
                    passphrase.toByteArray(Charsets.UTF_8),
                    salt,
                    rounds,
                    48
                )
            } catch (e: BcryptPBKDF.BcryptPBKDFException) {
                throw OpenSSHPrivateKeyException("bcrypt_pbkdf failed: ${e.message}")
            }
            val key = derived.copyOfRange(0, 32)
            val iv = derived.copyOfRange(32, 48)

            return try {
                AESCTR.decrypt(key, iv, ciphertext)
            } catch (e: AESCTR.AESCTRException) {
                throw OpenSSHPrivateKeyException("AES-CTR decrypt failed: ${e.message}")
            }
        }

        private fun parseEd25519Body(
            pubBuf: ByteBuffer,
            privBuf: ByteBuffer,
        ): Ed25519 {
            val outerPubKey = readWireBytes(pubBuf, "outer publicKey")
            if (outerPubKey.size != 32) throw OpenSSHPrivateKeyException(
                "ed25519 outer pubkey must be 32 bytes, got ${outerPubKey.size}"
            )

            val innerPubKey = readWireBytes(privBuf, "inner publicKey")
            if (innerPubKey.size != 32) throw OpenSSHPrivateKeyException(
                "ed25519 inner pubkey must be 32 bytes, got ${innerPubKey.size}"
            )
            if (!innerPubKey.contentEquals(outerPubKey)) throw OpenSSHPrivateKeyException(
                "inner pubkey doesn't match outer pubkey"
            )
            val privKey = readWireBytes(privBuf, "privateKey")
            if (privKey.size != 64) throw OpenSSHPrivateKeyException(
                "ed25519 private key must be 64 bytes (seed||pub), got ${privKey.size}"
            )
            val seed = privKey.copyOfRange(0, 32)
            val embeddedPub = privKey.copyOfRange(32, 64)
            if (!embeddedPub.contentEquals(outerPubKey)) throw OpenSSHPrivateKeyException(
                "embedded pubkey in private blob doesn't match"
            )
            val comment = readWireString(privBuf, "comment")
            return Ed25519(outerPubKey, seed, comment.ifEmpty { null })
        }

        private fun parseRSABody(
            pubBuf: ByteBuffer,
            privBuf: ByteBuffer,
        ): RSA {
            val outerE = readMPInt(pubBuf, "outer RSA exponent")
            val outerN = readMPInt(pubBuf, "outer RSA modulus")

            val n = readMPInt(privBuf, "inner RSA modulus n")
            val e = readMPInt(privBuf, "inner RSA exponent e")
            val d = readMPInt(privBuf, "inner RSA d")
            val iqmp = readMPInt(privBuf, "inner RSA iqmp")
            val p = readMPInt(privBuf, "inner RSA p")
            val q = readMPInt(privBuf, "inner RSA q")

            if (n != outerN) throw OpenSSHPrivateKeyException(
                "inner RSA modulus doesn't match outer"
            )
            if (e != outerE) throw OpenSSHPrivateKeyException(
                "inner RSA exponent doesn't match outer"
            )
            if (n.signum() <= 0 || e.signum() <= 0 || d.signum() <= 0
                || p.signum() <= 0 || q.signum() <= 0 || iqmp.signum() <= 0) {
                throw OpenSSHPrivateKeyException("RSA parameters must all be positive")
            }
            if (p.multiply(q) != n) throw OpenSSHPrivateKeyException(
                "RSA invariant violated: p*q != n"
            )

            val comment = readWireString(privBuf, "comment")
            return RSA(n, e, d, iqmp, p, q, comment.ifEmpty { null })
        }

        private fun readWireBytes(buf: ByteBuffer, field: String): ByteArray = try {
            SSHWire.readString(buf)
        } catch (e: SSHWire.SSHWireException) {
            throw OpenSSHPrivateKeyException("malformed $field: ${e.message}")
        }

        /**
         * Reads 4 big-endian bytes as a uint32 stored in an Int. Values >= 2^31 wrap to
         * negative Int values, which is fine — we only ever compare these for equality
         * (check1 == check2). Used in preference to `SSHWire.readUInt32` for fields where
         * the full uint32 range is legitimate (i.e., not length prefixes).
         */
        private fun readRawUInt32(buf: ByteBuffer, field: String): Int {
            if (buf.remaining() < 4) throw OpenSSHPrivateKeyException(
                "not enough bytes for $field (need 4, have ${buf.remaining()})"
            )
            val b0 = buf.get().toInt() and 0xff
            val b1 = buf.get().toInt() and 0xff
            val b2 = buf.get().toInt() and 0xff
            val b3 = buf.get().toInt() and 0xff
            return (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
        }

        private fun readWireString(buf: ByteBuffer, field: String): String =
            String(readWireBytes(buf, field), Charsets.US_ASCII)

        private fun readMPInt(buf: ByteBuffer, field: String): BigInteger = try {
            SSHMPInt.read(buf)
        } catch (e: SSHMPInt.SSHMPIntException) {
            throw OpenSSHPrivateKeyException("malformed $field: ${e.message}")
        }
    }
}
