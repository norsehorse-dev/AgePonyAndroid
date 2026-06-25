package com.agepony.core.ssh

import java.math.BigInteger
import java.util.Base64

/**
 * Parsed OpenSSH public key. Sealed hierarchy with one subtype per key algorithm.
 *
 * Input format (single line):
 *   `<keyType> <base64-of-wire-blob> [comment]`
 */
sealed class OpenSSHPublicKey {
    abstract val keyType: String
    abstract val comment: String?

    /**
     * ssh-ed25519 public key.
     * Wire blob: `<len><"ssh-ed25519"> <len><32-byte-pubkey>`.
     */
    class Ed25519(
        val publicKey: ByteArray,
        override val comment: String?,
    ) : OpenSSHPublicKey() {
        override val keyType: String = KEYTYPE_ED25519

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Ed25519) return false
            return publicKey.contentEquals(other.publicKey) && comment == other.comment
        }
        override fun hashCode(): Int {
            var h = publicKey.contentHashCode()
            h = 31 * h + (comment?.hashCode() ?: 0)
            return h
        }
        override fun toString(): String =
            "OpenSSHPublicKey.Ed25519(publicKey=[${publicKey.size}B], comment=$comment)"
    }

    /**
     * ssh-rsa public key.
     * Wire blob: `<len><"ssh-rsa"> <len><e (mpint)> <len><n (mpint)>`.
     */
    data class RSA(
        val modulus: BigInteger,
        val exponent: BigInteger,
        override val comment: String?,
    ) : OpenSSHPublicKey() {
        override val keyType: String = KEYTYPE_RSA
    }

    companion object {
        class OpenSSHPublicKeyException(message: String) : Exception(message)

        const val KEYTYPE_ED25519 = "ssh-ed25519"
        const val KEYTYPE_RSA = "ssh-rsa"

        fun parse(line: String): OpenSSHPublicKey {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) throw OpenSSHPublicKeyException("empty input")
            val parts = trimmed.split(Regex("\\s+"), limit = 3)
            if (parts.size < 2) throw OpenSSHPublicKeyException(
                "expected 'keytype base64 [comment]', got '$trimmed'"
            )
            val keyType = parts[0]
            val b64 = parts[1]
            val comment = if (parts.size > 2) parts[2] else null

            val blob = try {
                Base64.getDecoder().decode(b64)
            } catch (e: IllegalArgumentException) {
                throw OpenSSHPublicKeyException("invalid base64: ${e.message}")
            }

            val buf = SSHWire.wrapForRead(blob)
            val innerType = try {
                String(SSHWire.readString(buf), Charsets.US_ASCII)
            } catch (e: SSHWire.SSHWireException) {
                throw OpenSSHPublicKeyException("malformed wire blob: ${e.message}")
            }
            if (innerType != keyType) throw OpenSSHPublicKeyException(
                "inner keytype '$innerType' doesn't match outer '$keyType'"
            )

            return when (innerType) {
                KEYTYPE_ED25519 -> {
                    val pubKey = try {
                        SSHWire.readString(buf)
                    } catch (e: SSHWire.SSHWireException) {
                        throw OpenSSHPublicKeyException("malformed pubkey: ${e.message}")
                    }
                    if (pubKey.size != 32) throw OpenSSHPublicKeyException(
                        "ed25519 pubkey must be 32 bytes, got ${pubKey.size}"
                    )
                    if (buf.hasRemaining()) throw OpenSSHPublicKeyException(
                        "trailing bytes after pubkey: ${buf.remaining()}"
                    )
                    Ed25519(pubKey, comment)
                }
                KEYTYPE_RSA -> {
                    val e = try {
                        SSHMPInt.read(buf)
                    } catch (ex: SSHMPInt.SSHMPIntException) {
                        throw OpenSSHPublicKeyException("malformed RSA exponent: ${ex.message}")
                    }
                    val n = try {
                        SSHMPInt.read(buf)
                    } catch (ex: SSHMPInt.SSHMPIntException) {
                        throw OpenSSHPublicKeyException("malformed RSA modulus: ${ex.message}")
                    }
                    if (e.signum() <= 0) throw OpenSSHPublicKeyException(
                        "RSA exponent must be positive"
                    )
                    if (n.signum() <= 0) throw OpenSSHPublicKeyException(
                        "RSA modulus must be positive"
                    )
                    if (buf.hasRemaining()) throw OpenSSHPublicKeyException(
                        "trailing bytes after RSA key: ${buf.remaining()}"
                    )
                    RSA(n, e, comment)
                }
                else -> throw OpenSSHPublicKeyException(
                    "unsupported key type: '$innerType' " +
                    "(supported: ssh-ed25519, ssh-rsa)"
                )
            }
        }
    }
}
