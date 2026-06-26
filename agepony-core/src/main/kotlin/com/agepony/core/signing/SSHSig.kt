package com.agepony.core.signing

import com.agepony.core.crypto.SHA256
import com.agepony.core.ssh.SSHMPInt
import com.agepony.core.ssh.SSHWire
import org.bouncycastle.crypto.digests.SHA512Digest
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.Base64

/**
 * SSHSIG format (OpenSSH PROTOCOL.sshsig) primitives: signed-data construction, the
 * public-key and inner-signature wire builders/parsers for every algorithm AgePony
 * signs with, and the full-blob encode/decode plus ASCII armor.
 *
 * This object holds no private keys and performs no signing or verification; it is the
 * pure format layer. [SSHSigner] produces signatures, [SSHSigVerifier] checks them.
 *
 * Full SSHSIG blob:
 * ```
 * byte[6]   "SSHSIG"
 * uint32    SIG_VERSION (= 1)
 * string    publickey
 * string    namespace
 * string    reserved (empty)
 * string    hash_algorithm
 * string    signature
 * ```
 *
 * signed-data (the bytes a signature algorithm covers, except the sk variants, which
 * wrap this further per the FIDO authenticator data model):
 * ```
 * byte[6]   "SSHSIG"
 * string    namespace
 * string    reserved (empty)
 * string    hash_algorithm
 * string    H(message)
 * ```
 *
 * Armor:
 * ```
 * -----BEGIN SSH SIGNATURE-----
 * <standard padded base64, wrapped at 76 columns>
 * -----END SSH SIGNATURE-----
 * ```
 */
object SSHSig {
    class SSHSigFormatException(message: String) : Exception(message)

    // --- Envelope constants ---

    val MAGIC: ByteArray = "SSHSIG".toByteArray(Charsets.US_ASCII)
    const val SIG_VERSION: Int = 1

    /** AgePony's SSHSIG namespace. Detached file signatures use this. */
    const val NAMESPACE_AGEPONY: String = "agepony"

    const val HASH_SHA512: String = "sha512"
    const val HASH_SHA256: String = "sha256"

    const val ARMOR_BEGIN: String = "-----BEGIN SSH SIGNATURE-----"
    const val ARMOR_END: String = "-----END SSH SIGNATURE-----"
    private const val ARMOR_LINE_WIDTH: Int = 76

    /** Default FIDO application string OpenSSH stamps on security-key credentials. */
    const val SK_APPLICATION_DEFAULT: String = "ssh:"

    // --- Algorithm / key-type names (the leading wire string of each blob) ---

    const val KEY_ED25519: String = "ssh-ed25519"
    const val KEY_RSA: String = "ssh-rsa"
    const val KEY_ECDSA_P256: String = "ecdsa-sha2-nistp256"
    const val KEY_SK_ED25519: String = "sk-ssh-ed25519@openssh.com"
    const val KEY_SK_ECDSA_P256: String = "sk-ecdsa-sha2-nistp256@openssh.com"

    const val SIG_ED25519: String = "ssh-ed25519"
    const val SIG_RSA_SHA512: String = "rsa-sha2-512"
    const val SIG_ECDSA_P256: String = "ecdsa-sha2-nistp256"
    const val SIG_SK_ED25519: String = "sk-ssh-ed25519@openssh.com"
    const val SIG_SK_ECDSA_P256: String = "sk-ecdsa-sha2-nistp256@openssh.com"

    /** ECDSA P-256 curve identifier inside ecdsa key/signature blobs. */
    const val ECDSA_CURVE_P256: String = "nistp256"

    // --- Message hashing ---

    /** Hash a message with the named SSHSIG hash algorithm. */
    fun hashMessage(message: ByteArray, hashAlg: String = HASH_SHA512): ByteArray =
        when (hashAlg) {
            HASH_SHA512 -> sha512(message)
            HASH_SHA256 -> SHA256.digest(message)
            else -> throw SSHSigFormatException("unsupported hash algorithm: '$hashAlg'")
        }

    /**
     * Build the signed-data blob the signature algorithm covers. [messageHash] is the
     * output of [hashMessage] over the original message.
     */
    fun signedData(
        namespace: String,
        hashAlg: String,
        messageHash: ByteArray,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(MAGIC)
        SSHWire.writeString(out, namespace.toByteArray(Charsets.UTF_8))
        SSHWire.writeString(out, ByteArray(0))
        SSHWire.writeString(out, hashAlg.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, messageHash)
        return out.toByteArray()
    }

    // --- Public-key wire builders ---

    fun ed25519PublicWire(publicKey32: ByteArray): ByteArray {
        require(publicKey32.size == 32) { "ed25519 public key must be 32 bytes" }
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, KEY_ED25519.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, publicKey32)
        return out.toByteArray()
    }

    fun rsaPublicWire(exponent: BigInteger, modulus: BigInteger): ByteArray {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, KEY_RSA.toByteArray(Charsets.US_ASCII))
        SSHMPInt.write(out, exponent)
        SSHMPInt.write(out, modulus)
        return out.toByteArray()
    }

    /** [q] is the uncompressed EC point `0x04 || x(32) || y(32)`. */
    fun ecdsaP256PublicWire(q: ByteArray): ByteArray {
        require(q.size == 65 && q[0] == 0x04.toByte()) {
            "ecdsa P-256 point must be 65 bytes uncompressed (0x04 || x || y)"
        }
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, KEY_ECDSA_P256.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, ECDSA_CURVE_P256.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, q)
        return out.toByteArray()
    }

    fun skEd25519PublicWire(
        publicKey32: ByteArray,
        application: String = SK_APPLICATION_DEFAULT,
    ): ByteArray {
        require(publicKey32.size == 32) { "ed25519 public key must be 32 bytes" }
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, KEY_SK_ED25519.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, publicKey32)
        SSHWire.writeString(out, application.toByteArray(Charsets.UTF_8))
        return out.toByteArray()
    }

    fun skEcdsaP256PublicWire(
        q: ByteArray,
        application: String = SK_APPLICATION_DEFAULT,
    ): ByteArray {
        require(q.size == 65 && q[0] == 0x04.toByte()) {
            "ecdsa P-256 point must be 65 bytes uncompressed (0x04 || x || y)"
        }
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, KEY_SK_ECDSA_P256.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, ECDSA_CURVE_P256.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, q)
        SSHWire.writeString(out, application.toByteArray(Charsets.UTF_8))
        return out.toByteArray()
    }

    // --- Inner-signature wire builders ---

    fun ed25519SigWire(signature64: ByteArray): ByteArray {
        require(signature64.size == 64) { "ed25519 signature must be 64 bytes" }
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, SIG_ED25519.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, signature64)
        return out.toByteArray()
    }

    fun rsaSha512SigWire(signature: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, SIG_RSA_SHA512.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, signature)
        return out.toByteArray()
    }

    fun ecdsaSigWire(r: BigInteger, s: BigInteger): ByteArray {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, SIG_ECDSA_P256.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, ecdsaRawSigBlob(r, s))
        return out.toByteArray()
    }

    fun skEd25519SigWire(signature64: ByteArray, flags: Int, counter: Int): ByteArray {
        require(signature64.size == 64) { "ed25519 signature must be 64 bytes" }
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, SIG_SK_ED25519.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, signature64)
        out.write(flags and 0xff)
        writeUInt32(out, counter)
        return out.toByteArray()
    }

    fun skEcdsaSigWire(r: BigInteger, s: BigInteger, flags: Int, counter: Int): ByteArray {
        val out = ByteArrayOutputStream()
        SSHWire.writeString(out, SIG_SK_ECDSA_P256.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, ecdsaRawSigBlob(r, s))
        out.write(flags and 0xff)
        writeUInt32(out, counter)
        return out.toByteArray()
    }

    /** Inner ecdsa signature payload: `mpint r || mpint s`. */
    private fun ecdsaRawSigBlob(r: BigInteger, s: BigInteger): ByteArray {
        val out = ByteArrayOutputStream()
        SSHMPInt.write(out, r)
        SSHMPInt.write(out, s)
        return out.toByteArray()
    }

    // --- Full-blob encode / decode ---

    /** A decoded SSHSIG envelope. The two blobs stay in wire form for the verifier. */
    class Decoded(
        val version: Int,
        val publicKeyBlob: ByteArray,
        val namespace: String,
        val reserved: ByteArray,
        val hashAlgorithm: String,
        val signatureBlob: ByteArray,
    ) {
        /** The leading wire string of [publicKeyBlob]: the signer key type. */
        val keyType: String get() = readLeadingString(publicKeyBlob)

        /** The leading wire string of [signatureBlob]: the signature algorithm name. */
        val signatureType: String get() = readLeadingString(signatureBlob)
    }

    fun encode(
        publicKeyBlob: ByteArray,
        namespace: String,
        hashAlg: String,
        signatureBlob: ByteArray,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(MAGIC)
        writeUInt32(out, SIG_VERSION)
        SSHWire.writeString(out, publicKeyBlob)
        SSHWire.writeString(out, namespace.toByteArray(Charsets.UTF_8))
        SSHWire.writeString(out, ByteArray(0))
        SSHWire.writeString(out, hashAlg.toByteArray(Charsets.US_ASCII))
        SSHWire.writeString(out, signatureBlob)
        return out.toByteArray()
    }

    fun decode(blob: ByteArray): Decoded {
        if (blob.size < MAGIC.size) throw SSHSigFormatException("blob too short for magic")
        val magic = blob.copyOfRange(0, MAGIC.size)
        if (!magic.contentEquals(MAGIC)) throw SSHSigFormatException(
            "wrong magic; expected 'SSHSIG'"
        )
        val buf = SSHWire.wrapForRead(blob.copyOfRange(MAGIC.size, blob.size))
        val version = try {
            readRawUInt32(buf)
        } catch (e: SSHSigFormatException) {
            throw SSHSigFormatException("missing version: ${e.message}")
        }
        if (version != SIG_VERSION) throw SSHSigFormatException(
            "unsupported SSHSIG version: $version (expected $SIG_VERSION)"
        )
        val publicKeyBlob = readString(buf, "publickey")
        val namespace = String(readString(buf, "namespace"), Charsets.UTF_8)
        val reserved = readString(buf, "reserved")
        val hashAlg = String(readString(buf, "hash_algorithm"), Charsets.US_ASCII)
        val signatureBlob = readString(buf, "signature")
        if (buf.hasRemaining()) throw SSHSigFormatException(
            "trailing bytes after signature: ${buf.remaining()}"
        )
        return Decoded(version, publicKeyBlob, namespace, reserved, hashAlg, signatureBlob)
    }

    // --- Armor ---

    fun armor(blob: ByteArray): String {
        val b64 = Base64.getEncoder().encodeToString(blob)
        val sb = StringBuilder()
        sb.append(ARMOR_BEGIN).append('\n')
        var i = 0
        while (i < b64.length) {
            val end = minOf(i + ARMOR_LINE_WIDTH, b64.length)
            sb.append(b64, i, end).append('\n')
            i = end
        }
        sb.append(ARMOR_END).append('\n')
        return sb.toString()
    }

    fun dearmor(armored: String): ByteArray {
        val normalized = armored.replace("\r\n", "\n").trim()
        val lines = normalized.split('\n').map { it.trim() }
        if (lines.size < 2) throw SSHSigFormatException("armor too short")
        if (lines.first() != ARMOR_BEGIN) throw SSHSigFormatException("missing BEGIN marker")
        if (lines.last() != ARMOR_END) throw SSHSigFormatException("missing END marker")
        val body = if (lines.size > 2) lines.subList(1, lines.size - 1).joinToString("") else ""
        if (body.isEmpty()) throw SSHSigFormatException("empty armor body")
        return try {
            Base64.getDecoder().decode(body)
        } catch (e: IllegalArgumentException) {
            throw SSHSigFormatException("invalid base64 in armor body: ${e.message}")
        }
    }

    /** Accept either an armored signature or a raw blob and return the raw blob. */
    fun decodeArmoredOrRaw(input: ByteArray): ByteArray {
        val looksArmored = input.size >= ARMOR_BEGIN.length &&
            String(input.copyOfRange(0, ARMOR_BEGIN.length), Charsets.US_ASCII) == ARMOR_BEGIN
        return if (looksArmored) dearmor(String(input, Charsets.US_ASCII)) else input
    }

    // --- Parsing helpers exposed to the verifier ---

    /** Read the leading wire string of a blob (key type or signature type). */
    fun readLeadingString(blob: ByteArray): String {
        val buf = SSHWire.wrapForRead(blob)
        return String(readString(buf, "leading type"), Charsets.US_ASCII)
    }

    /** Wrap a blob for sequential wire reads. */
    fun reader(blob: ByteArray): ByteBuffer = SSHWire.wrapForRead(blob)

    /** Read a length-prefixed string, re-wrapping the wire exception as a format error. */
    fun readString(buf: ByteBuffer, field: String): ByteArray = try {
        SSHWire.readString(buf)
    } catch (e: SSHWire.SSHWireException) {
        throw SSHSigFormatException("malformed $field: ${e.message}")
    }

    fun readMPInt(buf: ByteBuffer, field: String): BigInteger = try {
        SSHMPInt.read(buf)
    } catch (e: SSHMPInt.SSHMPIntException) {
        throw SSHSigFormatException("malformed $field: ${e.message}")
    }

    /** Read one unsigned byte. */
    fun readByte(buf: ByteBuffer, field: String): Int {
        if (buf.remaining() < 1) throw SSHSigFormatException(
            "short read for $field (need 1 byte)"
        )
        return buf.get().toInt() and 0xff
    }

    /** Read a full-range uint32 (used for the FIDO signature counter). */
    fun readRawUInt32(buf: ByteBuffer): Int {
        if (buf.remaining() < 4) throw SSHSigFormatException("short read for uint32")
        val b0 = buf.get().toInt() and 0xff
        val b1 = buf.get().toInt() and 0xff
        val b2 = buf.get().toInt() and 0xff
        val b3 = buf.get().toInt() and 0xff
        return (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
    }

    /** Write a uint32 in big-endian order. */
    fun writeUInt32(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 24) and 0xff)
        out.write((value ushr 16) and 0xff)
        out.write((value ushr 8) and 0xff)
        out.write(value and 0xff)
    }

    private fun sha512(data: ByteArray): ByteArray {
        val md = SHA512Digest()
        md.update(data, 0, data.size)
        val out = ByteArray(md.digestSize)
        md.doFinal(out, 0)
        return out
    }
}
