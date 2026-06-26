package com.agepony.core.signing

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.RSADigestSigner
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer

/**
 * Verifies detached SSHSIG signatures over a message.
 *
 * Accepts an armored or raw SSHSIG blob plus the original message bytes, reconstructs the
 * signed-data from the message and the envelope's hash algorithm, and checks the
 * signature against the public key carried in the envelope. The recovered public-key wire
 * is returned so callers can decide trust (a known signer vs a valid-but-unknown one).
 *
 * For the `sk-*` security-key variants the verified message is the FIDO authenticator
 * model: `SHA-256(application) || flags || counter || SHA-256(signed-data)`.
 */
object SSHSigVerifier {

    /**
     * @param valid whether the signature verified.
     * @param keyType the signer key type (e.g. `ssh-ed25519`, `sk-ecdsa-sha2-nistp256@openssh.com`).
     * @param signerPublicWire the public-key wire blob from the envelope (for trust checks).
     * @param namespace the namespace the signature was made under.
     * @param reason null when valid; otherwise why it failed.
     */
    class Result(
        val valid: Boolean,
        val keyType: String,
        val signerPublicWire: ByteArray,
        val namespace: String,
        val reason: String?,
    )

    /**
     * Verify [signature] (armored or raw) over [message]. When [expectedNamespace] is
     * non-null and does not match the envelope, the result is invalid with a reason.
     * Throws [SSHSig.SSHSigFormatException] only for structurally malformed input.
     */
    fun verify(
        signature: ByteArray,
        message: ByteArray,
        expectedNamespace: String? = SSHSig.NAMESPACE_AGEPONY,
    ): Result {
        val blob = SSHSig.decodeArmoredOrRaw(signature)
        val env = SSHSig.decode(blob)
        val keyType = env.keyType

        if (expectedNamespace != null && env.namespace != expectedNamespace) {
            return Result(
                valid = false,
                keyType = keyType,
                signerPublicWire = env.publicKeyBlob,
                namespace = env.namespace,
                reason = "namespace mismatch: got '${env.namespace}', expected '$expectedNamespace'",
            )
        }

        val signedData = SSHSig.signedData(
            env.namespace,
            env.hashAlgorithm,
            SSHSig.hashMessage(message, env.hashAlgorithm),
        )

        val ok = when (keyType) {
            SSHSig.KEY_ED25519 -> verifyEd25519(env, signedData)
            SSHSig.KEY_RSA -> verifyRsa(env, signedData)
            SSHSig.KEY_ECDSA_P256 -> verifyEcdsa(env, signedData)
            SSHSig.KEY_SK_ED25519 -> verifySkEd25519(env, signedData)
            SSHSig.KEY_SK_ECDSA_P256 -> verifySkEcdsa(env, signedData)
            else -> throw SSHSig.SSHSigFormatException("unsupported signer key type: '$keyType'")
        }

        return Result(
            valid = ok,
            keyType = keyType,
            signerPublicWire = env.publicKeyBlob,
            namespace = env.namespace,
            reason = if (ok) null else "signature did not verify",
        )
    }

    /** Convenience boolean form. */
    fun isValid(
        signature: ByteArray,
        message: ByteArray,
        expectedNamespace: String? = SSHSig.NAMESPACE_AGEPONY,
    ): Boolean = verify(signature, message, expectedNamespace).valid

    // --- Per-algorithm verification ---

    private fun verifyEd25519(env: SSHSig.Decoded, signedData: ByteArray): Boolean {
        val pub = parseEd25519Public(env.publicKeyBlob)
        val sig = parseEd25519Sig(env.signatureBlob)
        return ed25519Verify(pub, signedData, sig)
    }

    private fun verifyRsa(env: SSHSig.Decoded, signedData: ByteArray): Boolean {
        val (e, n) = parseRsaPublic(env.publicKeyBlob)
        val sig = parseRsaSig(env.signatureBlob)
        val verifier = RSADigestSigner(org.bouncycastle.crypto.digests.SHA512Digest())
        verifier.init(false, RSAKeyParameters(false, n, e))
        verifier.update(signedData, 0, signedData.size)
        return try {
            verifier.verifySignature(sig)
        } catch (e2: Exception) {
            false
        }
    }

    private fun verifyEcdsa(env: SSHSig.Decoded, signedData: ByteArray): Boolean {
        val q = parseEcdsaPublic(env.publicKeyBlob)
        val (r, s) = parseEcdsaSig(env.signatureBlob)
        return ecdsaVerify(q, sha256(signedData), r, s)
    }

    private fun verifySkEd25519(env: SSHSig.Decoded, signedData: ByteArray): Boolean {
        val (pub, application) = parseSkEd25519Public(env.publicKeyBlob)
        val (sig, flags, counter) = parseSkEd25519Sig(env.signatureBlob)
        val authMessage = skAuthMessage(application, flags, counter, signedData)
        return ed25519Verify(pub, authMessage, sig)
    }

    private fun verifySkEcdsa(env: SSHSig.Decoded, signedData: ByteArray): Boolean {
        val (q, application) = parseSkEcdsaPublic(env.publicKeyBlob)
        val (r, s, flags, counter) = parseSkEcdsaSig(env.signatureBlob)
        val authMessage = skAuthMessage(application, flags, counter, signedData)
        return ecdsaVerify(q, sha256(authMessage), r, s)
    }

    /** FIDO authenticator message: `SHA-256(app) || flags || counter || SHA-256(signedData)`. */
    private fun skAuthMessage(
        application: String,
        flags: Int,
        counter: Int,
        signedData: ByteArray,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(sha256(application.toByteArray(Charsets.UTF_8)))
        out.write(flags and 0xff)
        SSHSig.writeUInt32(out, counter)
        out.write(sha256(signedData))
        return out.toByteArray()
    }

    // --- Public-key blob parsers ---

    private fun parseEd25519Public(blob: ByteArray): ByteArray {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.KEY_ED25519)
        val pub = SSHSig.readString(buf, "ed25519 pubkey")
        if (pub.size != 32) throw SSHSig.SSHSigFormatException(
            "ed25519 pubkey must be 32 bytes, got ${pub.size}"
        )
        requireEnd(buf, "ed25519 public blob")
        return pub
    }

    private fun parseRsaPublic(blob: ByteArray): Pair<BigInteger, BigInteger> {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.KEY_RSA)
        val e = SSHSig.readMPInt(buf, "RSA exponent")
        val n = SSHSig.readMPInt(buf, "RSA modulus")
        requireEnd(buf, "RSA public blob")
        return Pair(e, n)
    }

    private fun parseEcdsaPublic(blob: ByteArray): ByteArray {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.KEY_ECDSA_P256)
        expectCurve(buf)
        val q = SSHSig.readString(buf, "ecdsa point")
        validatePoint(q)
        requireEnd(buf, "ecdsa public blob")
        return q
    }

    private fun parseSkEd25519Public(blob: ByteArray): Pair<ByteArray, String> {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.KEY_SK_ED25519)
        val pub = SSHSig.readString(buf, "sk-ed25519 pubkey")
        if (pub.size != 32) throw SSHSig.SSHSigFormatException(
            "sk-ed25519 pubkey must be 32 bytes, got ${pub.size}"
        )
        val app = String(SSHSig.readString(buf, "sk-ed25519 application"), Charsets.UTF_8)
        requireEnd(buf, "sk-ed25519 public blob")
        return Pair(pub, app)
    }

    private fun parseSkEcdsaPublic(blob: ByteArray): Pair<ByteArray, String> {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.KEY_SK_ECDSA_P256)
        expectCurve(buf)
        val q = SSHSig.readString(buf, "sk-ecdsa point")
        validatePoint(q)
        val app = String(SSHSig.readString(buf, "sk-ecdsa application"), Charsets.UTF_8)
        requireEnd(buf, "sk-ecdsa public blob")
        return Pair(q, app)
    }

    // --- Signature blob parsers ---

    private fun parseEd25519Sig(blob: ByteArray): ByteArray {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.SIG_ED25519)
        val sig = SSHSig.readString(buf, "ed25519 signature")
        if (sig.size != 64) throw SSHSig.SSHSigFormatException(
            "ed25519 signature must be 64 bytes, got ${sig.size}"
        )
        requireEnd(buf, "ed25519 signature blob")
        return sig
    }

    private fun parseRsaSig(blob: ByteArray): ByteArray {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.SIG_RSA_SHA512)
        val sig = SSHSig.readString(buf, "rsa signature")
        requireEnd(buf, "rsa signature blob")
        return sig
    }

    private fun parseEcdsaSig(blob: ByteArray): Pair<BigInteger, BigInteger> {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.SIG_ECDSA_P256)
        val inner = SSHSig.readString(buf, "ecdsa signature blob")
        requireEnd(buf, "ecdsa signature blob")
        return readRS(inner)
    }

    private data class SkEdSig(val sig: ByteArray, val flags: Int, val counter: Int)

    private fun parseSkEd25519Sig(blob: ByteArray): SkEdSig {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.SIG_SK_ED25519)
        val sig = SSHSig.readString(buf, "sk-ed25519 signature")
        if (sig.size != 64) throw SSHSig.SSHSigFormatException(
            "sk-ed25519 signature must be 64 bytes, got ${sig.size}"
        )
        val flags = SSHSig.readByte(buf, "sk flags")
        val counter = SSHSig.readRawUInt32(buf)
        requireEnd(buf, "sk-ed25519 signature blob")
        return SkEdSig(sig, flags, counter)
    }

    private data class SkEcSig(
        val r: BigInteger,
        val s: BigInteger,
        val flags: Int,
        val counter: Int,
    )

    private fun parseSkEcdsaSig(blob: ByteArray): SkEcSig {
        val buf = SSHSig.reader(blob)
        expectType(buf, SSHSig.SIG_SK_ECDSA_P256)
        val inner = SSHSig.readString(buf, "sk-ecdsa signature blob")
        val flags = SSHSig.readByte(buf, "sk flags")
        val counter = SSHSig.readRawUInt32(buf)
        requireEnd(buf, "sk-ecdsa signature blob")
        val (r, s) = readRS(inner)
        return SkEcSig(r, s, flags, counter)
    }

    private fun readRS(inner: ByteArray): Pair<BigInteger, BigInteger> {
        val ib = SSHSig.reader(inner)
        val r = SSHSig.readMPInt(ib, "ecdsa r")
        val s = SSHSig.readMPInt(ib, "ecdsa s")
        requireEnd(ib, "ecdsa r||s")
        return Pair(r, s)
    }

    // --- Crypto primitives ---

    private fun ed25519Verify(pub32: ByteArray, message: ByteArray, sig64: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(pub32, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(sig64)
    }

    private fun ecdsaVerify(q65: ByteArray, hash: ByteArray, r: BigInteger, s: BigInteger): Boolean {
        val dom = SSHSigner.p256Domain()
        val point = try {
            dom.curve.decodePoint(q65)
        } catch (e: Exception) {
            throw SSHSig.SSHSigFormatException("invalid ecdsa point: ${e.message}")
        }
        val verifier = ECDSASigner()
        verifier.init(false, ECPublicKeyParameters(point, dom))
        return verifier.verifySignature(hash, r, s)
    }

    private fun sha256(data: ByteArray): ByteArray {
        val md = SHA256Digest()
        md.update(data, 0, data.size)
        val out = ByteArray(md.digestSize)
        md.doFinal(out, 0)
        return out
    }

    // --- Small reader helpers ---

    private fun expectType(buf: ByteBuffer, expected: String) {
        val got = String(SSHSig.readString(buf, "type"), Charsets.US_ASCII)
        if (got != expected) throw SSHSig.SSHSigFormatException(
            "expected type '$expected', got '$got'"
        )
    }

    private fun expectCurve(buf: ByteBuffer) {
        val curve = String(SSHSig.readString(buf, "curve"), Charsets.US_ASCII)
        if (curve != SSHSig.ECDSA_CURVE_P256) throw SSHSig.SSHSigFormatException(
            "expected curve '${SSHSig.ECDSA_CURVE_P256}', got '$curve'"
        )
    }

    private fun validatePoint(q: ByteArray) {
        if (q.size != 65 || q[0] != 0x04.toByte()) throw SSHSig.SSHSigFormatException(
            "ecdsa point must be 65 bytes uncompressed, got ${q.size}"
        )
    }

    private fun requireEnd(buf: ByteBuffer, where: String) {
        if (buf.hasRemaining()) throw SSHSig.SSHSigFormatException(
            "trailing bytes in $where: ${buf.remaining()}"
        )
    }
}
