package com.agepony.core.signing

import com.agepony.core.ssh.OpenSSHPrivateKey
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.RSADigestSigner
import org.bouncycastle.jce.ECNamedCurveTable
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Produces detached SSHSIG signatures.
 *
 * Two layers:
 *   - Software signing for keys AgePony holds in-app: ed25519 and rsa (from an
 *     [OpenSSHPrivateKey]), and ecdsa P-256 from a raw scalar (used by tests and by any
 *     future in-app ecdsa key).
 *   - Assembly of signatures produced elsewhere: [assembleEcdsaP256] for an Android
 *     Keystore hardware key (P2), and [assembleSkEd25519] / [assembleSkEcdsaP256] for a
 *     FIDO security key over NFC (P3). These take the already-computed raw signature plus
 *     the FIDO flags/counter and package the SSHSIG envelope.
 *
 * Every entry point returns the armored signature (`-----BEGIN SSH SIGNATURE-----`).
 */
object SSHSigner {
    class SSHSignerException(message: String) : Exception(message)

    private val rng = SecureRandom()

    // --- In-app SSH key signing (the FileSigner SSH route in P6) ---

    /**
     * Sign [message] with an in-app SSH private key. Dispatches on the key type.
     * ed25519 produces an `ssh-ed25519` signature; rsa produces `rsa-sha2-512`.
     */
    fun sign(
        privateKey: OpenSSHPrivateKey,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        hashAlg: String = SSHSig.HASH_SHA512,
    ): String = when (privateKey) {
        is OpenSSHPrivateKey.Ed25519 ->
            signEd25519(privateKey.privateKey, privateKey.publicKey, message, namespace, hashAlg)
        is OpenSSHPrivateKey.RSA ->
            signRsaSha512(privateKey.n, privateKey.e, privateKey.d, message, namespace, hashAlg)
    }

    /** Sign with a raw 32-byte ed25519 seed; [publicKey32] is the matching public key. */
    fun signEd25519(
        seed32: ByteArray,
        publicKey32: ByteArray,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        hashAlg: String = SSHSig.HASH_SHA512,
    ): String {
        require(seed32.size == 32) { "ed25519 seed must be 32 bytes" }
        val toSign = SSHSig.signedData(namespace, hashAlg, SSHSig.hashMessage(message, hashAlg))
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed32, 0))
        signer.update(toSign, 0, toSign.size)
        val sig = signer.generateSignature()
        val pub = SSHSig.ed25519PublicWire(publicKey32)
        val sigWire = SSHSig.ed25519SigWire(sig)
        return SSHSig.armor(SSHSig.encode(pub, namespace, hashAlg, sigWire))
    }

    /** Sign with RSA (rsa-sha2-512, PKCS#1 v1.5 over the signed-data blob). */
    fun signRsaSha512(
        n: BigInteger,
        e: BigInteger,
        d: BigInteger,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        hashAlg: String = SSHSig.HASH_SHA512,
    ): String {
        val toSign = SSHSig.signedData(namespace, hashAlg, SSHSig.hashMessage(message, hashAlg))
        val signer = RSADigestSigner(org.bouncycastle.crypto.digests.SHA512Digest())
        signer.init(true, RSAKeyParameters(true, n, d))
        signer.update(toSign, 0, toSign.size)
        val sig = try {
            signer.generateSignature()
        } catch (ex: Exception) {
            throw SSHSignerException("RSA signing failed: ${ex.message}")
        }
        val pub = SSHSig.rsaPublicWire(e, n)
        val sigWire = SSHSig.rsaSha512SigWire(sig)
        return SSHSig.armor(SSHSig.encode(pub, namespace, hashAlg, sigWire))
    }

    /**
     * Sign with an ecdsa-sha2-nistp256 private scalar. The signature covers
     * SHA-256(signed-data), matching `ecdsa-sha2-nistp256`. Used by tests and any future
     * in-app ecdsa key; the hardware Keystore path uses [assembleEcdsaP256] instead.
     */
    fun signEcdsaP256(
        d: BigInteger,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        hashAlg: String = SSHSig.HASH_SHA512,
    ): String {
        val toSign = SSHSig.signedData(namespace, hashAlg, SSHSig.hashMessage(message, hashAlg))
        val (r, s) = ecdsaSignRaw(d, sha256(toSign))
        val q = publicPointFromScalar(d)
        val pub = SSHSig.ecdsaP256PublicWire(q)
        val sigWire = SSHSig.ecdsaSigWire(r, s)
        return SSHSig.armor(SSHSig.encode(pub, namespace, hashAlg, sigWire))
    }

    // --- Assembly of externally-produced signatures ---

    /**
     * Package a hardware ecdsa P-256 signature (P2 Keystore). [publicQ65] is the
     * uncompressed point; [derSignature] is the DER ECDSA signature the Keystore
     * `Signature` produced over the signed-data blob.
     */
    fun assembleEcdsaP256(
        publicQ65: ByteArray,
        derSignature: ByteArray,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        hashAlg: String = SSHSig.HASH_SHA512,
    ): String {
        val (r, s) = derToRS(derSignature)
        val pub = SSHSig.ecdsaP256PublicWire(publicQ65)
        val sigWire = SSHSig.ecdsaSigWire(r, s)
        val armored = SSHSig.armor(SSHSig.encode(pub, namespace, hashAlg, sigWire))
        return selfCheck(armored, message, namespace, "ecdsa P-256")
    }

    /**
     * Package a security-key ed25519 signature (P3, FIDO over NFC). [rawSig64] is the
     * 64-byte ed25519 signature the authenticator returned; [flags] and [counter] are the
     * authenticator-data fields. [application] must match the credential's rp id.
     */
    fun assembleSkEd25519(
        publicKey32: ByteArray,
        rawSig64: ByteArray,
        flags: Int,
        counter: Int,
        message: ByteArray,
        application: String = SSHSig.SK_APPLICATION_DEFAULT,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        hashAlg: String = SSHSig.HASH_SHA512,
    ): String {
        require(rawSig64.size == 64) { "ed25519 signature must be 64 bytes" }
        val pub = SSHSig.skEd25519PublicWire(publicKey32, application)
        val sigWire = SSHSig.skEd25519SigWire(rawSig64, flags, counter)
        val armored = SSHSig.armor(SSHSig.encode(pub, namespace, hashAlg, sigWire))
        return selfCheck(armored, message, namespace, "sk-ed25519")
    }

    /**
     * Package a security-key ecdsa P-256 signature (P3). [derSignature] is the DER ES256
     * signature from the authenticator; [flags]/[counter] are the authenticator-data
     * fields.
     */
    fun assembleSkEcdsaP256(
        publicQ65: ByteArray,
        derSignature: ByteArray,
        flags: Int,
        counter: Int,
        message: ByteArray,
        application: String = SSHSig.SK_APPLICATION_DEFAULT,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        hashAlg: String = SSHSig.HASH_SHA512,
    ): String {
        val (r, s) = derToRS(derSignature)
        val pub = SSHSig.skEcdsaP256PublicWire(publicQ65, application)
        val sigWire = SSHSig.skEcdsaSigWire(r, s, flags, counter)
        val armored = SSHSig.armor(SSHSig.encode(pub, namespace, hashAlg, sigWire))
        return selfCheck(armored, message, namespace, "sk-ecdsa P-256")
    }

    /**
     * Verify a freshly assembled signature against the message before returning it. The
     * assemble paths wrap signatures produced by external hardware (Keystore, FIDO key);
     * a wrong flags/counter or malformed DER would otherwise only surface later at verify
     * time. This catches it at the source.
     */
    private fun selfCheck(armored: String, message: ByteArray, namespace: String, what: String): String {
        val ok = SSHSigVerifier.isValid(armored.toByteArray(Charsets.US_ASCII), message, namespace)
        if (!ok) throw SSHSignerException(
            "$what signature failed self-verification after assembly; " +
            "check the raw signature, flags, counter, and public key material"
        )
        return armored
    }

    // --- ECDSA P-256 helpers (shared with the verifier) ---

    internal fun p256Domain(): ECDomainParameters {
        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        return ECDomainParameters(spec.curve, spec.g, spec.n, spec.h)
    }

    /** Derive the uncompressed public point `0x04 || x || y` from a private scalar. */
    internal fun publicPointFromScalar(d: BigInteger): ByteArray {
        val dom = p256Domain()
        val q = dom.g.multiply(d).normalize()
        return q.getEncoded(false)
    }

    private fun ecdsaSignRaw(d: BigInteger, hash: ByteArray): Pair<BigInteger, BigInteger> {
        val signer = ECDSASigner()
        signer.init(true, ParametersWithRandom(ECPrivateKeyParameters(d, p256Domain()), rng))
        val sig = signer.generateSignature(hash)
        return Pair(sig[0], sig[1])
    }

    /** Decode a DER `SEQUENCE { INTEGER r, INTEGER s }` into the two integers. */
    internal fun derToRS(der: ByteArray): Pair<BigInteger, BigInteger> {
        val seq = try {
            ASN1Sequence.getInstance(der)
        } catch (e: Exception) {
            throw SSHSignerException("malformed DER ECDSA signature: ${e.message}")
        }
        if (seq.size() != 2) throw SSHSignerException(
            "DER ECDSA signature must have 2 integers, got ${seq.size()}"
        )
        val r = ASN1Integer.getInstance(seq.getObjectAt(0)).positiveValue
        val s = ASN1Integer.getInstance(seq.getObjectAt(1)).positiveValue
        return Pair(r, s)
    }

    private fun sha256(data: ByteArray): ByteArray {
        val md = SHA256Digest()
        md.update(data, 0, data.size)
        val out = ByteArray(md.digestSize)
        md.doFinal(out, 0)
        return out
    }
}
