package com.agepony.app.security.keystore

import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner
import java.math.BigInteger
import java.security.interfaces.ECPublicKey

/**
 * Pure, device-independent logic behind [HardwareKeyService]: the SEC1 point encoding,
 * the SSHSIG public-key wire, the signed-data a Keystore `Signature` must cover, and the
 * DER -> armored SSHSIG assembly.
 *
 * No AndroidKeyStore or Android framework types appear here, so this is exercised on the
 * JVM with an ordinary software EC key, which is the same math the hardware key runs.
 */
object KeystoreEcdsa {

    /** SEC1 uncompressed point `0x04 || X(32) || Y(32)` from a P-256 public key. */
    fun uncompressedPoint(pub: ECPublicKey): ByteArray {
        val x = fixedWidth(pub.w.affineX, 32)
        val y = fixedWidth(pub.w.affineY, 32)
        val out = ByteArray(65)
        out[0] = 0x04
        System.arraycopy(x, 0, out, 1, 32)
        System.arraycopy(y, 0, out, 33, 32)
        return out
    }

    /** The `ecdsa-sha2-nistp256` SSHSIG public-key wire blob for [pub]. */
    fun publicWire(pub: ECPublicKey): ByteArray =
        SSHSig.ecdsaP256PublicWire(uncompressedPoint(pub))

    /** The SSHSIG signed-data a Keystore `Signature` must sign over. */
    fun signedData(
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        hashAlg: String = SSHSig.HASH_SHA512,
    ): ByteArray = SSHSig.signedData(namespace, hashAlg, SSHSig.hashMessage(message, hashAlg))

    /**
     * Wrap a DER ECDSA signature (produced by a Keystore `Signature` over the
     * [signedData] for [message]) into an armored SSHSIG. Delegates to
     * [SSHSigner.assembleEcdsaP256], which self-verifies before returning.
     */
    fun assemble(
        pub: ECPublicKey,
        derSignature: ByteArray,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
        hashAlg: String = SSHSig.HASH_SHA512,
    ): String = SSHSigner.assembleEcdsaP256(
        uncompressedPoint(pub), derSignature, message, namespace, hashAlg
    )

    /** Left-pad / trim a non-negative coordinate to exactly [len] big-endian bytes. */
    private fun fixedWidth(v: BigInteger, len: Int): ByteArray {
        val raw = v.toByteArray()
        if (raw.size == len) return raw
        // BigInteger may prepend a 0x00 sign byte for values with the top bit set.
        if (raw.size == len + 1 && raw[0] == 0.toByte()) return raw.copyOfRange(1, raw.size)
        if (raw.size > len) return raw.copyOfRange(raw.size - len, raw.size)
        val out = ByteArray(len)
        System.arraycopy(raw, 0, out, len - raw.size, raw.size)
        return out
    }
}
