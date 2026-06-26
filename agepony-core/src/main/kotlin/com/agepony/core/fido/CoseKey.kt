package com.agepony.core.fido

/**
 * COSE_Key handling for the FIDO stack. Decodes a credential's public key from the
 * authenticator (Ed25519 OKP or P-256 EC2) into raw form for the sk SSHSIG wire, and
 * encodes the platform's EC2 key-agreement key (alg -25) for the clientPin handshake.
 *
 * Label map: kty(1), alg(3), crv(-1), x(-2), y(-3). Curves: Ed25519=6, P-256=1.
 */
object CoseKey {
    const val KTY = 1L
    const val ALG = 3L
    const val CRV = -1L
    const val X = -2L
    const val Y = -3L

    const val KTY_OKP = 1L
    const val KTY_EC2 = 2L

    const val ALG_EDDSA = -8L
    const val ALG_ES256 = -7L
    const val ALG_ECDH_HKDF256 = -25L

    const val CRV_ED25519 = 6L
    const val CRV_P256 = 1L

    sealed class Decoded {
        /** Ed25519 (OKP) public key, 32 raw bytes. */
        class Ed25519(val raw32: ByteArray) : Decoded()
        /** P-256 (EC2) public key, 65-byte uncompressed `0x04 || X || Y`. */
        class P256(val x963: ByteArray) : Decoded()
    }

    fun decode(map: Map<Long, Any?>): Decoded {
        return when (val kty = Cbor.asLong(map[KTY])) {
            KTY_OKP -> {
                val crv = Cbor.asLong(map[CRV])
                if (crv != CRV_ED25519) throw Cbor.CborException("OKP curve is not Ed25519: $crv")
                Decoded.Ed25519(require32(Cbor.asBytes(map[X]), "Ed25519 x"))
            }
            KTY_EC2 -> {
                val crv = Cbor.asLong(map[CRV])
                if (crv != CRV_P256) throw Cbor.CborException("EC2 curve is not P-256: $crv")
                val x = require32(Cbor.asBytes(map[X]), "EC2 x")
                val y = require32(Cbor.asBytes(map[Y]), "EC2 y")
                val q = ByteArray(65)
                q[0] = 0x04
                System.arraycopy(x, 0, q, 1, 32)
                System.arraycopy(y, 0, q, 33, 32)
                Decoded.P256(q)
            }
            else -> throw Cbor.CborException("unsupported COSE kty: $kty")
        }
    }

    fun decodeBytes(coseCbor: ByteArray): Decoded = decode(Cbor.asMap(Cbor.decode(coseCbor)))

    /**
     * Encode the platform key-agreement public key as an EC2 COSE_Key (clientPin). [x32]
     * and [y32] are the P-256 coordinates; [alg] defaults to ECDH-ES+HKDF-256 (-25).
     */
    fun encodePlatformEc2(x32: ByteArray, y32: ByteArray, alg: Long = ALG_ECDH_HKDF256): ByteArray {
        require(x32.size == 32 && y32.size == 32) { "EC2 coordinates must be 32 bytes" }
        val map = LinkedHashMap<Any, Any?>()
        map[KTY] = KTY_EC2
        map[ALG] = alg
        map[CRV] = CRV_P256
        map[X] = x32
        map[Y] = y32
        return Cbor.encode(map)
    }

    private fun require32(b: ByteArray, label: String): ByteArray {
        if (b.size != 32) throw Cbor.CborException("$label must be 32 bytes, got ${b.size}")
        return b
    }
}
