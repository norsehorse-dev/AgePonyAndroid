package com.agepony.core.fido

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * FIDO authenticator data: `rpIdHash(32) || flags(1) || signCount(4 BE)` followed, when
 * the AT flag is set (makeCredential), by attested credential data
 * `aaguid(16) || credIdLen(2 BE) || credentialId || credentialPublicKey(COSE)`.
 *
 * getAssertion returns the same header with AT clear and no attested data. The header is
 * also what the sk SSHSIG signature covers (rpIdHash || flags || signCount), so the bytes
 * here line up with the P1 sk verification model.
 */
object AuthenticatorData {
    const val FLAG_UP = 0x01
    const val FLAG_UV = 0x04
    const val FLAG_AT = 0x40
    const val FLAG_ED = 0x80

    class Parsed(
        val rpIdHash: ByteArray,
        val flags: Int,
        val signCount: Long,
        val aaguid: ByteArray?,
        val credentialId: ByteArray?,
        val credentialPublicKey: CoseKey.Decoded?,
        val raw: ByteArray,
    ) {
        val userPresent: Boolean get() = flags and FLAG_UP != 0
        val userVerified: Boolean get() = flags and FLAG_UV != 0
        val hasAttestedCredential: Boolean get() = flags and FLAG_AT != 0
    }

    fun parse(authData: ByteArray): Parsed {
        if (authData.size < 37) throw Cbor.CborException("authenticatorData too short: ${authData.size}")
        val buf = ByteBuffer.wrap(authData).order(ByteOrder.BIG_ENDIAN)
        val rpIdHash = ByteArray(32).also { buf.get(it) }
        val flags = buf.get().toInt() and 0xff
        val signCount = buf.int.toLong() and 0xffffffffL

        var aaguid: ByteArray? = null
        var credentialId: ByteArray? = null
        var pub: CoseKey.Decoded? = null

        if (flags and FLAG_AT != 0) {
            if (buf.remaining() < 18) throw Cbor.CborException("truncated attested credential data")
            aaguid = ByteArray(16).also { buf.get(it) }
            val credLen = buf.short.toInt() and 0xffff
            if (buf.remaining() < credLen) throw Cbor.CborException("credentialId length exceeds data")
            credentialId = ByteArray(credLen).also { buf.get(it) }
            val coseMap = Cbor.decodeValue(buf) // advances past the COSE key, leaving extensions if any
            pub = CoseKey.decode(Cbor.asMap(coseMap))
        }

        return Parsed(rpIdHash, flags, signCount, aaguid, credentialId, pub, authData)
    }
}
