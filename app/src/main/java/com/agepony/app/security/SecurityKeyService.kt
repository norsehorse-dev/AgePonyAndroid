package com.agepony.app.security

import androidx.fragment.app.FragmentActivity
import com.agepony.app.security.nfc.SecurityKeyTransport
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredIdentityType
import com.agepony.app.vault.b64d
import com.agepony.app.vault.b64e
import com.agepony.core.crypto.SHA256
import com.agepony.core.fido.CoseKey
import com.agepony.core.fido.Ctap2
import com.agepony.core.fido.PinProtocolV1
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner
import java.security.SecureRandom
import java.util.UUID

/**
 * FIDO security-key signing identities over NFC. [enroll] runs makeCredential to create a
 * resident sk credential and turns the returned public key into an sk SSHSIG identity;
 * [signSSHSIG] runs getAssertion and packages the assertion into an armored SSHSIG via the
 * P1 assemble paths (which self-verify).
 *
 * Touch / user-presence is the default. If the authenticator demands a PIN it returns CTAP
 * 0x36; when a [pinProvider] is supplied, the clientPin handshake (getKeyAgreement, ECDH,
 * getPinToken) runs inside the same tap and the command is retried with a pinUvAuthParam.
 * A wrong PIN (0x31) re-prompts. With no provider, 0x36 surfaces as [PinRequiredException].
 */
class SecurityKeyService(
    private val activity: FragmentActivity,
    private val pinProvider: PinProvider? = null,
) {
    class SecurityKeyException(message: String, cause: Throwable? = null) : Exception(message, cause)
    class PinRequiredException(message: String = "security key requires a PIN") : Exception(message)

    /** Supplies a PIN on demand. [wrongPreviousAttempt] is true when re-prompting after 0x31. */
    fun interface PinProvider {
        suspend fun providePin(wrongPreviousAttempt: Boolean): String?
    }

    private val rng = SecureRandom()

    enum class Algorithm(val cose: Long, val type: StoredIdentityType) {
        ED25519(Ctap2.ALG_EDDSA, StoredIdentityType.SK_ED25519),
        ECDSA_P256(Ctap2.ALG_ES256, StoredIdentityType.SK_ECDSA_P256),
    }

    /**
     * Enroll a resident sk credential and return a vault identity. The credentialId is
     * stored as the private material and the sk SSHSIG wire as the public material.
     */
    suspend fun enroll(
        name: String,
        algorithm: Algorithm,
        application: String = Ctap2.APPLICATION_DEFAULT,
    ): StoredIdentity {
        val clientDataHash = ByteArray(32).also { rng.nextBytes(it) }
        val userId = ByteArray(32).also { rng.nextBytes(it) }

        val transport = SecurityKeyTransport(activity)
        val result = transport.withSecurityKey { session ->
            val response = runCommand(session, clientDataHash) { pinUvAuthParam ->
                Ctap2.buildMakeCredential(
                    clientDataHash = clientDataHash,
                    rpId = application,
                    userId = userId,
                    userName = name.ifBlank { "agepony" },
                    algorithms = listOf(algorithm.cose),
                    residentKey = true,
                    pinUvAuthParam = pinUvAuthParam,
                    pinUvAuthProtocol = pinUvAuthParam?.let { PinProtocolV1.VERSION },
                )
            }
            Ctap2.parseMakeCredential(response)
        }

        val authData = result.authData
        val credentialId = authData.credentialId
            ?: throw SecurityKeyException("authenticator returned no credentialId")
        val pub = authData.credentialPublicKey
            ?: throw SecurityKeyException("authenticator returned no public key")

        val publicWire = when (pub) {
            is CoseKey.Decoded.Ed25519 -> {
                if (algorithm != Algorithm.ED25519)
                    throw SecurityKeyException("authenticator returned ed25519 for a non-ed25519 request")
                SSHSig.skEd25519PublicWire(pub.raw32, application)
            }
            is CoseKey.Decoded.P256 -> {
                if (algorithm != Algorithm.ECDSA_P256)
                    throw SecurityKeyException("authenticator returned p256 for a non-p256 request")
                SSHSig.skEcdsaP256PublicWire(pub.x963, application)
            }
        }

        return StoredIdentity(
            id = UUID.randomUUID().toString(),
            name = name,
            type = algorithm.type,
            publicKeyB64 = b64e(publicWire),
            privateKeyB64 = b64e(credentialId),
            sshComment = application,
            createdAt = System.currentTimeMillis(),
        )
    }

    /** Sign [message] with an sk identity, returning an armored SSHSIG. */
    suspend fun signSSHSIG(
        identity: StoredIdentity,
        message: ByteArray,
        namespace: String = SSHSig.NAMESPACE_AGEPONY,
    ): String {
        require(identity.type == StoredIdentityType.SK_ED25519 ||
            identity.type == StoredIdentityType.SK_ECDSA_P256) {
            "not a security-key identity: ${identity.type}"
        }
        val publicWire = b64d(identity.publicKeyB64)
        val credentialId = b64d(identity.privateKeyB64)
        val application = identity.sshComment ?: Ctap2.APPLICATION_DEFAULT

        val signedData = SSHSig.signedData(
            namespace, SSHSig.HASH_SHA512, SSHSig.hashMessage(message, SSHSig.HASH_SHA512)
        )
        val clientDataHash = SHA256.digest(signedData)

        val transport = SecurityKeyTransport(activity)
        val assertion = transport.withSecurityKey { session ->
            val response = runCommand(session, clientDataHash) { pinUvAuthParam ->
                Ctap2.buildGetAssertion(
                    rpId = application,
                    clientDataHash = clientDataHash,
                    allowCredentialIds = listOf(credentialId),
                    up = true,
                    pinUvAuthParam = pinUvAuthParam,
                    pinUvAuthProtocol = pinUvAuthParam?.let { PinProtocolV1.VERSION },
                )
            }
            Ctap2.parseGetAssertion(response)
        }

        val flags = assertion.authData.flags
        val counter = assertion.authData.signCount.toInt()
        return when (identity.type) {
            StoredIdentityType.SK_ED25519 -> {
                val (pub32, app) = parseSkEd25519(publicWire)
                SSHSigner.assembleSkEd25519(
                    pub32, assertion.signature, flags, counter, message, app, namespace
                )
            }
            StoredIdentityType.SK_ECDSA_P256 -> {
                val (q65, app) = parseSkEcdsa(publicWire)
                SSHSigner.assembleSkEcdsaP256(
                    q65, assertion.signature, flags, counter, message, app, namespace
                )
            }
            else -> throw SecurityKeyException("unreachable")
        }
    }

    /**
     * Run a CTAP command, handling clientPin. [build] produces the request given an
     * optional pinUvAuthParam. On the first attempt no PIN is sent; if the authenticator
     * returns 0x36 and a [pinProvider] exists, the PIN token is obtained in this same
     * session and [build] is retried with a pinUvAuthParam over [clientDataHash]. A wrong
     * PIN (0x31) re-prompts.
     */
    private suspend fun runCommand(
        session: SecurityKeyTransport.Session,
        clientDataHash: ByteArray,
        build: (pinUvAuthParam: ByteArray?) -> ByteArray,
    ): ByteArray {
        try {
            return session.ctap(build(null))
        } catch (e: Ctap2.CtapError) {
            if (e.code != Ctap2.ERR_PIN_REQUIRED) throw mapCtapError(e)
        }
        val provider = pinProvider ?: throw PinRequiredException()

        var wrongPrevious = false
        while (true) {
            val pin = provider.providePin(wrongPrevious)
                ?: throw SecurityKeyException("PIN entry was cancelled")
            val pinUvAuthParam = obtainPinUvAuthParam(session, pin, clientDataHash)
            try {
                return session.ctap(build(pinUvAuthParam))
            } catch (e: Ctap2.CtapError) {
                if (e.code == Ctap2.ERR_PIN_INVALID) { wrongPrevious = true; continue }
                throw mapCtapError(e)
            }
        }
    }

    /**
     * clientPin handshake in the live session: getKeyAgreement, derive the shared secret,
     * getPinToken with the encrypted PIN hash, decrypt the token, and return the
     * pinUvAuthParam (HMAC of [clientDataHash] under the PIN token) for the main command.
     */
    private fun obtainPinUvAuthParam(
        session: SecurityKeyTransport.Session,
        pin: String,
        clientDataHash: ByteArray,
    ): ByteArray {
        val authKeyAgreement = Ctap2.parseGetKeyAgreement(session.ctap(Ctap2.buildGetKeyAgreement()))
        val enc = PinProtocolV1.encapsulate(authKeyAgreement)
        val pinHashEnc = PinProtocolV1.pinHashEnc(enc.sharedSecret, pin)
        val tokenEnc = Ctap2.parseGetPinToken(
            session.ctap(Ctap2.buildGetPinToken(enc.platformCose, pinHashEnc))
        )
        val pinToken = PinProtocolV1.decrypt(enc.sharedSecret, tokenEnc)
        return PinProtocolV1.authenticate(pinToken, clientDataHash)
    }

    private fun mapCtapError(e: Ctap2.CtapError): Exception =
        if (e.code == Ctap2.ERR_PIN_REQUIRED) PinRequiredException()
        else SecurityKeyException("security key error: 0x%02x".format(e.code), e)

    private fun parseSkEd25519(wire: ByteArray): Pair<ByteArray, String> {
        val buf = SSHSig.reader(wire)
        SSHSig.readString(buf, "type")
        val pub = SSHSig.readString(buf, "sk-ed25519 pubkey")
        val app = String(SSHSig.readString(buf, "application"), Charsets.UTF_8)
        return pub to app
    }

    private fun parseSkEcdsa(wire: ByteArray): Pair<ByteArray, String> {
        val buf = SSHSig.reader(wire)
        SSHSig.readString(buf, "type")
        SSHSig.readString(buf, "curve")
        val q = SSHSig.readString(buf, "sk-ecdsa point")
        val app = String(SSHSig.readString(buf, "application"), Charsets.UTF_8)
        return q to app
    }
}
