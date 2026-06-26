package com.agepony.core.fido

/**
 * CTAP2 request builders and response parsers for the two commands AgePony uses:
 * `authenticatorMakeCredential` (0x01) to enroll a resident sk credential, and
 * `authenticatorGetAssertion` (0x02) to sign.
 *
 * A CTAP2 request is `command byte || canonical-CBOR(parameters)`. A response is
 * `status byte || CBOR(result)`; a non-zero status raises [CtapError], whose code lets
 * callers branch (notably [ERR_PIN_REQUIRED] = 0x36, the clientPin seam).
 *
 * The pinUvAuthParam / pinUvAuthProtocol map keys differ by command and are baked in
 * correctly here from the start: makeCredential uses 8 and 9, getAssertion uses 6 and 7.
 * (On iOS, getting these crossed made enroll succeed while signing reported "PIN
 * required".) clientPin (command 0x06) request building lands with the PIN layer; the
 * optional params below are wired so it only needs to supply the values.
 */
object Ctap2 {
    class CtapError(val code: Int) : Exception(
        if (code in 0..255) "CTAP error 0x%02x".format(code) else "CTAP error $code"
    )

    const val CMD_MAKE_CREDENTIAL = 0x01
    const val CMD_GET_ASSERTION = 0x02
    const val CMD_GET_INFO = 0x04
    const val CMD_CLIENT_PIN = 0x06

    const val STATUS_OK = 0x00
    const val ERR_UP_REQUIRED = 0x19
    const val ERR_OPERATION_DENIED = 0x27
    const val ERR_PIN_INVALID = 0x31
    const val ERR_PIN_AUTH_INVALID = 0x33
    const val ERR_PIN_REQUIRED = 0x36

    const val ALG_EDDSA = -8L
    const val ALG_ES256 = -7L

    const val APPLICATION_DEFAULT = "ssh:"

    // makeCredential parameter keys
    private const val MC_CLIENT_DATA_HASH = 1L
    private const val MC_RP = 2L
    private const val MC_USER = 3L
    private const val MC_PUB_KEY_CRED_PARAMS = 4L
    private const val MC_OPTIONS = 7L
    private const val MC_PIN_UV_AUTH_PARAM = 8L
    private const val MC_PIN_UV_AUTH_PROTOCOL = 9L

    // getAssertion parameter keys
    private const val GA_RP_ID = 1L
    private const val GA_CLIENT_DATA_HASH = 2L
    private const val GA_ALLOW_LIST = 3L
    private const val GA_OPTIONS = 5L
    private const val GA_PIN_UV_AUTH_PARAM = 6L
    private const val GA_PIN_UV_AUTH_PROTOCOL = 7L

    // clientPin subcommands
    const val SUBCMD_GET_KEY_AGREEMENT = 0x02
    const val SUBCMD_GET_PIN_TOKEN = 0x05

    // clientPin parameter keys
    private const val CP_PIN_PROTOCOL = 1L
    private const val CP_SUBCOMMAND = 2L
    private const val CP_KEY_AGREEMENT = 3L
    private const val CP_PIN_HASH_ENC = 6L

    // clientPin response keys
    private const val CP_RESP_KEY_AGREEMENT = 1L
    private const val CP_RESP_PIN_TOKEN = 2L

    // response keys
    private const val MC_RESP_AUTH_DATA = 2L
    private const val GA_RESP_CREDENTIAL = 1L
    private const val GA_RESP_AUTH_DATA = 2L
    private const val GA_RESP_SIGNATURE = 3L

    /**
     * Build an `authenticatorMakeCredential` request. [algorithms] is the ordered
     * pubKeyCredParams preference (e.g. EdDSA then ES256). [residentKey] requests a
     * discoverable credential, as ssh security keys use.
     */
    fun buildMakeCredential(
        clientDataHash: ByteArray,
        rpId: String,
        userId: ByteArray,
        userName: String,
        algorithms: List<Long>,
        residentKey: Boolean = true,
        pinUvAuthParam: ByteArray? = null,
        pinUvAuthProtocol: Int? = null,
    ): ByteArray {
        val params = algorithms.map { alg ->
            val p = LinkedHashMap<Any, Any?>()
            p["alg"] = alg
            p["type"] = "public-key"
            p
        }
        val map = LinkedHashMap<Any, Any?>()
        map[MC_CLIENT_DATA_HASH] = clientDataHash
        map[MC_RP] = linkedMapOf<Any, Any?>("id" to rpId)
        map[MC_USER] = linkedMapOf<Any, Any?>("id" to userId, "name" to userName)
        map[MC_PUB_KEY_CRED_PARAMS] = params
        map[MC_OPTIONS] = linkedMapOf<Any, Any?>("rk" to residentKey)
        if (pinUvAuthParam != null) {
            map[MC_PIN_UV_AUTH_PARAM] = pinUvAuthParam
            map[MC_PIN_UV_AUTH_PROTOCOL] = (pinUvAuthProtocol ?: 1).toLong()
        }
        return byteArrayOf(CMD_MAKE_CREDENTIAL.toByte()) + Cbor.encode(map)
    }

    /**
     * Build an `authenticatorGetAssertion` request. [allowCredentialIds] pins the
     * assertion to specific credentials; [up] requests user presence (touch).
     */
    fun buildGetAssertion(
        rpId: String,
        clientDataHash: ByteArray,
        allowCredentialIds: List<ByteArray>,
        up: Boolean = true,
        uv: Boolean = false,
        pinUvAuthParam: ByteArray? = null,
        pinUvAuthProtocol: Int? = null,
    ): ByteArray {
        val allow = allowCredentialIds.map {
            val d = LinkedHashMap<Any, Any?>()
            d["type"] = "public-key"
            d["id"] = it
            d
        }
        val options = LinkedHashMap<Any, Any?>()
        options["up"] = up
        if (uv) options["uv"] = true

        val map = LinkedHashMap<Any, Any?>()
        map[GA_RP_ID] = rpId
        map[GA_CLIENT_DATA_HASH] = clientDataHash
        if (allow.isNotEmpty()) map[GA_ALLOW_LIST] = allow
        map[GA_OPTIONS] = options
        if (pinUvAuthParam != null) {
            map[GA_PIN_UV_AUTH_PARAM] = pinUvAuthParam
            map[GA_PIN_UV_AUTH_PROTOCOL] = (pinUvAuthProtocol ?: 1).toLong()
        }
        return byteArrayOf(CMD_GET_ASSERTION.toByte()) + Cbor.encode(map)
    }

    class MakeCredentialResult(val authData: AuthenticatorData.Parsed)

    fun parseMakeCredential(response: ByteArray): MakeCredentialResult {
        val map = Cbor.asMap(Cbor.decode(checkStatus(response)))
        val authData = Cbor.asBytes(map[MC_RESP_AUTH_DATA])
        return MakeCredentialResult(AuthenticatorData.parse(authData))
    }

    class GetAssertionResult(
        val authData: AuthenticatorData.Parsed,
        val signature: ByteArray,
        val credentialId: ByteArray?,
    )

    fun parseGetAssertion(response: ByteArray): GetAssertionResult {
        val map = Cbor.asMap(Cbor.decode(checkStatus(response)))
        val authData = AuthenticatorData.parse(Cbor.asBytes(map[GA_RESP_AUTH_DATA]))
        val signature = Cbor.asBytes(map[GA_RESP_SIGNATURE])
        val credentialId = (map[GA_RESP_CREDENTIAL] as? Map<*, *>)?.get("id") as? ByteArray
        return GetAssertionResult(authData, signature, credentialId)
    }

    /** Build a clientPin `getKeyAgreement` (subcommand 0x02) request. */
    fun buildGetKeyAgreement(): ByteArray {
        val map = LinkedHashMap<Any, Any?>()
        map[CP_PIN_PROTOCOL] = 1L
        map[CP_SUBCOMMAND] = SUBCMD_GET_KEY_AGREEMENT.toLong()
        return byteArrayOf(CMD_CLIENT_PIN.toByte()) + Cbor.encode(map)
    }

    /**
     * Build a clientPin `getPinToken` (subcommand 0x05) request. [platformKeyAgreement] is
     * the platform's EC2 COSE key map; [pinHashEnc] is AES-CBC(sharedSecret, SHA-256(pin)[:16]).
     */
    fun buildGetPinToken(platformKeyAgreement: Map<Any, Any?>, pinHashEnc: ByteArray): ByteArray {
        val map = LinkedHashMap<Any, Any?>()
        map[CP_PIN_PROTOCOL] = 1L
        map[CP_SUBCOMMAND] = SUBCMD_GET_PIN_TOKEN.toLong()
        map[CP_KEY_AGREEMENT] = platformKeyAgreement
        map[CP_PIN_HASH_ENC] = pinHashEnc
        return byteArrayOf(CMD_CLIENT_PIN.toByte()) + Cbor.encode(map)
    }

    /** Parse a getKeyAgreement response into the authenticator's keyAgreement COSE map. */
    fun parseGetKeyAgreement(response: ByteArray): Map<Long, Any?> {
        val map = Cbor.asMap(Cbor.decode(checkStatus(response)))
        return Cbor.asMap(map[CP_RESP_KEY_AGREEMENT])
    }

    /** Parse a getPinToken response into the encrypted PIN token. */
    fun parseGetPinToken(response: ByteArray): ByteArray {
        val map = Cbor.asMap(Cbor.decode(checkStatus(response)))
        return Cbor.asBytes(map[CP_RESP_PIN_TOKEN])
    }

    /** Strip and check the CTAP status byte, returning the CBOR payload (possibly empty). */
    fun checkStatus(response: ByteArray): ByteArray {
        if (response.isEmpty()) throw Cbor.CborException("empty CTAP response")
        val status = response[0].toInt() and 0xff
        if (status != STATUS_OK) throw CtapError(status)
        return response.copyOfRange(1, response.size)
    }
}
