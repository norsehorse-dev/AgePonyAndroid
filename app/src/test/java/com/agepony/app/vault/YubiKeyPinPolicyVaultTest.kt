package com.agepony.app.vault

import com.agepony.core.crypto.P256Curve
import com.agepony.core.piv.YubiKeyPinPolicy
import com.agepony.core.portability.KeyTransfer
import com.agepony.core.recipients.P256Recipient
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.YubiKeyStub
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * 5.1.0 item 1: the YubiKey PIN policy in the vault record, in `agepony.json` (same key and
 * values as iOS), and on import from an age-plugin-yubikey identity file. Host test.
 */
class YubiKeyPinPolicyVaultTest {
    private val json = Json { ignoreUnknownKeys = true }
    private val pub = P256Curve.toCompressed(P256Curve.randomPublicUncompressed())
    private val stub = YubiKeyStub(12345678, 0x82, YubiKeyStub.staticTag(pub))

    private fun yubiKey(policy: YubiKeyPinPolicy) = StoredIdentity(
        id = "y", name = "YubiKey", type = StoredIdentityType.YUBIKEY_PIV,
        publicKeyB64 = b64e(pub), privateKeyB64 = b64e(stub.toBytes()), createdAt = 0L,
    ).withYubiKeyPinPolicy(policy)

    private fun x25519(name: String = "age"): StoredIdentity {
        val id = X25519Identity.generate()
        return StoredIdentity(
            id = "x-$name", name = name, type = StoredIdentityType.X25519,
            publicKeyB64 = b64e(id.publicKey), privateKeyB64 = b64e(id.privateKey), createdAt = 0L,
        )
    }

    private fun identityRecords(bundle: KeyTransfer.Bundle): List<JsonObject> =
        json.parseToJsonElement(bundle.metadataJson).jsonObject["identities"]!!.jsonArray.map { it.jsonObject }

    // ---- vault record ----

    @Test
    fun recordWithoutTheFieldReadsAsUnknown() {
        val old = """{"id":"y","name":"YubiKey","type":"yubikeyPiv","publicKeyB64":"${b64e(pub)}","privateKeyB64":"${b64e(stub.toBytes())}","createdAt":0}"""
        val record = json.decodeFromString(StoredIdentity.serializer(), old)
        assertNull(record.pinPolicy)
        assertEquals(YubiKeyPinPolicy.UNKNOWN, record.yubiKeyPinPolicy)
    }

    @Test
    fun aValueFromANewerVersionReadsAsUnknown() {
        val newer = """{"id":"y","name":"YubiKey","type":"yubikeyPiv","publicKeyB64":"${b64e(pub)}","privateKeyB64":"${b64e(stub.toBytes())}","createdAt":0,"pinPolicy":"biometric"}"""
        assertEquals(YubiKeyPinPolicy.UNKNOWN, json.decodeFromString(StoredIdentity.serializer(), newer).yubiKeyPinPolicy)
    }

    @Test
    fun storedValuesAreTheIosStrings() {
        assertEquals("required", yubiKey(YubiKeyPinPolicy.REQUIRED).pinPolicy)
        assertEquals("notRequired", yubiKey(YubiKeyPinPolicy.NOT_REQUIRED).pinPolicy)
        assertNull(yubiKey(YubiKeyPinPolicy.UNKNOWN).pinPolicy)
        // Other types never carry it.
        assertEquals(YubiKeyPinPolicy.UNKNOWN, x25519().copy(pinPolicy = "required").yubiKeyPinPolicy)
    }

    // ---- agepony.json ----

    @Test
    fun pinPolicyTravelsInAgeponyJson() {
        for (policy in listOf(YubiKeyPinPolicy.REQUIRED, YubiKeyPinPolicy.NOT_REQUIRED)) {
            val bundle = KeyPortability.buildBundle(listOf(yubiKey(policy)), emptyList(), emptyList())
            assertEquals(JsonPrimitive(policy.raw), identityRecords(bundle).single()["pinPolicy"])
            val back = KeyPortability.readBundle(bundle, TestKeyNames).identities.single()
            assertEquals(policy, back.yubiKeyPinPolicy)
        }
    }

    @Test
    fun unknownAndOtherTypesLeaveTheKeyOut() {
        val bundle = KeyPortability.buildBundle(
            listOf(yubiKey(YubiKeyPinPolicy.UNKNOWN), x25519().copy(pinPolicy = "required")),
            emptyList(), emptyList(),
        )
        for (record in identityRecords(bundle)) assertFalse(record.containsKey("pinPolicy"))
        assertTrue(KeyPortability.readBundle(bundle, TestKeyNames).identities.all { it.pinPolicy == null })
    }

    @Test
    fun readerIgnoresUnknownValuesAndOtherTypes() {
        fun meta(type: String, publicKey: ByteArray, privateKey: ByteArray, policy: String) =
            """{"format":"agepony.com/transfer v1","app":"AgePony iOS","identities":[""" +
                """{"id":"a","name":"k","type":"$type","publicKeyB64":"${b64e(publicKey)}",""" +
                """"privateKeyB64":"${b64e(privateKey)}","createdAt":0,"pinPolicy":"$policy"}],"recipients":[],"signers":[]}"""

        val future = KeyPortability.readBundle(KeyTransfer.Bundle("", emptyMap(), meta("yubikeyPiv", pub, stub.toBytes(), "biometric")), TestKeyNames)
        assertNull(future.identities.single().pinPolicy)

        val x = X25519Identity.generate()
        val onX25519 = KeyPortability.readBundle(KeyTransfer.Bundle("", emptyMap(), meta("x25519", x.publicKey, x.privateKey, "required")), TestKeyNames)
        assertNull(onX25519.identities.single().pinPolicy)

        val fromIos = KeyPortability.readBundle(KeyTransfer.Bundle("", emptyMap(), meta("yubikeyPiv", pub, stub.toBytes(), "notRequired")), TestKeyNames)
        assertEquals(YubiKeyPinPolicy.NOT_REQUIRED, fromIos.identities.single().yubiKeyPinPolicy)
    }

    // ---- import from an identity file ----

    private fun identityFile(pinPolicy: String?, recipient: Boolean): String = buildString {
        append("#       Serial: 12345678, Slot: 1\n")
        if (pinPolicy != null) append("#   PIN policy: $pinPolicy\n")
        append("# Touch policy: Always (A physical touch is required for every decryption)\n")
        if (recipient) append("#    Recipient: ${P256Recipient(pub).toBech32()}\n")
        append(stub.encode()).append('\n')
    }

    private val noTap: (YubiKeyStub) -> Pair<ByteArray, YubiKeyPinPolicy> = { fail("no tap expected"); throw AssertionError() }

    @Test
    fun neverFileImportsWithoutATap() {
        val file = identityFile("Never  (A PIN is NOT required to decrypt)", recipient = true)
        assertTrue(IdentityImport.isYubiKeyIdentity(file))
        val stored = IdentityImport.fromYubiKey(file, "Desk key", { "YubiKey $it" }, noTap)
        assertEquals(YubiKeyPinPolicy.NOT_REQUIRED, stored.yubiKeyPinPolicy)
        assertArrayEquals(pub, b64d(stored.publicKeyB64))
        assertArrayEquals(stub.toBytes(), b64d(stored.privateKeyB64))
        assertEquals("Desk key", stored.name)
        assertTrue(KeyPortability.isConsistent(stored))
    }

    @Test
    fun bareStubTapsAndTakesTheMetadataPolicy() {
        var taps = 0
        val stored = IdentityImport.fromYubiKey(stub.encode(), " ", { "YubiKey $it" }) { s ->
            taps++
            assertEquals(stub, s)
            pub to YubiKeyPinPolicy.REQUIRED
        }
        assertEquals(1, taps)
        assertEquals(YubiKeyPinPolicy.REQUIRED, stored.yubiKeyPinPolicy)
        assertEquals("YubiKey 12345678", stored.name)
    }

    @Test
    fun theTapWinsOverTheCommentWhenTheKeyAnswers() {
        val once = identityFile("Once   (A PIN is required once per session, if set)", recipient = false)
        assertEquals(
            YubiKeyPinPolicy.NOT_REQUIRED,
            IdentityImport.fromYubiKey(once, "k", { "" }) { pub to YubiKeyPinPolicy.NOT_REQUIRED }.yubiKeyPinPolicy,
        )
        // Old firmware: the comment stands.
        val never = identityFile("Never", recipient = false)
        assertEquals(
            YubiKeyPinPolicy.NOT_REQUIRED,
            IdentityImport.fromYubiKey(never, "k", { "" }) { pub to YubiKeyPinPolicy.UNKNOWN }.yubiKeyPinPolicy,
        )
        assertEquals(
            YubiKeyPinPolicy.UNKNOWN,
            IdentityImport.fromYubiKey(identityFile(null, recipient = false), "k", { "" }) { pub to YubiKeyPinPolicy.UNKNOWN }.yubiKeyPinPolicy,
        )
    }

    @Test
    fun notAStubIsAnImportError() {
        assertFalse(IdentityImport.isYubiKeyIdentity("AGE-SECRET-KEY-1QQQQ"))
        try {
            IdentityImport.fromYubiKey("# PIN policy: Once", "k", { "" }, noTap)
            fail("expected an import error")
        } catch (e: IdentityImportException) {
            assertEquals(IdentityImportException.Kind.MALFORMED, e.kind)
        }
    }

    // ---- picker rows (5.1.0 item 3) ----

    @Test
    fun sameNamedKeysHaveDifferentPickerKeys() {
        val a = x25519("Work")
        val b = x25519("Work")
        assertEquals(a.name, b.name)
        assertFalse(KeyPortability.keySummaryOrNull(a) == KeyPortability.keySummaryOrNull(b))

        val sshA = com.agepony.core.recipients.SSHEd25519Identity.generate()
        val sshB = com.agepony.core.recipients.SSHEd25519Identity.generate()
        fun ssh(id: com.agepony.core.recipients.SSHEd25519Identity, n: String) = StoredIdentity(
            id = n, name = "laptop", type = StoredIdentityType.SSH_ED25519, publicKeyB64 = b64e(id.edPublicKey),
            privateKeyB64 = b64e(id.edSeed), sshComment = "user@example", createdAt = 0L,
        )
        val ka = KeyPortability.keySummaryOrNull(ssh(sshA, "1"))!!
        val kb = KeyPortability.keySummaryOrNull(ssh(sshB, "2"))!!
        assertTrue(ka.startsWith("SHA256:"))
        assertFalse(ka == kb)

        fun recipient(id: X25519Identity) = StoredRecipient(
            id = "r", name = "Team", type = StoredRecipientType.X25519, publicKeyB64 = b64e(id.publicKey),
            source = StoredRecipientSource.PASTE_AGE, createdAt = 0L,
        )
        assertFalse(
            KeyPortability.keySummaryOrNull(recipient(X25519Identity.generate())) ==
                KeyPortability.keySummaryOrNull(recipient(X25519Identity.generate()))
        )
    }
}
