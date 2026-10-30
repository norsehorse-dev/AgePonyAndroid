package com.agepony.core.piv

import com.agepony.core.crypto.P256Curve
import com.agepony.core.recipients.P256Recipient
import com.agepony.core.recipients.YubiKeyStub
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.math.BigInteger

/** A card that answers GET METADATA with [policyByte] and passes everything else to [inner]. */
private class MetadataPivCard(val inner: FakePivCard, private val policyByte: Int) : Piv.Card {
    val metadataApdus = ArrayList<ByteArray>()

    override fun transmit(apdu: ByteArray): ByteArray {
        if ((apdu[1].toInt() and 0xff) == 0xF7) {
            metadataApdus.add(apdu)
            val body = Tlv.encode(0x01, byteArrayOf(0x11)) + Tlv.encode(0x02, byteArrayOf(policyByte.toByte(), 0x01))
            return body + byteArrayOf(0x90.toByte(), 0x00)
        }
        return inner.transmit(apdu)
    }
}

/** 5.1.0 item 1: where a YubiKey's PIN policy comes from. Same cases as the iOS tests. */
class YubiKeyPinPolicyTest {
    private val key = BigInteger("60cda4181bd5744a6c0b3ecadc89f7ca528c4dea68c8643549c163e93fd2f587", 16)
    private val compressedPub = P256Curve.compressed(P256Curve.publicPoint(key))
    private val stub = YubiKeyStub(12345678, 0x82, YubiKeyStub.staticTag(compressedPub))

    private fun identityFile(pinPolicyLine: String?, recipient: Boolean = true): String {
        val lines = mutableListOf(
            "#       Serial: 12345678, Slot: 1",
            "#         Name: age identity TEST",
        )
        if (pinPolicyLine != null) lines.add(pinPolicyLine)
        lines.add("# Touch policy: Always (A physical touch is required for every decryption)")
        if (recipient) lines.add("#    Recipient: ${P256Recipient(compressedPub).toBech32()}")
        lines.add(stub.encode())
        return lines.joinToString("\n")
    }

    @Test
    fun identityFilePinPolicyComment() {
        val never = YubiKeyIdentityFile.parse(identityFile("#   PIN policy: Never  (A PIN is NOT required to decrypt)"))
        assertEquals(YubiKeyPinPolicy.NOT_REQUIRED, never.pinPolicy)
        assertEquals(stub, never.stub)
        assertArrayEquals(compressedPub, never.publicKey)

        val once = YubiKeyIdentityFile.parse(identityFile("#   PIN policy: Once   (A PIN is required once per session, if set)"))
        assertEquals(YubiKeyPinPolicy.REQUIRED, once.pinPolicy)

        val always = YubiKeyIdentityFile.parse(identityFile("#   PIN policy: Always (A PIN is required for every decryption, if set)"))
        assertEquals(YubiKeyPinPolicy.REQUIRED, always.pinPolicy)

        // No PIN policy line (the touch policy line must not be read as one), and a bare stub.
        assertEquals(YubiKeyPinPolicy.UNKNOWN, YubiKeyIdentityFile.parse(identityFile(null)).pinPolicy)
        val bare = YubiKeyIdentityFile.parse(stub.encode())
        assertEquals(YubiKeyPinPolicy.UNKNOWN, bare.pinPolicy)
        assertNull(bare.publicKey)

        // A value this version doesn't know stays unknown, so the app still asks first.
        assertEquals(YubiKeyPinPolicy.UNKNOWN, YubiKeyIdentityFile.parse(identityFile("#   PIN policy: Sometimes")).pinPolicy)
    }

    @Test
    fun identityFilePinPolicyFromFirstStubOnly() {
        val text = identityFile("#   PIN policy: Never  (A PIN is NOT required to decrypt)") + "\n\n" +
            identityFile("#   PIN policy: Always (A PIN is required for every decryption, if set)")
        val parsed = YubiKeyIdentityFile.parse(text)
        assertEquals(stub, parsed.stub)
        assertEquals(YubiKeyPinPolicy.NOT_REQUIRED, parsed.pinPolicy)

        val reversed = identityFile("#   PIN policy: Once   (A PIN is required once per session, if set)") + "\n\n" +
            identityFile("#   PIN policy: Never  (A PIN is NOT required to decrypt)")
        assertEquals(YubiKeyPinPolicy.REQUIRED, YubiKeyIdentityFile.parse(reversed).pinPolicy)
    }

    @Test
    fun identityFileWithoutRecipientOrWithSomeoneElses() {
        val noRecipient = YubiKeyIdentityFile.parse(identityFile("#   PIN policy: Once", recipient = false))
        assertNull(noRecipient.publicKey)
        val other = P256Curve.toCompressed(P256Curve.randomPublicUncompressed())
        val wrong = identityFile(null, recipient = false).replace(
            stub.encode(), "#    Recipient: ${P256Recipient(other).toBech32()}\n${stub.encode()}"
        )
        assertNull(YubiKeyIdentityFile.parse(wrong).publicKey)
    }

    @Test
    fun identityFileDetection() {
        assertTrue(YubiKeyIdentityFile.contains(identityFile("#   PIN policy: Once")))
        assertTrue(YubiKeyIdentityFile.contains(stub.encode()))
        assertFalse(YubiKeyIdentityFile.contains("AGE-SECRET-KEY-1QQQQ"))
        assertFalse(YubiKeyIdentityFile.contains("# ${stub.encode()}"))
        assertThrows<IllegalArgumentException> { YubiKeyIdentityFile.parse("#   PIN policy: Once") }
    }

    @Test
    fun storedValuesMatchIos() {
        assertEquals("unknown", YubiKeyPinPolicy.UNKNOWN.raw)
        assertEquals("required", YubiKeyPinPolicy.REQUIRED.raw)
        assertEquals("notRequired", YubiKeyPinPolicy.NOT_REQUIRED.raw)
        assertEquals(YubiKeyPinPolicy.REQUIRED, YubiKeyPinPolicy.fromRaw("required"))
        assertEquals(YubiKeyPinPolicy.NOT_REQUIRED, YubiKeyPinPolicy.fromRaw("notRequired"))
        assertEquals(YubiKeyPinPolicy.UNKNOWN, YubiKeyPinPolicy.fromRaw(null))
        assertEquals(YubiKeyPinPolicy.UNKNOWN, YubiKeyPinPolicy.fromRaw("biometric"))
    }

    @Test
    fun metadataPinPolicyBytes() {
        fun answer(policy: Int) = Tlv.encode(0x01, byteArrayOf(0x11)) + Tlv.encode(0x02, byteArrayOf(policy.toByte(), 0x01))
        assertEquals(YubiKeyPinPolicy.REQUIRED, Piv.pinPolicy(answer(0), 0x9000))       // slot default
        assertEquals(YubiKeyPinPolicy.NOT_REQUIRED, Piv.pinPolicy(answer(1), 0x9000))   // never
        assertEquals(YubiKeyPinPolicy.REQUIRED, Piv.pinPolicy(answer(2), 0x9000))       // once
        assertEquals(YubiKeyPinPolicy.REQUIRED, Piv.pinPolicy(answer(3), 0x9000))       // always
        assertEquals(YubiKeyPinPolicy.UNKNOWN, Piv.pinPolicy(answer(0x7F), 0x9000))
        // Firmware before 5.3 has no GET METADATA.
        assertEquals(YubiKeyPinPolicy.UNKNOWN, Piv.pinPolicy(ByteArray(0), 0x6D00))
        // No policy tag, or a truncated one.
        assertEquals(YubiKeyPinPolicy.UNKNOWN, Piv.pinPolicy(Tlv.encode(0x01, byteArrayOf(0x11)), 0x9000))
        assertEquals(YubiKeyPinPolicy.UNKNOWN, Piv.pinPolicy(byteArrayOf(0x02, 0x05, 0x01), 0x9000))
    }

    @Test
    fun metadataOnTheImportTap() {
        // Old firmware (the fake card answers 6D00 to F7): policy unknown.
        val old = FakePivCard(key, ByteArray(0))
        Piv.select(old)
        assertEquals(YubiKeyPinPolicy.UNKNOWN, Piv.pinPolicy(old, 0x82))

        val expected = listOf(0 to YubiKeyPinPolicy.REQUIRED, 1 to YubiKeyPinPolicy.NOT_REQUIRED,
            2 to YubiKeyPinPolicy.REQUIRED, 3 to YubiKeyPinPolicy.REQUIRED)
        for ((byte, policy) in expected) {
            val card = MetadataPivCard(FakePivCard(key, ByteArray(0)), byte)
            assertEquals(policy, Piv.pinPolicy(card, 0x82), "policy byte $byte")
            // GET METADATA for the slot: 00 F7 00 82 00. No PIN was sent.
            assertEquals(1, card.metadataApdus.size)
            assertArrayEquals(byteArrayOf(0x00, 0xF7.toByte(), 0x00, 0x82.toByte(), 0x00), card.metadataApdus[0])
            assertFalse(card.inner.pinVerified)
        }
    }
}
