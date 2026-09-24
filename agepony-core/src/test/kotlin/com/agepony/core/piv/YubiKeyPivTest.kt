package com.agepony.core.piv

import com.agepony.core.Age
import com.agepony.core.crypto.P256Curve
import com.agepony.core.crypto.P256KeyAgreement
import com.agepony.core.crypto.P256SoftwareKey
import com.agepony.core.interop.AgeCli
import com.agepony.core.recipients.P256Recipient
import com.agepony.core.recipients.TagRecipient
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.recipients.YubiKeyIdentity
import com.agepony.core.recipients.YubiKeyStub
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.math.BigInteger
import java.util.Base64

/** A PIV card simulator: one P-256 key in retired slot 82, PIN 123456, chained GET DATA. */
class FakePivCard(private val key: BigInteger, private val certDer: ByteArray, private val serial: Long = 12345678) : Piv.Card {
    var pinVerified = false
    var ecdhCalls = 0
    private var pending = ByteArray(0)

    override fun transmit(apdu: ByteArray): ByteArray {
        val ins = apdu[1].toInt() and 0xff
        return when (ins) {
            0xA4 -> sw(0x9000)
            0xF8 -> byteArrayOf((serial shr 24).toByte(), (serial shr 16).toByte(), (serial shr 8).toByte(), serial.toByte()) + sw(0x9000)
            0x20 -> {
                val pin = String(apdu.copyOfRange(5, 13)).trimEnd('￿', 'ÿ').filter { it.isDigit() }
                if (pin == "123456") { pinVerified = true; sw(0x9000) } else sw(0x63C2)
            }
            0xCB -> {
                val obj = Tlv.encode(0x53, Tlv.encode(0x70, certDer) + Tlv.encode(0x71, byteArrayOf(0)) + Tlv.encode(0xFE, ByteArray(0)))
                pending = obj
                chunk()
            }
            0xC0 -> chunk()
            0x87 -> {
                if (!pinVerified) return sw(0x6982)
                ecdhCalls++
                val template = Tlv.find(apdu.copyOfRange(5, 5 + (apdu[4].toInt() and 0xff)), 0x7C)!!
                val peer = Tlv.find(template, 0x85)!!
                val secret = P256SoftwareKey(key).sharedX(peer)
                Tlv.encode(0x7C, Tlv.encode(0x82, secret)) + sw(0x9000)
            }
            else -> sw(0x6D00)
        }
    }

    private fun chunk(): ByteArray {
        val n = minOf(200, pending.size)
        val out = pending.copyOfRange(0, n)
        pending = pending.copyOfRange(n, pending.size)
        return out + if (pending.isEmpty()) sw(0x9000) else sw(0x6100 or minOf(pending.size, 255))
    }

    private fun sw(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())
}

class YubiKeyPivTest {
    private val key = BigInteger("60cda4181bd5744a6c0b3ecadc89f7ca528c4dea68c8643549c163e93fd2f587", 16)
    private val certDer = Base64.getDecoder().decode("MIIBxzCCAW2gAwIBAgIUDyEblkoM2MCTYtnPpEzaivk20yIwCgYIKoZIzj0EAwIwOTEaMBgGA1UEAwwRYWdlIGlkZW50aXR5IFRFU1QxGzAZBgNVBAoMEmFnZS1wbHVnaW4teXViaWtleTAeFw0yNjA5MjMwMzAzMDFaFw0zNjA5MjAwMzAzMDFaMDkxGjAYBgNVBAMMEWFnZSBpZGVudGl0eSBURVNUMRswGQYDVQQKDBJhZ2UtcGx1Z2luLXl1YmlrZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQJPmrO6hFIw1SMqKOwZlg5+E2FNTBK7AdpaiUCpv3Gv/NLuvgMa+jCYTESnvtcUb7UfX1TCr6+HJlZzEgqvP1bo1MwUTAdBgNVHQ4EFgQUMGDL+y60S+eoXlwcltyFx5GlD5gwHwYDVR0jBBgwFoAUMGDL+y60S+eoXlwcltyFx5GlD5gwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBDJsrW5Difydm8s6SQEvpqskTc/u4aIWV6wEL/uwwYAwIhAKOAQ13PEjt/kV5Mc2knLK6aTLyE1L4IsEH0kiZswp2E")
    private val compressedPub = P256Curve.compressed(P256Curve.publicPoint(key))

    private fun cardKa(card: FakePivCard, pin: String?) = P256KeyAgreement { peer ->
        Piv.select(card)
        try {
            Piv.ecdh(card, 0x82, peer)
        } catch (e: Piv.PinRequiredException) {
            Piv.verifyPin(card, pin ?: throw e)
            Piv.ecdh(card, 0x82, peer)
        }
    }

    @Test
    fun readsPublicKeyAndSerialThroughChaining() {
        val card = FakePivCard(key, certDer)
        Piv.select(card)
        assertEquals(12345678L, Piv.serial(card))
        assertArrayEquals(compressedPub, Piv.readPublicKey(card, 0x82))
    }

    @Test
    fun stubRoundTrip() {
        val stub = YubiKeyStub(12345678, 0x82, YubiKeyStub.staticTag(compressedPub))
        val s = stub.encode()
        assertTrue(s.startsWith("AGE-PLUGIN-YUBIKEY-1"), s)
        assertTrue(YubiKeyStub.isStub(s))
        assertEquals(stub, YubiKeyStub.parse(s))
        assertTrue(stub.matchesKey(compressedPub))
        assertThrows<Exception> { YubiKeyStub(1, 0x9a, ByteArray(4)) }
    }

    @Test
    fun decryptsPivP256AndP256TagWithOneEcdhEach() {
        val stub = YubiKeyStub(12345678, 0x82, YubiKeyStub.staticTag(compressedPub))
        val card = FakePivCard(key, certDer)
        val id = YubiKeyIdentity(stub, compressedPub, cardKa(card, "123456"))
        val pt = "for the yubikey".toByteArray()

        val legacy = Age.encrypt(pt, listOf(P256Recipient(compressedPub)))
        assertArrayEquals(pt, Age.decrypt(legacy, listOf(id)))
        val tagged = Age.encrypt(pt, listOf(TagRecipient(compressedPub)))
        assertArrayEquals(pt, Age.decrypt(tagged, listOf(id)))
        assertEquals(2, card.ecdhCalls)
    }

    @Test
    fun softwareRecipientWinsWithoutTouchingTheCard() {
        val stub = YubiKeyStub(12345678, 0x82, YubiKeyStub.staticTag(compressedPub))
        val card = FakePivCard(key, certDer)
        val id = YubiKeyIdentity(stub, compressedPub, cardKa(card, null))
        val x = X25519Identity.generate()
        val ct = Age.encrypt("x".toByteArray(), listOf(P256Recipient(compressedPub), X25519Recipient(x.publicKey)))
        Age.decrypt(ct, listOf(id, x))
        assertEquals(0, card.ecdhCalls)
        assertTrue(Age.canDecryptStream(ct.inputStream(), listOf(id)))
        assertEquals(0, card.ecdhCalls)
    }

    @Test
    fun wrongPinReportsTriesLeft() {
        val card = FakePivCard(key, certDer)
        Piv.select(card)
        val e = assertThrows<Piv.WrongPinException> { Piv.verifyPin(card, "000000") }
        assertEquals(2, e.retriesLeft)
        assertThrows<Piv.PinRequiredException> { Piv.ecdh(card, 0x82, P256Curve.uncompressed(P256Curve.publicPoint(BigInteger.TEN))) }
        assertFalse(card.pinVerified)
    }

    @Test
    fun ageCliTagFileOpensOnTheYubiKey() {
        val age = AgeCli.find(); assumeTrue(age != null && age.atLeast(1, 3), "needs age >= 1.3.0")
        val stub = YubiKeyStub(12345678, 0x82, YubiKeyStub.staticTag(compressedPub))
        val id = YubiKeyIdentity(stub, compressedPub, cardKa(FakePivCard(key, certDer), "123456"))
        val pt = "from the age cli".toByteArray()
        assertArrayEquals(pt, Age.decrypt(age!!.encrypt(pt, TagRecipient(compressedPub).toBech32()), listOf(id)))
    }
}
