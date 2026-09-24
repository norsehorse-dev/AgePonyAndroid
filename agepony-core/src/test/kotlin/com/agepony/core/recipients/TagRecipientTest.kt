package com.agepony.core.recipients

import com.agepony.core.Age
import com.agepony.core.crypto.HpkeP256
import com.agepony.core.crypto.P256KeyAgreement
import com.agepony.core.crypto.P256SoftwareKey
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom

class TagRecipientTest {

    // Recipients of age's own test plugin (filippo.io/age tag/internal/age-plugin-tagtest), derived
    // with HPKE DeriveKeyPair from the ikm "age-plugin-tagtest". Matching them proves our KEM key
    // derivation, point encoding and Bech32 layout agree with age 1.3.
    private val tagtestClassic = "age1tag1qwe0kafsjrar4txm6heqnhpfuggzr0gvznz7fvygxrlq90u5mq2pysxtw6h"
    private val tagtestHybridPrefix = "age1tagpq14h4z7cks9sxftfc8tq4xektt4854ur9rv76tvujdvtzk2fmyywkvh9z2emz3x4epvhz7qdt2v7uksyyq2cdzf3k04ny0g5sc3u4heqh3r9v4cnwhfjw0a2azpgmnk9xk02wvywt5szcq6q3jvwsjxvkn3tsk52vqjczdcvc398ym4j6cvqas4w99gkgt7ur3fmt4g873phr23tgxw3f7wgsz9zxz7m8cp27vpq3h5vc8nssjemtr2etmtmqkg4fzn2u9x9zvtysuya5yrytgx482ftx9864h8a6pprarxd3d0qe8nw2at5ekg3tsahtef7kawasxjamyckw2ans6v933vuypcfrra32f89r2v72mka9hhc55s49xe2khfsq7w9r2zynuzfx4fg6v7jjncsc87rw2yy8qp8hr27edus6zw5xd6m3hax2nxhl2dys9792z3wp5c034sfkrxe86guj7pfdh7sytzrufl9euhuhyf9w6c7z2nwf7v5v8f2s4gplgvfx4jj4le22k2qn242qkqkcwx7llfyrct7jm2wcv0ytypeh6h93ezgtd7q6zr428qze3dec5jxlc5xxjetyephp42fljft3s02p0570kjwyfeyjcnks2vglkvyus5g9l4z6m0gf8wu22ygfm40028txwjlxvvgnn7c36z783c6tmc9k5nef8nucj6u3ustff5vhtnzhnscsvsz79wzrkv3sujtntx4wezucy6lp49flmnyydn3khk2xsesw0ekn4u44nzqw2g2rjyrrl7crshlzttgpe0jvqycjzp9kmtz23t3yu0w9j4n344nnrf88k2jqqfpjxte38pcn0epr879pqsuvajxrkmsas89pvfrzwcewneujn08guj5pvvrtn5hzzg2y6u4wwjqqxx4x8w65yc4dchf750dft8kgcttt2f6j0j5v8s7tkaua78tte7artdfar544vl0rau79h95mc4ghp887z82s6rq93txpkvan86n963kagqkldngnkjcn28zdrh38vdxj002zqs9mx7zjvg3ynzdfhfakkynt9fyqpaxpsdrsqrycuhw5ykwgjz6wldef7xtu6p689234hstxe7v8e5422f2dy8ystn57z3fvy9yfrm4t3lye6ejk5n6x8zqexmql7lx965xcxuuy38xzyt8j9qprnwgfqgx54l4tnjdpzdde6xgmwtnpkfwvyr7rkgnavvjn6a3e56wtvjx3evmhjjxvukpq5zqrj0s4sntkz3yeszs5dty8q0q6m7dgp6mjpvaer0c4343g72eycfqzkjupeaemh0n8e935hqs8fh3jgk7fzyxctzuqlx6d2q9jaf8r9wu4sjxj5w6ppw7m9c3hxrzpcv2uek3kxnndgf2hd99q9v2ux8pjkv29ntslvnvhy09dvcy9578rt89gf4cj4cu79zjxtlj3dpct6rjme02zj3qspsade96njkkufu9zuq2lk3qwvddpxjkqm2hnpqwck54zug7ctvkgvk325lwkg4q5rf73zkgys5e9y8jqc96ntdyl4r78lgtw4k5uljk5ttf46s3gc0rq0jwmddnxt875twwq92505zh3zkse5ag2dhjjxyfzkn7xv3j0kv9r3jzpvgep8fq6z8mar509u4fvnhvthp2ah0r45lsyq0mm6fwkcs30v8k9wzvgt6uvcty6qsjvarjs3htym69zu43m4jd3k4tllrr8c05v6p6spuhup4hkk2p9fp9lxafe3pntcn4nk83gzhjjpcjwyg7jcyz5uancu0fakgz27up7ymzp2xv3sqyqewkkqynskw9qkvysrncxj0cy7dt6q8dsseuwmc2urfmcvkykf82wfa54t85hqx8gywhmhzunm2x0d66a4pwl0xl78fhkces5dpq8pfnp35m5a3u8vdam64zx5s5x9cmnrx3zr066f4f8hlecqnq2fd5quw79ljg3q5nvs6ggmm4gkc"

    private val ikm = "age-plugin-tagtest".toByteArray()
    private val fileKey = ByteArray(16).also { SecureRandom().nextBytes(it) }

    fun tagtestClassicIdentity() = TagIdentity.softwareClassic(HpkeP256.dhkemDeriveKeyPair(ikm))
    fun tagtestHybridIdentity() = TagIdentity.softwareHybrid(HpkeP256.hybridDeriveSeed(ikm))

    @Test
    fun classicDerivationMatchesAgeTagtest() {
        assertEquals(tagtestClassic, tagtestClassicIdentity().recipient.toBech32())
    }

    @Test
    fun hybridDerivationMatchesAgeTagtest() {
        assertEquals(tagtestHybridPrefix, tagtestHybridIdentity().recipient.toBech32())
    }

    @Test
    fun parsesBothEncodingsAndRoundTripsBech32() {
        val c = TagRecipient(tagtestClassic)
        assertFalse(c.hybrid); assertEquals(tagtestClassic, c.toBech32())
        val h = TagRecipient(tagtestHybridPrefix)
        assertTrue(h.hybrid); assertEquals(tagtestHybridPrefix, h.toBech32())
        assertEquals(setOf(POSTQUANTUM_LABEL), h.labels())
        assertTrue(TagRecipient.isTagRecipient(tagtestClassic))
        assertTrue(TagRecipient.isTagRecipient(tagtestHybridPrefix))
        assertFalse(TagRecipient.isTagRecipient("age1qqq"))
    }

    @Test
    fun rejectsWrongHrpAndBadPoints() {
        assertThrows<Exception> { TagRecipient("age1yubikey1qtlu4dlqkg0tg6nswpgmhw34vpszdeaffzp4f6fgpemlvxqcvzv35hnavmu") }
        assertThrows<Exception> { TagRecipient(ByteArray(33) { 5 }) }
        assertThrows<Exception> { TagRecipient(ByteArray(40) { 2 }) }
    }

    @Test
    fun classicWrapUnwrap() {
        val id = TagIdentity.softwareClassic(HpkeP256.dhkemDeriveKeyPair(ByteArray(8) { 7 }))
        val s = id.recipient.wrap(fileKey)
        assertEquals("p256tag", s.type)
        assertEquals(2, s.args.size)
        assertTrue(id.matches(s))
        assertArrayEquals(fileKey, id.unwrap(s))
    }

    @Test
    fun hybridWrapUnwrap() {
        val id = TagIdentity.softwareHybrid(ByteArray(32) { it.toByte() })
        val s = id.recipient.wrap(fileKey)
        assertEquals("mlkem768p256tag", s.type)
        assertArrayEquals(fileKey, id.unwrap(s))
    }

    @Test
    fun wrongIdentityNeverTouchesItsKey() {
        val mine = tagtestClassicIdentity()
        var calls = 0
        val other = P256SoftwareKey.generate()
        val counting = P256KeyAgreement { calls++; other.sharedX(it) }
        val theirs = TagIdentity.classic(other.publicUncompressed, counting)
        val s = mine.recipient.wrap(fileKey)
        assertFalse(theirs.matches(s))
        assertNull(theirs.unwrap(s))
        assertEquals(0, calls, "a stanza for another key must be rejected on the tag, before ECDH")
    }

    @Test
    fun fullFileRoundTrip() {
        val id = tagtestHybridIdentity()
        val pt = "hardware bound".toByteArray()
        assertArrayEquals(pt, Age.decrypt(Age.encrypt(pt, listOf(id.recipient)), listOf(id)))
        val cid = tagtestClassicIdentity()
        val x = X25519Identity.generate()
        val ct = Age.encrypt(pt, listOf(cid.recipient, X25519Recipient(x.publicKey)))
        assertArrayEquals(pt, Age.decrypt(ct, listOf(cid)))
        assertArrayEquals(pt, Age.decrypt(ct, listOf(x)))
    }

    @Test
    fun hybridRefusesMixingWithClassicRecipients() {
        val h = tagtestHybridIdentity().recipient
        val x = X25519Recipient(X25519Identity.generate().publicKey)
        assertThrows<Exception> { Age.encrypt("x".toByteArray(), listOf(h, x)) }
        assertThrows<Exception> { Age.encrypt("x".toByteArray(), listOf(h, tagtestClassicIdentity().recipient)) }
        // Hybrid tag + native PQ recipient is fine.
        Age.encrypt("x".toByteArray(), listOf(h, HybridIdentity.generate().recipient()))
    }

    @Test
    fun failingHardwareKeyDoesNotBlockASoftwareRecipient() {
        val hw = P256SoftwareKey.generate()
        val broken = TagIdentity.classic(hw.publicUncompressed, P256KeyAgreement { throw IllegalStateException("prompt cancelled") })
        val backup = X25519Identity.generate()
        val pt = "two recipients".toByteArray()
        // Hardware stanza first in the header, as it would be when the user lists it first.
        val ct = Age.encrypt(pt, listOf(broken.recipient, X25519Recipient(backup.publicKey)))
        assertArrayEquals(pt, Age.decrypt(ct, listOf(broken, backup)))
        // With only the broken key, its own error surfaces rather than "no matching identity".
        val e = assertThrows<IllegalStateException> { Age.decrypt(ct, listOf(broken)) }
        assertEquals("prompt cancelled", e.message)
    }

    @Test
    fun rejectsSec1HybridPointEncodings() {
        val pt = P256SoftwareKey.generate().publicUncompressed.copyOf()
        pt[0] = 0x06
        assertThrows<Exception> { com.agepony.core.crypto.P256Curve.decode(pt) }
    }
}
