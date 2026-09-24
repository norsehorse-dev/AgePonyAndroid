package com.agepony.core.ssh

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset

/** allowed_signers options are parsed and enforced the way ssh-keygen -Y verify does (audit L-6). */
class AllowedSignersOptionsTests {

    private val key = "AAAAC3NzaC1lZDI1NTE5AAAAILr/NVvNaGxfkVp8Ni/Z3ubM8/k89JoVOg8oMJeid1tU"
    private val utc = ZoneOffset.UTC
    private val now = Instant.parse("2026-06-01T12:00:00Z")

    private fun entry(options: String?) =
        AllowedSigners.parseLine("alice@example.com ${options?.let { "$it " } ?: ""}ssh-ed25519 $key")!!

    // --- tokenizing ---

    @Test
    fun quotedValueMayHoldCommasAndSpaces() {
        val line = "alice@example.com namespaces=\"agepony, git\",valid-after=\"20240101\" ssh-ed25519 $key the comment"
        val s = AllowedSigners.parseLine(line)!!
        assertEquals("namespaces=\"agepony, git\",valid-after=\"20240101\"", s.options)
        assertEquals("ssh-ed25519", s.keyType)
        assertEquals(key, s.keyBase64)
        assertEquals("the comment", s.comment)
        val o = s.parsedOptions(utc)
        assertNull(o.error)
        assertEquals("agepony, git", o.namespaces)
        assertEquals(Instant.parse("2024-01-01T00:00:00Z"), o.validAfter)
        // Lossless: the raw field goes back out verbatim.
        assertEquals(line + "\n", AllowedSigners.serialize(listOf(s)))
        assertEquals(s, AllowedSigners.parse(AllowedSigners.serialize(listOf(s)))[0])
    }

    @Test
    fun escapedQuoteInsideAValue() {
        val o = AllowedSignerOptions.parse("namespaces=\"a\\\"b,c\"", utc)
        assertNull(o.error)
        assertEquals("a\"b,c", o.namespaces)
    }

    @Test
    fun unterminatedQuoteDropsTheLine() {
        assertNull(AllowedSigners.parseLine("alice namespaces=\"agepony ssh-ed25519 $key"))
    }

    @Test
    fun tabsSeparateFields() {
        val s = AllowedSigners.parseLine("alice@example.com\tcert-authority\tssh-ed25519\t$key")!!
        assertEquals("cert-authority", s.options)
        assertTrue(s.isCertAuthority)
    }

    @Test
    fun quotedPrincipalsRoundTrip() {
        val s = AllowedSigners.parseLine("\"alice smith,bob\" ssh-ed25519 $key")!!
        assertEquals(listOf("alice smith", "bob"), s.principals)
        val text = AllowedSigners.serialize(listOf(s))
        assertEquals("\"alice smith,bob\" ssh-ed25519 $key\n", text)
        assertEquals(s, AllowedSigners.parse(text)[0])
    }

    // --- dates ---

    @Test
    fun dateFormats() {
        val z = ZoneId.of("America/New_York")
        fun after(v: String, zone: ZoneId = utc) = AllowedSignerOptions.parse("valid-after=\"$v\"", zone)
        assertEquals(Instant.parse("2025-03-04T00:00:00Z"), after("20250304Z").validAfter)
        assertEquals(Instant.parse("2025-03-04T05:06:00Z"), after("202503040506Z").validAfter)
        assertEquals(Instant.parse("2025-03-04T05:06:07Z"), after("20250304050607Z").validAfter)
        assertEquals(Instant.parse("2025-03-04T05:06:07Z"), after("20250304050607utc").validAfter)
        // No suffix: local time in the supplied zone (EST is UTC-5 in March before DST).
        assertEquals(Instant.parse("2025-03-04T05:00:00Z"), after("20250304", z).validAfter)
        assertEquals(LocalDateTime.of(2025, 3, 4, 5, 6).atZone(z).toInstant(), after("202503040506", z).validAfter)
        // Unquoted is accepted too.
        assertEquals(Instant.parse("2025-03-04T00:00:00Z"), AllowedSignerOptions.parse("valid-after=20250304Z", utc).validAfter)
    }

    @Test
    fun badDatesAreErrors() {
        for (v in listOf("2025030", "202503041", "20251301", "20250230", "2025-03-04", "20250304T", "", "Z", "19700101Z")) {
            val o = AllowedSignerOptions.parse("valid-before=\"$v\"", utc)
            assertNotNull(o.error, "should reject '$v'")
            assertFalse(o.permits("agepony", now), "should not permit with '$v'")
        }
    }

    @Test
    fun validBeforeMustFollowValidAfter() {
        assertNotNull(AllowedSignerOptions.parse("valid-after=\"20250101Z\",valid-before=\"20250101Z\"", utc).error)
        assertNotNull(AllowedSignerOptions.parse("valid-after=\"20250102Z\",valid-before=\"20250101Z\"", utc).error)
        assertNull(AllowedSignerOptions.parse("valid-after=\"20250101Z\",valid-before=\"20250102Z\"", utc).error)
    }

    @Test
    fun duplicateClausesAreErrors() {
        assertNotNull(AllowedSignerOptions.parse("namespaces=\"a\",namespaces=\"b\"", utc).error)
        assertNotNull(AllowedSignerOptions.parse("valid-after=\"20250101Z\",valid-after=\"20250102Z\"", utc).error)
        assertNotNull(AllowedSignerOptions.parse("cert-authority,,no-touch-required", utc).error)
    }

    // --- permits() matrix ---

    @Test
    fun noOptionsPermitsEverything() {
        val s = entry(null)
        assertTrue(s.permits("agepony", now, utc))
        assertTrue(s.permits("git", now, utc))
        assertFalse(s.isCertAuthority)
        assertTrue(s.requiresTouch)
        assertFalse(s.requiresUserVerification)
        assertEquals(emptyList<String>(), s.unknownOptions)
    }

    @Test
    fun namespacesRestrict() {
        val s = entry("namespaces=\"agepony\"")
        assertTrue(s.permits("agepony", now, utc))
        assertFalse(s.permits("git", now, utc))
        assertFalse(s.permits("agepony-sig-v2", now, utc))
        assertFalse(s.permits("Agepony", now, utc)) // case-sensitive, like OpenSSH
    }

    @Test
    fun namespacePatterns() {
        val s = entry("namespaces=\"agepony*,?it,file\"")
        assertTrue(s.permits("agepony", now, utc))
        assertTrue(s.permits("agepony-bundle-v2", now, utc))
        assertTrue(s.permits("git", now, utc))
        assertTrue(s.permits("file", now, utc))
        assertFalse(s.permits("gitx", now, utc))
        assertFalse(s.permits("files", now, utc))

        val neg = entry("namespaces=\"*,!git\"")
        assertTrue(neg.permits("agepony", now, utc))
        assertFalse(neg.permits("git", now, utc))

        assertEquals(1, AllowedSignerOptions.matchPatternList("abc", "a*c"))
        assertEquals(1, AllowedSignerOptions.matchPatternList("ac", "a*c"))
        assertEquals(0, AllowedSignerOptions.matchPatternList("abd", "a*c"))
        assertEquals(-1, AllowedSignerOptions.matchPatternList("abc", "a*,!a?c"))
        assertEquals(0, AllowedSignerOptions.matchPatternList("git", "agepony, git")) // not trimmed
    }

    @Test
    fun agePonyFamilyCoversTheV2Namespaces() {
        val s = entry("namespaces=\"agepony\"")
        assertTrue(s.permitsAgePony("agepony", now, utc))
        assertTrue(s.permitsAgePony("agepony-sig-v2", now, utc))
        assertTrue(s.permitsAgePony("agepony-bundle-v2", now, utc))
        assertFalse(s.permitsAgePony("git", now, utc))
        assertFalse(entry("namespaces=\"git\"").permitsAgePony("agepony-sig-v2", now, utc))
        assertFalse(entry("namespaces=\"agepony,!agepony-sig-v2\"").permitsAgePony("agepony-sig-v2", now, utc))
    }

    @Test
    fun certAuthorityPermitsNothing() {
        val s = entry("Cert-Authority")
        assertTrue(s.isCertAuthority)
        assertFalse(s.permits("agepony", now, utc))
        assertFalse(s.permitsAgePony("agepony", now, utc))
    }

    @Test
    fun unknownOptionsPermitNothing() {
        val s = entry("namespaces=\"agepony\",restrict,from=\"10.0.0.1\"")
        assertEquals(listOf("restrict", "from=\"10.0.0.1\""), s.unknownOptions)
        assertFalse(s.permits("agepony", now, utc))
        // A known flag with a value, or a valued option without one, is unknown too.
        assertEquals(listOf("cert-authority=\"x\""), entry("cert-authority=\"x\"").unknownOptions)
        assertEquals(listOf("namespaces"), entry("namespaces").unknownOptions)
    }

    @Test
    fun validityWindow() {
        val s = entry("valid-after=\"20260101Z\",valid-before=\"20261231235959Z\"")
        assertTrue(s.permits("agepony", now, utc))
        assertFalse(s.permits("agepony", Instant.parse("2025-12-31T23:59:59Z"), utc))
        assertTrue(s.permits("agepony", Instant.parse("2026-01-01T00:00:00Z"), utc)) // inclusive
        assertTrue(s.permits("agepony", Instant.parse("2026-12-31T23:59:59Z"), utc)) // inclusive
        assertFalse(s.permits("agepony", Instant.parse("2027-01-01T00:00:00Z"), utc))
        assertFalse(entry("valid-before=\"20200101\"").permits("agepony", now, utc))
        assertFalse(entry("valid-after=\"20300101\"").permits("agepony", now, utc))
    }

    @Test
    fun localTimeUsesTheSuppliedZone() {
        // Midnight 1 June in Tokyo is 15:00 UTC on 31 May.
        val s = entry("valid-after=\"20260601\"")
        val tokyo = ZoneId.of("Asia/Tokyo")
        assertTrue(s.permits("agepony", Instant.parse("2026-05-31T15:00:00Z"), tokyo))
        assertFalse(s.permits("agepony", Instant.parse("2026-05-31T14:59:59Z"), tokyo))
        assertFalse(s.permits("agepony", Instant.parse("2026-05-31T15:00:00Z"), utc))
    }

    @Test
    fun touchAndVerifyFlags() {
        assertFalse(entry("no-touch-required").requiresTouch)
        assertTrue(entry("verify-required").requiresUserVerification)
        assertTrue(entry("no-touch-required,verify-required,namespaces=\"agepony\"").permits("agepony", now, utc))
    }

    @Test
    fun makeSignerOutputStillParsesAsRestricted() {
        val s = AllowedSigners.makeSigner(listOf("a"), "ssh-ed25519 $key", namespaceRestricted = true)!!
        assertTrue(s.permits("agepony", now, utc))
        assertFalse(s.permits("git", now, utc))
    }
}
