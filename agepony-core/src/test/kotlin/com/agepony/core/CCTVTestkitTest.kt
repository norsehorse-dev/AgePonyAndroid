package com.agepony.core

import com.agepony.core.recipients.AgeIdentity
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.ScryptIdentity
import com.agepony.core.recipients.X25519Identity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.net.JarURLConnection
import java.security.MessageDigest
import java.util.HexFormat
import java.util.zip.InflaterInputStream

/**
 * Runs the C2SP CCTV age test vectors (github.com/C2SP/CCTV, `age/testdata`) through the core's
 * real decrypt path: [Armor.decode] for armored files, then the streaming [Age.decryptStream],
 * hashing every plaintext byte it releases. Port of the iOS `CCTVTestkitTests.swift`.
 *
 * Source and updating: the vectors live in `src/test/resources/cctv-testkit/` (copied as is from
 * the iOS repo's `Tests/AgePonyCoreTests/Testkit`, commit recorded in `SOURCE.md`, format in
 * `CCTV-README.md`, iOS runner notes in `RUNNER-NOTES.md`). To update, replace the vector files,
 * record the new commit in SOURCE.md, then set [EXPECTED_VECTOR_COUNT] (and [EXPECTED_SKIPPED]
 * if a vector uses a header key this runner doesn't know) to match the new set.
 *
 * Error mapping ([categoryOf]). CCTV has six expected results; the core's exceptions map onto
 * them as follows. Rows marked "alias" are places where the core can't tell two CCTV results
 * apart or files the failure at a different stage than Go age does.
 *
 *   Armor.ArmorException                         -> armor failure
 *   AgeHeader.HeaderException "MAC verification failed" -> HMAC failure
 *   AgeHeader.HeaderException (any other)        -> header failure (includes scrypt-not-alone and
 *                                                   a file key that isn't 16 bytes)
 *   AgePayload.PayloadException "payload too short ..." -> header failure (alias: the core reads
 *                                                   the 16-byte nonce in the payload stage; CCTV
 *                                                   counts a missing/short nonce as header)
 *   AgePayload.PayloadException (any other)      -> payload failure
 *   Age.NoMatchingIdentityException              -> no match
 *   anything else                                -> "unexpected error" (never matches)
 *
 * Alias "no match" for "header failure": [AgeIdentity.unwrap] returns null both for "not for me"
 * and for a stanza of its own type that it can't use (wrong argument count, non-canonical or
 * wrong-length share/salt, malformed or too-high work factor, low-order share, wrapped key that
 * isn't 16+16 bytes; audits L-5 and L-14). Go age fails the header for those. So `no match` is
 * accepted for an expected `header failure` only when the header itself parsed and at least one
 * stanza has a type one of the vector's identities handles (X25519, mlkem768x25519, scrypt).
 * Every vector passing through this alias is listed in the output.
 *
 * [KNOWN_DIVERGENCES] lists vectors the core deliberately handles differently, each with the
 * exact outcome expected instead and why. An entry only waives that specific outcome, and the
 * test fails if a listed vector starts passing, so the list can't go stale. The list started as
 * the iOS one; the first Android run is what confirms it.
 *
 * Output: every vector's result goes to stdout and to `build/reports/cctv-testkit/results.txt`
 * (module directory), and the assertion message lists each mismatch as name, expected, got.
 */
class CCTVTestkitTest {

    enum class Category(val label: String) {
        SUCCESS("success"),
        NO_MATCH("no match"),
        HMAC_FAILURE("HMAC failure"),
        HEADER_FAILURE("header failure"),
        PAYLOAD_FAILURE("payload failure"),
        ARMOR_FAILURE("armor failure"),

        /** Not a CCTV category: an exception the mapping doesn't know, or a runner problem. */
        UNEXPECTED("unexpected error");

        companion object {
            fun fromLabel(s: String): Category? =
                Category.entries.firstOrNull { it.label == s && it != Category.UNEXPECTED }
        }
    }

    private class KnownDivergence(
        /** The category the core gives instead of the expected one. */
        val actual: Category,
        /** True when the category matches and only the released-plaintext hash differs. */
        val hashOnly: Boolean,
        val reason: String,
    )

    private class Vector(
        val name: String,
        val expect: Category,
        val payloadHash: String?,
        val identities: List<String>,
        val passphrases: List<String>,
        val armored: Boolean,
        val compressed: Boolean,
        val body: ByteArray,
    )

    private sealed class Parsed {
        class Ok(val vector: Vector) : Parsed()
        class Skipped(val reason: String) : Parsed()
    }

    private class Outcome(
        val category: Category,
        val detail: String,
        val releasedHash: String,
        /** Stanza types in the header, when it parsed (used by the alias). */
        val stanzaTypes: Set<String>?,
        /** Stanza types the vector's identities handle. */
        val handledTypes: Set<String>,
    )

    companion object {
        private const val RESOURCE_DIR = "cctv-testkit"

        /** Vectors at CCTV commit 50a8ecf (see SOURCE.md). */
        private const val EXPECTED_VECTOR_COUNT = 147

        /** Vectors this runner is expected to skip for using an unknown header key. None today. */
        private val EXPECTED_SKIPPED: Set<String> = emptySet()

        /** Files in the folder that aren't vectors. */
        private val NON_VECTOR_FILES = setOf("CCTV-README.md", "SOURCE.md", "RUNNER-NOTES.md")

        private const val ARMOR_WHITESPACE =
            "Armor.decode trims whitespace (spaces, tabs, CR) from both ends of each armor line, on " +
                "purpose, so armor pasted from mail or chat still opens. Go age rejects this input. " +
                "The decoded bytes are the same either way."

        private const val ARMOR_BLANK_BEFORE_END =
            "The core accepts one blank line between a full 64-column final line and END, as age " +
                "1.1.1 does, so armor from older age versions still opens (StrictFormatTests " +
                "armorWithAFullFinalLineOpensHereAndInGo). Newer age and CCTV reject it. Two blank " +
                "lines are still refused."

        private const val STREAM_READ_AHEAD =
            "AgePayload.decryptStream looks ahead before opening a full chunk and only opens it once " +
                "it knows whether it is the last one, so it never releases a chunk it then has to " +
                "reject. Go age opens the chunk first (retrying it as final) and fails afterwards, so " +
                "it releases one more chunk before the error. Same category; shorter released prefix."

        /**
         * Started as the iOS list (RUNNER-NOTES.md); confirm against the first Android run.
         *
         * One iOS entry is left out: `stream_short_second_chunk` (a full chunk, then 12 bytes).
         * iOS reads the whole next chunk before opening the first, so it never releases it. This
         * core only peeks one byte past a full chunk, opens and releases it as non-final, and
         * then fails on the short one, exactly as Go does, so the vector should pass here. A
         * Python model of this core's reader reproduced the CCTV hash for it.
         */
        private val KNOWN_DIVERGENCES: Map<String, KnownDivergence> = mapOf(
            "armor_cr_line_start" to KnownDivergence(Category.SUCCESS, false, ARMOR_WHITESPACE),
            "armor_double_crlf" to KnownDivergence(Category.SUCCESS, false, ARMOR_WHITESPACE),
            "armor_whitespace_eol" to KnownDivergence(Category.SUCCESS, false, ARMOR_WHITESPACE),
            "armor_whitespace_last_line" to KnownDivergence(Category.SUCCESS, false, ARMOR_WHITESPACE),
            "armor_whitespace_line_start" to KnownDivergence(Category.SUCCESS, false, ARMOR_WHITESPACE),
            "armor_empty_last_line" to KnownDivergence(Category.SUCCESS, false, ARMOR_BLANK_BEFORE_END),

            "armor_garbage_encoded" to KnownDivergence(Category.PAYLOAD_FAILURE, true, STREAM_READ_AHEAD),
            "stream_no_final_full" to KnownDivergence(Category.PAYLOAD_FAILURE, true, STREAM_READ_AHEAD),
            "stream_no_final_two_chunks_full" to KnownDivergence(Category.PAYLOAD_FAILURE, true, STREAM_READ_AHEAD),
            "stream_trailing_garbage_long" to KnownDivergence(Category.PAYLOAD_FAILURE, true, STREAM_READ_AHEAD),
            "stream_trailing_garbage_short" to KnownDivergence(Category.PAYLOAD_FAILURE, true, STREAM_READ_AHEAD),
            "stream_two_final_chunks" to KnownDivergence(Category.PAYLOAD_FAILURE, true, STREAM_READ_AHEAD),
            "stream_two_final_chunks_full" to KnownDivergence(Category.PAYLOAD_FAILURE, true, STREAM_READ_AHEAD),
            "stream_two_final_chunks_second" to KnownDivergence(Category.PAYLOAD_FAILURE, true, STREAM_READ_AHEAD),
        )

        /**
         * Stand-in for a vector with no identity or passphrase (`empty`, `armor_empty`):
         * [Age.decryptStream] requires a non-empty list, and an identity that never matches is
         * the same as having none. Those vectors fail in the header before any identity runs.
         */
        private val NO_IDENTITY = AgeIdentity { null }

        private val HEX = HexFormat.of()
    }

    @Test
    fun cctvVectors() {
        val files = loadVectorFiles()
            .filter { (name, _) -> !name.startsWith(".") && name !in NON_VECTOR_FILES }
            .sortedBy { it.first }

        var processed = 0
        val skipped = mutableListOf<String>()
        val failures = mutableListOf<String>()
        val aliased = mutableListOf<String>()
        val waived = mutableListOf<String>()
        val table = mutableListOf<String>()
        val seen = mutableSetOf<String>()

        for ((name, raw) in files) {
            seen.add(name)
            val vector = when (val p = parse(name, raw)) {
                is Parsed.Skipped -> {
                    skipped.add("$name (${p.reason})")
                    table.add("$name | skipped | ${p.reason}")
                    continue
                }
                is Parsed.Ok -> p.vector
            }
            processed++

            val outcome = run(vector)
            val divergence = KNOWN_DIVERGENCES[name]

            // Compare category, then the released-plaintext hash where CCTV gives one.
            var categoryOK = outcome.category == vector.expect
            var usedAlias = false
            if (!categoryOK && vector.expect == Category.HEADER_FAILURE && outcome.category == Category.NO_MATCH) {
                val types = outcome.stanzaTypes
                if (types != null && types.any { it in outcome.handledTypes }) {
                    categoryOK = true
                    usedAlias = true
                }
            }
            var hashOK = true
            if (categoryOK && outcome.category == vector.expect &&
                (vector.expect == Category.SUCCESS || vector.expect == Category.PAYLOAD_FAILURE)
            ) {
                hashOK = outcome.releasedHash == vector.payloadHash?.lowercase()
            }
            val passes = categoryOK && hashOK
            val got = "${outcome.category.label} (${outcome.detail})"

            if (passes) {
                if (usedAlias) aliased.add("$name: ${outcome.detail}")
                if (divergence != null) {
                    failures.add("$name: expected ${vector.expect.label}, got $got; listed in KNOWN_DIVERGENCES but now passes, remove the entry")
                    table.add("$name | ${vector.expect.label} | $got | STALE DIVERGENCE")
                } else {
                    table.add("$name | ${vector.expect.label} | $got | ${if (usedAlias) "pass (alias)" else "pass"}")
                }
                continue
            }

            val summary = if (!categoryOK) {
                "expected ${vector.expect.label}, got $got"
            } else {
                "expected ${vector.expect.label}, got ${outcome.category.label} as expected but released " +
                    "plaintext SHA-256 ${outcome.releasedHash} != payload ${vector.payloadHash ?: "(none)"}"
            }

            if (divergence != null) {
                val covered = if (divergence.hashOnly) {
                    categoryOK && !hashOK && outcome.category == divergence.actual
                } else {
                    !categoryOK && outcome.category == divergence.actual
                }
                if (covered) {
                    waived.add("$name: $summary")
                    table.add("$name | ${vector.expect.label} | $got | waived (known divergence)")
                    continue
                }
                val expectedText = if (divergence.hashOnly) "${divergence.actual.label}, hash only" else divergence.actual.label
                failures.add("$name: $summary [KNOWN_DIVERGENCES expects $expectedText, so this is a different failure]")
            } else {
                failures.add("$name: $summary")
            }
            table.add("$name | ${vector.expect.label} | $got | FAIL")
        }

        for (name in KNOWN_DIVERGENCES.keys.sorted()) {
            if (name !in seen) failures.add("$name: listed in KNOWN_DIVERGENCES but no such vector in $RESOURCE_DIR/")
        }

        val report = buildString {
            appendLine("CCTV: $processed vector(s) run, ${skipped.size} skipped")
            if (aliased.isNotEmpty()) {
                appendLine("CCTV: ${aliased.size} vector(s) passed via the no match -> header failure alias:")
                aliased.forEach { appendLine("  $it") }
            }
            if (waived.isNotEmpty()) {
                appendLine("CCTV: ${waived.size} vector(s) waived by KNOWN_DIVERGENCES:")
                waived.forEach { appendLine("  $it") }
            }
            if (failures.isNotEmpty()) {
                appendLine("CCTV: ${failures.size} failure(s):")
                failures.forEach { appendLine("  $it") }
            }
            appendLine("CCTV: every vector (name | expected | got | verdict):")
            table.forEach { appendLine("  $it") }
        }
        println(report)
        writeReport(report)

        assertEquals(
            EXPECTED_VECTOR_COUNT, processed + skipped.size,
            "vector files found in $RESOURCE_DIR/ ($processed run, ${skipped.size} skipped)",
        )
        val unexpectedSkips = skipped.filter { entry -> EXPECTED_SKIPPED.none { entry.startsWith("$it ") } }
        assertTrue(
            unexpectedSkips.isEmpty(),
            "skipped vectors (unknown header keys):\n  " + unexpectedSkips.joinToString("\n  "),
        )
        assertTrue(
            failures.isEmpty(),
            "CCTV testkit: ${failures.size} of $processed vectors don't match:\n  " + failures.joinToString("\n  "),
        )
    }

    // --- Vector file parsing ---

    /** Header of `key: value` lines, a blank line, then the age file. */
    private fun parse(name: String, raw: ByteArray): Parsed {
        val sep = indexOf(raw, byteArrayOf(0x0A, 0x0A))
        if (sep < 0) return Parsed.Skipped("no blank line after header")
        val headerText = String(raw, 0, sep, Charsets.UTF_8)
        val body = raw.copyOfRange(sep + 2, raw.size)

        var expect: Category? = null
        var payload: String? = null
        val identities = mutableListOf<String>()
        val passphrases = mutableListOf<String>()
        var armored = false
        var compressed = false

        for (line in headerText.split('\n')) {
            val colon = line.indexOf(": ")
            if (colon < 0) return Parsed.Skipped("header line without ': '")
            val key = line.substring(0, colon)
            val value = line.substring(colon + 2)
            when (key) {
                "expect" -> expect = Category.fromLabel(value) ?: return Parsed.Skipped("unknown expect value $value")
                "payload" -> payload = value
                "identity" -> identities.add(value)
                "passphrase" -> passphrases.add(value)
                "armored" -> {
                    if (value != "yes") return Parsed.Skipped("armored: $value")
                    armored = true
                }
                "compressed" -> {
                    if (value != "zlib") return Parsed.Skipped("compressed: $value")
                    compressed = true
                }
                "file key", "comment" -> Unit
                else -> return Parsed.Skipped("unknown key $key")
            }
        }
        val e = expect ?: return Parsed.Skipped("no expect key")
        return Parsed.Ok(Vector(name, e, payload, identities, passphrases, armored, compressed, body))
    }

    // --- Running one vector ---

    private fun run(v: Vector): Outcome {
        // Identities: X25519, hybrid, then one scrypt identity per passphrase, all tried.
        val identities = mutableListOf<AgeIdentity>()
        val handled = mutableSetOf<String>()
        try {
            for (s in v.identities) {
                if (s.uppercase().startsWith("AGE-SECRET-KEY-PQ-1")) {
                    identities.add(HybridIdentity(s))
                    handled.add("mlkem768x25519")
                } else {
                    identities.add(X25519Identity(s))
                    handled.add("X25519")
                }
            }
        } catch (e: Exception) {
            return Outcome(Category.UNEXPECTED, "runner: identity: ${describe(e)}", sha256Hex(ByteArray(0)), null, handled)
        }
        for (p in v.passphrases) {
            // Default work factor cap (22), as the app builds it.
            identities.add(ScryptIdentity(p))
            handled.add("scrypt")
        }
        if (identities.isEmpty()) identities.add(NO_IDENTITY)

        var file = v.body
        if (v.compressed) {
            file = try {
                // Inflater's default (zlib-wrapped) mode checks the header and the Adler-32 trailer.
                InflaterInputStream(ByteArrayInputStream(file)).use { it.readBytes() }
            } catch (e: Exception) {
                return Outcome(Category.UNEXPECTED, "runner: zlib: ${describe(e)}", sha256Hex(ByteArray(0)), null, handled)
            }
        }

        val out = ByteArrayOutputStream()
        var category = Category.SUCCESS
        var detail = "decrypted to EOF"
        try {
            if (v.armored) {
                // ISO-8859-1 maps bytes one to one onto chars, as Armor.DecodingSource reads them.
                file = Armor.decode(String(file, Charsets.ISO_8859_1))
            }
            Age.decryptStream(ByteArrayInputStream(file), identities, out)
        } catch (e: Exception) {
            val (c, d) = categoryOf(e)
            category = c
            detail = d
        }
        // Whatever reached `out` before a failure is the released plaintext.
        val released = out.toByteArray()

        val stanzaTypes = if (category == Category.NO_MATCH) {
            try {
                Age.parseHeaderStream(ByteArrayInputStream(file)).stanzas.map { it.type }.toSet()
            } catch (e: Exception) {
                null
            }
        } else {
            null
        }
        return Outcome(category, detail, sha256Hex(released), stanzaTypes, handled)
    }

    /** The one place core exceptions become CCTV categories. See the table at the top. */
    private fun categoryOf(e: Exception): Pair<Category, String> {
        val d = describe(e)
        return when (e) {
            is Armor.ArmorException -> Category.ARMOR_FAILURE to d
            is AgeHeader.HeaderException ->
                if (e.message == "MAC verification failed") Category.HMAC_FAILURE to d else Category.HEADER_FAILURE to d
            is AgePayload.PayloadException ->
                if (e.message?.startsWith("payload too short") == true) {
                    Category.HEADER_FAILURE to "$d (alias: nonce counts as header)"
                } else {
                    Category.PAYLOAD_FAILURE to d
                }
            is Age.NoMatchingIdentityException -> Category.NO_MATCH to d
            else -> Category.UNEXPECTED to d
        }
    }

    // --- Helpers ---

    private fun describe(e: Throwable): String = "${e.javaClass.simpleName}: ${e.message}"

    private fun sha256Hex(data: ByteArray): String =
        HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(data))

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    /**
     * Every file in the resource folder as (name, bytes). Anchored on SOURCE.md, since a
     * directory has no resource entry of its own inside a jar. Test resources are normally a
     * plain directory on the unit-test classpath; the jar branch is there in case AGP packages
     * them.
     */
    private fun loadVectorFiles(): List<Pair<String, ByteArray>> {
        val anchor = javaClass.getResource("/$RESOURCE_DIR/SOURCE.md")
            ?: throw FileNotFoundException("/$RESOURCE_DIR/SOURCE.md not found on the test classpath")
        return when (anchor.protocol) {
            "file" -> {
                val dir = File(anchor.toURI()).parentFile
                    ?: throw FileNotFoundException("no folder above $anchor")
                (dir.listFiles() ?: emptyArray()).filter { it.isFile }.map { it.name to it.readBytes() }
            }
            "jar" -> {
                val conn = anchor.openConnection() as JarURLConnection
                val prefix = conn.entryName.substringBeforeLast('/') + "/"
                val jar = conn.jarFile
                jar.entries().asSequence()
                    .filter { !it.isDirectory && it.name.startsWith(prefix) && '/' !in it.name.substring(prefix.length) }
                    .map { entry -> entry.name.substring(prefix.length) to jar.getInputStream(entry).use { it.readBytes() } }
                    .toList()
            }
            else -> throw IllegalStateException("unsupported resource URL ${anchor.protocol}: $anchor")
        }
    }

    private fun writeReport(report: String) {
        try {
            val dir = File("build/reports/cctv-testkit")
            dir.mkdirs()
            File(dir, "results.txt").writeText(report)
        } catch (_: Exception) {
            // Best effort; the same text is on stdout.
        }
    }
}
