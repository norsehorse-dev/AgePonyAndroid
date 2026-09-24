package com.agepony.core.ssh

import com.agepony.core.archive.SignedBundle
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigVerifier
import com.agepony.core.signing.SignatureStanza
import java.time.DateTimeException
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Base64

/**
 * One entry of an OpenSSH `allowed_signers` file: the principals authorized to
 * sign, an optional options field (preserved verbatim), the key type, the
 * base64 public-key wire blob, and an optional trailing comment.
 */
data class AllowedSigner(
    /** Comma-separated principals split out (e.g. ["alice@example.com"]). */
    val principals: List<String>,
    /** Raw options field, preserved verbatim if present (e.g. `namespaces="agepony"`). */
    val options: String? = null,
    /** Key algorithm, e.g. "ssh-ed25519". */
    val keyType: String,
    /** Base64 of the SSH public-key wire blob. */
    val keyBase64: String,
    /** Optional trailing comment. */
    val comment: String? = null,
) {
    /** The public key as raw SSH wire bytes, or null if the base64 doesn't decode. */
    val publicKeyWire: ByteArray?
        get() = try {
            Base64.getDecoder().decode(keyBase64)
        } catch (_: IllegalArgumentException) {
            null
        }

    /**
     * Does this entry authorize [principal] to sign with the key whose wire blob is
     * [candidate]? Principal matching is exact (and case-sensitive, matching
     * ssh-keygen's behavior for plain identities); pattern principals are not
     * expanded here.
     */
    fun matches(principal: String, candidate: ByteArray): Boolean {
        val mine = publicKeyWire ?: return false
        if (!mine.contentEquals(candidate)) return false
        return principal in principals
    }

    // --- Options (audit L-6) ---

    /**
     * The options field parsed. Dates without a trailing `Z` are local time in [zone], as
     * ssh-keygen reads them.
     */
    fun parsedOptions(zone: ZoneId = ZoneId.systemDefault()): AllowedSignerOptions =
        AllowedSignerOptions.parse(options, zone)

    /** `cert-authority`: the key signs certificates. AgePony has no certificate support, so such an entry permits nothing. */
    val isCertAuthority: Boolean get() = parsedOptions(ZoneOffset.UTC).certAuthority

    /** False only when the entry has `no-touch-required`: a security-key signature must then carry the touch flag. */
    val requiresTouch: Boolean get() = !parsedOptions(ZoneOffset.UTC).noTouchRequired

    /** `verify-required`: a security-key signature must carry the user-verified (PIN or biometric) flag. */
    val requiresUserVerification: Boolean get() = parsedOptions(ZoneOffset.UTC).verifyRequired

    /** Options AgePony does not know, verbatim. Any of these makes [permits] false, as OpenSSH refuses the line. */
    val unknownOptions: List<String> get() = parsedOptions(ZoneOffset.UTC).unknown

    /**
     * Does this entry allow a signature in [namespace] made at [at]? Mirrors ssh-keygen -Y verify:
     * false for a `cert-authority` entry, for a namespace outside `namespaces=` (OpenSSH pattern
     * list, `*` and `?` wildcards, `!` negation), for a time before `valid-after` or after
     * `valid-before`, and for an options field that is malformed or has an option AgePony does
     * not understand. This says nothing about the key itself; match that with [matches] or by
     * comparing [publicKeyWire].
     */
    fun permits(namespace: String, at: Instant = Instant.now(), zone: ZoneId = ZoneId.systemDefault()): Boolean =
        parsedOptions(zone).permits(namespace, at, agePonyFamily = false)

    /**
     * [permits] for AgePony's own formats: an entry restricted to `namespaces="agepony"` also
     * permits the v2 namespaces ([SignatureStanza.NAMESPACE_V2], [SignedBundle.NAMESPACE_V2]),
     * which are AgePony's sub-formats, so a restriction written for 5.0.0 keeps working. An
     * explicit `!` negation of a v2 namespace still wins.
     */
    fun permitsAgePony(namespace: String, at: Instant = Instant.now(), zone: ZoneId = ZoneId.systemDefault()): Boolean =
        parsedOptions(zone).permits(namespace, at, agePonyFamily = true)

    /**
     * Whole-entry policy for a verified signature: [result] is valid, [permitsAgePony] allows its
     * namespace at [at], and a security-key signature carries the flags this entry demands (touch
     * unless `no-touch-required`, user verification with `verify-required`). The caller still
     * checks that [result]'s key is this entry's key.
     */
    fun accepts(result: SSHSigVerifier.Result, at: Instant = Instant.now(), zone: ZoneId = ZoneId.systemDefault()): Boolean {
        if (!result.valid) return false
        val opts = parsedOptions(zone)
        if (!opts.permits(result.namespace, at, agePonyFamily = true)) return false
        if (result.userPresent == false && !opts.noTouchRequired) return false
        if (opts.verifyRequired && result.userVerified == false) return false
        return true
    }
}

/**
 * The options field of an allowed_signers line, parsed the way OpenSSH's sshsig.c does (audit
 * L-6). The field is a comma-separated list; a value may be double-quoted, and a quoted value may
 * hold commas and spaces (`\"` is a literal quote). Names are case-insensitive.
 *
 * Understood: `cert-authority`, `namespaces="pattern,list"`, `valid-after=` and `valid-before=`
 * (`YYYYMMDD`, `YYYYMMDDHHMM` or `YYYYMMDDHHMMSS`, with a trailing `Z` or `UTC` meaning UTC,
 * otherwise local time), `no-touch-required`, `verify-required`. Anything else lands in
 * [unknown]. A duplicate namespaces/valid-* clause, a bad date, an unterminated quote, an empty
 * item, or valid-before not after valid-after sets [error]. Either makes [permits] false.
 */
class AllowedSignerOptions private constructor(
    /** The options field exactly as written (null when the line had none). */
    val raw: String?,
    val certAuthority: Boolean,
    /** The `namespaces=` value, dequoted, or null when absent (every namespace allowed). */
    val namespaces: String?,
    val validAfter: Instant?,
    val validBefore: Instant?,
    val noTouchRequired: Boolean,
    val verifyRequired: Boolean,
    val unknown: List<String>,
    val error: String?,
) {
    /** See [AllowedSigner.permits] and [AllowedSigner.permitsAgePony]. */
    fun permits(namespace: String, at: Instant, agePonyFamily: Boolean = false): Boolean {
        if (error != null || unknown.isNotEmpty() || certAuthority) return false
        validAfter?.let { if (at.isBefore(it)) return false }
        validBefore?.let { if (at.isAfter(it)) return false }
        val list = namespaces ?: return true
        return when (matchPatternList(namespace, list)) {
            1 -> true
            -1 -> false
            else -> agePonyFamily && namespace in AGEPONY_V2_NAMESPACES &&
                matchPatternList(SSHSig.NAMESPACE_AGEPONY, list) == 1
        }
    }

    companion object {
        private val AGEPONY_V2_NAMESPACES = setOf(SignatureStanza.NAMESPACE_V2, SignedBundle.NAMESPACE_V2)

        fun parse(raw: String?, zone: ZoneId = ZoneId.systemDefault()): AllowedSignerOptions {
            var ca = false
            var namespaces: String? = null
            var after: Instant? = null
            var before: Instant? = null
            var noTouch = false
            var verify = false
            val unknown = mutableListOf<String>()
            var error: String? = null
            fun fail(msg: String) { if (error == null) error = msg }

            val items = if (raw.isNullOrEmpty()) emptyList() else splitItems(raw) ?: run {
                fail("unterminated quote in options")
                emptyList()
            }
            for (item in items) {
                val eq = item.indexOf('=')
                val name = (if (eq >= 0) item.substring(0, eq) else item).lowercase()
                val value = if (eq >= 0) item.substring(eq + 1) else null
                when {
                    item.isEmpty() -> fail("empty option")
                    value == null && name == "cert-authority" -> ca = true
                    value == null && name == "no-touch-required" -> noTouch = true
                    value == null && name == "verify-required" -> verify = true
                    value != null && name == "namespaces" -> {
                        if (namespaces != null) fail("multiple namespaces clauses")
                        namespaces = dequote(value) ?: run { fail("bad namespaces value"); "" }
                    }
                    value != null && (name == "valid-after" || name == "valid-before") -> {
                        val t = dequote(value)?.let { parseTime(it, zone) }
                        if (t == null) fail("invalid $name time")
                        if (name == "valid-after") {
                            if (after != null) fail("multiple valid-after clauses")
                            after = t
                        } else {
                            if (before != null) fail("multiple valid-before clauses")
                            before = t
                        }
                    }
                    else -> unknown += item
                }
            }
            val a = after
            val b = before
            if (a != null && b != null && !b.isAfter(a)) fail("valid-before is not after valid-after")
            return AllowedSignerOptions(raw, ca, namespaces, after, before, noTouch, verify, unknown, error)
        }

        /** Split on commas outside double quotes. Null for an unterminated quote. */
        private fun splitItems(raw: String): List<String>? {
            val items = mutableListOf<String>()
            val cur = StringBuilder()
            var quoted = false
            var i = 0
            while (i < raw.length) {
                val c = raw[i]
                when {
                    c == '\\' && i + 1 < raw.length && raw[i + 1] == '"' -> { cur.append(c).append('"'); i++ }
                    c == '"' -> { quoted = !quoted; cur.append(c) }
                    c == ',' && !quoted -> { items += cur.toString(); cur.setLength(0) }
                    else -> cur.append(c)
                }
                i++
            }
            if (quoted) return null
            items += cur.toString()
            return items
        }

        /**
         * A quoted value loses its quotes (`\"` becomes `"`); the closing quote must end the item.
         * An unquoted value is taken as is, which OpenSSH would refuse but which is harmless here
         * since every such value only narrows what the entry permits.
         */
        private fun dequote(v: String): String? {
            if (!v.startsWith("\"")) return v
            val out = StringBuilder()
            var i = 1
            while (i < v.length) {
                val c = v[i]
                if (c == '\\' && i + 1 < v.length && v[i + 1] == '"') {
                    out.append('"'); i += 2; continue
                }
                if (c == '"') return if (i == v.length - 1) out.toString() else null
                out.append(c)
                i++
            }
            return null
        }

        /** OpenSSH parse_absolute_time. Null if malformed, or not after the epoch (OpenSSH treats 0 as unset). */
        internal fun parseTime(s: String, zone: ZoneId): Instant? {
            var body = s
            var utc = false
            if (body.length > 1 && body.endsWith("Z", ignoreCase = true)) {
                utc = true; body = body.dropLast(1)
            } else if (body.length > 3 && body.endsWith("UTC", ignoreCase = true)) {
                utc = true; body = body.dropLast(3)
            }
            if (body.length !in setOf(8, 12, 14) || !body.all { it in '0'..'9' }) return null
            fun num(from: Int, len: Int) = body.substring(from, from + len).toInt()
            val local = try {
                LocalDateTime.of(
                    num(0, 4), num(4, 2), num(6, 2),
                    if (body.length >= 12) num(8, 2) else 0,
                    if (body.length >= 12) num(10, 2) else 0,
                    if (body.length == 14) num(12, 2) else 0,
                )
            } catch (_: DateTimeException) {
                return null
            }
            val instant = if (utc) local.toInstant(ZoneOffset.UTC) else local.atZone(zone).toInstant()
            return if (instant.epochSecond > 0) instant else null
        }

        /**
         * OpenSSH match_pattern_list (case-sensitive): 1 if some pattern matches, -1 if a `!`
         * pattern matches (which wins), 0 if none does. Patterns are not trimmed.
         */
        internal fun matchPatternList(s: String, list: String): Int {
            var positive = false
            for (entry in list.split(',')) {
                val negated = entry.startsWith("!")
                val pattern = if (negated) entry.substring(1) else entry
                if (globMatch(s, pattern)) {
                    if (negated) return -1
                    positive = true
                }
            }
            return if (positive) 1 else 0
        }

        /** `*` matches any run (including none), `?` exactly one character. Iterative, no backtracking blow-up. */
        private fun globMatch(s: String, p: String): Boolean {
            var si = 0
            var pi = 0
            var star = -1
            var mark = 0
            while (si < s.length) {
                when {
                    pi < p.length && (p[pi] == '?' || p[pi] == s[si]) -> { si++; pi++ }
                    pi < p.length && p[pi] == '*' -> { star = pi++; mark = si }
                    star >= 0 -> { pi = star + 1; si = ++mark }
                    else -> return false
                }
            }
            while (pi < p.length && p[pi] == '*') pi++
            return pi == p.length
        }
    }
}

/**
 * Parse and serialize the OpenSSH `allowed_signers` file format, the trust store
 * `ssh-keygen -Y verify -f allowed_signers` reads. AgePony's trusted-signers
 * vault collection round-trips through this so a list built in the app drops
 * straight onto a machine's command line and back.
 *
 * Line format (per ssh-keygen(1), ALLOWED SIGNERS):
 *
 *     principals [options] keytype base64-key [comment]
 *
 * where `principals` is a comma-separated list (no spaces), `options` is an
 * optional comma-separated list of restrictions (e.g. namespaces="agepony",
 * valid-after=...), and comment is free text. Blank lines and lines beginning
 * with '#' are ignored.
 *
 * Mirrors iOS `AgePonyCore/Signing/AllowedSigners.swift`; the two must keep
 * parsing identically so a file exported on one platform imports losslessly on
 * the other.
 */
object AllowedSigners {

    /**
     * Key types recognized as the start of the key field (used to tell whether
     * the token after the principals is an options field or the key type).
     */
    private val knownKeyTypes: Set<String> = setOf(
        "ssh-ed25519",
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    )

    /** Parse an allowed_signers file body. Unparseable lines are skipped. */
    fun parse(text: String): List<AllowedSigner> {
        val normalized = text.replace("\r\n", "\n").replace('\r', '\n')
        return normalized.split('\n')
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull(::parseLine)
    }

    /**
     * Parse a single non-comment line, or null if it isn't well-formed.
     *
     * Fields split on spaces and tabs, as ssh-keygen splits them, except that a principals field
     * starting with a double quote runs to the closing quote, and an options field may hold
     * spaces inside double quotes (`namespaces="a, b"`) (audit L-6). The options field is kept
     * verbatim; [AllowedSigner.parsedOptions] interprets it.
     */
    fun parseLine(line: String): AllowedSigner? {
        var pos = 0
        fun skipSpace() { while (pos < line.length && (line[pos] == ' ' || line[pos] == '\t')) pos++ }
        fun word(): String? {
            skipSpace()
            if (pos >= line.length) return null
            val start = pos
            while (pos < line.length && line[pos] != ' ' && line[pos] != '\t') pos++
            return line.substring(start, pos)
        }

        skipSpace()
        val principalsField = if (pos < line.length && line[pos] == '"') {
            val close = line.indexOf('"', pos + 1)
            if (close < 0) return null
            line.substring(pos + 1, close).also { pos = close + 1 }
        } else {
            word() ?: return null
        }
        val principals = principalsField.split(',').filter { it.isNotEmpty() }
        if (principals.isEmpty()) return null

        // The token after principals is either options or the key type.
        skipSpace()
        val afterPrincipals = pos
        var options: String? = null
        var keyType = word() ?: return null
        if (keyType !in knownKeyTypes) {
            pos = afterPrincipals
            options = optionsField(line, pos) ?: return null
            pos += options.length
            keyType = word() ?: return null
        }
        if (keyType !in knownKeyTypes) return null

        val keyBase64 = word() ?: return null
        if (!decodes(keyBase64)) return null

        val rest = mutableListOf<String>()
        while (true) rest += word() ?: break
        val comment = if (rest.isNotEmpty()) rest.joinToString(" ") else null

        return AllowedSigner(
            principals = principals,
            options = options,
            keyType = keyType,
            keyBase64 = keyBase64,
            comment = comment,
        )
    }

    /**
     * The options field starting at [from]: OpenSSH sshkey_advance_past_options, which stops at the
     * first space or tab outside double quotes and skips `\"`. Null for an unterminated quote.
     */
    private fun optionsField(line: String, from: Int): String? {
        var i = from
        var quoted = false
        while (i < line.length && (quoted || (line[i] != ' ' && line[i] != '\t'))) {
            if (line[i] == '\\' && i + 1 < line.length && line[i + 1] == '"') {
                i++
            } else if (line[i] == '"') {
                quoted = !quoted
            }
            i++
        }
        if (quoted) return null
        return line.substring(from, i)
    }

    /** Serialize signers back into allowed_signers file text (LF-terminated). */
    fun serialize(signers: List<AllowedSigner>): String = buildString {
        for (s in signers) {
            val joined = s.principals.joinToString(",")
            // A principal with a space only survives the round trip quoted (see parseLine).
            val fields = mutableListOf(if (joined.any { it == ' ' || it == '\t' }) "\"$joined\"" else joined)
            s.options?.takeIf { it.isNotEmpty() }?.let { fields.add(it) }
            fields.add(s.keyType)
            fields.add(s.keyBase64)
            s.comment?.takeIf { it.isNotEmpty() }?.let { fields.add(it) }
            append(fields.joinToString(" "))
            append('\n')
        }
    }

    /**
     * Build a signer entry from an SSH public-key line (`keytype base64 [comment]`)
     * for one or more principals. Convenient for "promote recipient to signer".
     */
    fun makeSigner(
        principals: List<String>,
        sshPublicKeyLine: String,
        namespaceRestricted: Boolean = false,
    ): AllowedSigner? {
        val parts = sshPublicKeyLine.trim().split(' ').filter { it.isNotEmpty() }
        if (parts.size < 2) return null
        val keyType = parts[0]
        if (keyType !in knownKeyTypes) return null
        val keyBase64 = parts[1]
        if (!decodes(keyBase64)) return null
        val comment = if (parts.size >= 3) parts.subList(2, parts.size).joinToString(" ") else null
        val options = if (namespaceRestricted) "namespaces=\"${SSHSig.NAMESPACE_AGEPONY}\"" else null
        return AllowedSigner(
            principals = principals,
            options = options,
            keyType = keyType,
            keyBase64 = keyBase64,
            comment = comment,
        )
    }

    private fun decodes(b64: String): Boolean = try {
        Base64.getDecoder().decode(b64)
        true
    } catch (_: IllegalArgumentException) {
        false
    }
}
