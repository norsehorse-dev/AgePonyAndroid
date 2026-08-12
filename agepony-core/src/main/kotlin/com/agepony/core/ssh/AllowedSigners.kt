package com.agepony.core.ssh

import com.agepony.core.signing.SSHSig
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

    /** Parse a single non-comment line, or null if it isn't well-formed. */
    fun parseLine(line: String): AllowedSigner? {
        val parts = line.split(' ').filter { it.isNotEmpty() }
        if (parts.size < 3) return null

        val principals = parts[0].split(',').filter { it.isNotEmpty() }
        if (principals.isEmpty()) return null

        var index = 1
        var options: String? = null

        // The token after principals is either options or the key type.
        if (parts[index] !in knownKeyTypes) {
            options = parts[index]
            index++
        }
        if (index >= parts.size) return null

        val keyType = parts[index]
        index++
        if (keyType !in knownKeyTypes) return null
        if (index >= parts.size) return null

        val keyBase64 = parts[index]
        index++
        if (!decodes(keyBase64)) return null

        val comment = if (index < parts.size) {
            parts.subList(index, parts.size).joinToString(" ")
        } else {
            null
        }

        return AllowedSigner(
            principals = principals,
            options = options,
            keyType = keyType,
            keyBase64 = keyBase64,
            comment = comment,
        )
    }

    /** Serialize signers back into allowed_signers file text (LF-terminated). */
    fun serialize(signers: List<AllowedSigner>): String = buildString {
        for (s in signers) {
            val fields = mutableListOf(s.principals.joinToString(","))
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
