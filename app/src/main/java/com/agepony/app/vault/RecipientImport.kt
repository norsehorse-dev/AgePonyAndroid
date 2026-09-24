package com.agepony.app.vault

import com.agepony.core.recipients.HybridRecipient
import com.agepony.core.recipients.MIN_RSA_RECIPIENT_BITS
import com.agepony.core.recipients.P256Recipient
import com.agepony.core.recipients.SSHEd25519Recipient
import com.agepony.core.recipients.SSHRSARecipient
import com.agepony.core.recipients.TagRecipient
import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.ssh.OpenSSHPublicKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.agepony.app.network.HttpClientFactory
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.io.InputStream

//
// Android counterpart of iOS's RecipientImportService. Import paths funnel into
// a single RecipientCandidate: paste (age1… / age1pq… / ssh-* line) and GitHub
// (.keys fetch). Each candidate carries the publicKeyB64 already in the storage
// shape the hydration layer expects.
//

class RecipientImportException(message: String) : Exception(message)

data class RecipientCandidate(
    val type: StoredRecipientType,
    val publicKeyB64: String,
    val sshComment: String?,
    val defaultName: String,
    val source: StoredRecipientSource,
    val sourceMetadata: String?,
)

object RecipientImport {

    /** Parse a single pasted blob (age1pq… / age1… recipient or one-line OpenSSH public key). */
    fun parsePastedText(raw: String): RecipientCandidate {
        val t = raw.trim()
        if (t.isEmpty()) throw RecipientImportException("Nothing to parse.")

        // Post-quantum recipients must be checked before "age1" — their HRP is "age1pq",
        // so they also start with "age1" and would otherwise route to the X25519 parser.
        if (t.startsWith("age1pq")) {
            val recipient = try {
                HybridRecipient(t)
            } catch (e: Exception) {
                throw RecipientImportException("Not a valid quantum-safe age recipient (${e.message}).")
            }
            return RecipientCandidate(
                type = StoredRecipientType.MLKEM768X25519,
                publicKeyB64 = b64e(recipient.publicKey),
                sshComment = null,
                defaultName = shortAgeName(t),
                source = StoredRecipientSource.PASTE_AGE,
                sourceMetadata = null,
            )
        }

        // age v1.3 tag recipients (hardware keys: age1tag1 / age1tagpq1). Before "age1".
        if (TagRecipient.isTagRecipient(t)) {
            val recipient = try {
                TagRecipient(t)
            } catch (e: Exception) {
                throw RecipientImportException("Not a valid age hardware-key recipient (${e.message}).")
            }
            return RecipientCandidate(
                type = if (recipient.hybrid) StoredRecipientType.TAG_PQ else StoredRecipientType.TAG,
                publicKeyB64 = b64e(recipient.publicKey),
                sshComment = null,
                defaultName = shortAgeName(t),
                source = StoredRecipientSource.PASTE_AGE,
                sourceMetadata = null,
            )
        }

        // age-plugin-yubikey recipients: age1yubikey1... Must be checked before the
        // generic "age1" branch, since they also start with "age1".
        if (t.startsWith("age1yubikey")) {
            val recipient = try {
                P256Recipient(t)
            } catch (e: Exception) {
                throw RecipientImportException("Not a valid YubiKey recipient (${e.message}).")
            }
            return RecipientCandidate(
                type = StoredRecipientType.YUBIKEY_P256,
                publicKeyB64 = b64e(recipient.compressedPublicKey),
                sshComment = null,
                defaultName = shortAgeName(t),
                source = StoredRecipientSource.PASTE_AGE,
                sourceMetadata = null,
            )
        }

        if (t.startsWith("age1")) {
            val recipient = try {
                X25519Recipient(t)
            } catch (e: Exception) {
                throw RecipientImportException("Not a valid age recipient (${e.message}).")
            }
            return RecipientCandidate(
                type = StoredRecipientType.X25519,
                publicKeyB64 = b64e(recipient.publicKey),
                sshComment = null,
                defaultName = shortAgeName(t),
                source = StoredRecipientSource.PASTE_AGE,
                sourceMetadata = null,
            )
        }

        if (t.startsWith("ssh-ed25519 ") || t.startsWith("ssh-rsa ")) {
            return sshCandidate(t, StoredRecipientSource.PASTE_SSH, null)
        }

        throw RecipientImportException(
            "Expected an age1… / age1pq… / age1tag1… / age1yubikey1… recipient or an ssh-ed25519 / ssh-rsa line."
        )
    }

    /** Fetch https://github.com/<username>.keys and return every parsable recipient. */
    suspend fun fetchFromGitHub(
        username: String,
        proxyConfig: ProxyConfig = ProxyConfig.DIRECT,
    ): List<RecipientCandidate> =
        withContext(Dispatchers.IO) {
            val user = username.trim()
            if (!isValidGitHubUsername(user)) {
                throw RecipientImportException(
                    "GitHub usernames are 1 to 39 letters (A to Z), digits and hyphens, and don't start with a hyphen."
                )
            }

            val text = httpGet("https://github.com/$user.keys", proxyConfig)
            val metadata = "github.com/$user"
            val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }

            val raw = lines.mapNotNull { line ->
                if (!line.startsWith("ssh-ed25519 ") && !line.startsWith("ssh-rsa ")) return@mapNotNull null
                try {
                    sshCandidate(line, StoredRecipientSource.GITHUB, metadata, comment = "from $metadata")
                } catch (_: Exception) {
                    null
                }
            }
            if (raw.isEmpty()) {
                throw RecipientImportException(
                    "GitHub returned no ed25519 or RSA public keys for that user."
                )
            }
            // Name them: bare username for a single key, numbered when several.
            if (raw.size == 1) {
                listOf(raw[0].copy(defaultName = user))
            } else {
                raw.mapIndexed { i, c -> c.copy(defaultName = "$user (key ${i + 1})") }
            }
        }

    /** Largest `.keys` response read (audit hardening). A real key list is a few KiB. */
    const val MAX_GITHUB_KEYS_BYTES = 256 * 1024

    private val GITHUB_USERNAME = Regex("[A-Za-z0-9][A-Za-z0-9-]{0,38}")

    /**
     * GitHub's own rule: ASCII letters, digits and hyphens, at most 39, not starting with a
     * hyphen. Unicode letters used to pass (isLetterOrDigit), which put them in the URL path.
     */
    fun isValidGitHubUsername(user: String): Boolean = GITHUB_USERNAME.matches(user)

    /**
     * True for an ssh-rsa key under [MIN_RSA_RECIPIENT_BITS] bits. Encrypting to one now throws
     * (age requires 2048), so the UI warns and doesn't select it (audit L-4). False for every
     * other type and for a key that doesn't parse.
     */
    fun isRsaBelowMinimum(type: StoredRecipientType, publicKeyB64: String): Boolean =
        parsedRsa(type, publicKeyB64)?.let { SSHRSARecipient(it).isBelowMinimumSize } ?: false

    /** The modulus size of an ssh-rsa key in storage form, or null for other types or a bad key. */
    fun rsaBits(type: StoredRecipientType, publicKeyB64: String): Int? =
        parsedRsa(type, publicKeyB64)?.modulus?.bitLength()

    private fun parsedRsa(type: StoredRecipientType, publicKeyB64: String): OpenSSHPublicKey.RSA? {
        if (type != StoredRecipientType.SSH_RSA) return null
        return runCatching {
            OpenSSHPublicKey.parse(String(b64d(publicKeyB64), Charsets.UTF_8)) as? OpenSSHPublicKey.RSA
        }.getOrNull()
    }

    /** One-line warning for a small RSA key, shared by the add, transfer and list screens. */
    fun rsaTooSmallMessage(bits: Int?): String =
        "Too small to encrypt to" + (bits?.let { " ($it bits)" } ?: "") +
            ", $MIN_RSA_RECIPIENT_BITS bits minimum."

    // MARK: - Helpers

    private fun sshCandidate(
        line: String,
        source: StoredRecipientSource,
        metadata: String?,
        comment: String? = trailingComment(line),
    ): RecipientCandidate {
        val parsed = try {
            OpenSSHPublicKey.parse(line)
        } catch (e: Exception) {
            throw RecipientImportException("Couldn't parse that SSH key (${e.message}).")
        }
        if (parsed is OpenSSHPublicKey.Ed25519) {
            // The line parser only checks the length; a 32-byte value that isn't a curve point
            // would save fine and then fail every encryption, so refuse it here.
            try {
                SSHEd25519Recipient(parsed.publicKey)
            } catch (e: Exception) {
                throw RecipientImportException("That ssh-ed25519 key isn't a valid public key (${e.message}).")
            }
        }
        return when (parsed) {
            is OpenSSHPublicKey.Ed25519 -> RecipientCandidate(
                type = StoredRecipientType.SSH_ED25519,
                publicKeyB64 = b64e(parsed.publicKey),
                sshComment = comment,
                defaultName = comment?.takeIf { it.isNotBlank() } ?: "SSH Ed25519",
                source = source,
                sourceMetadata = metadata,
            )

            is OpenSSHPublicKey.RSA -> RecipientCandidate(
                type = StoredRecipientType.SSH_RSA,
                publicKeyB64 = b64e(line.trim().toByteArray(Charsets.UTF_8)),
                sshComment = comment,
                defaultName = comment?.takeIf { it.isNotBlank() } ?: "SSH RSA",
                source = source,
                sourceMetadata = metadata,
            )
        }
    }

    private fun trailingComment(line: String): String? {
        val parts = line.trim().split(Regex("\\s+"), limit = 3)
        return if (parts.size == 3) parts[2] else null
    }

    private fun shortAgeName(s: String): String {
        if (s.length <= 16) return s
        return "${s.take(10)}…${s.takeLast(4)}"
    }

    private fun httpGet(urlString: String, proxyConfig: ProxyConfig): String {
        try {
            // Building the client applies the proxy; a dead or incomplete proxy
            // throws here, so the fetch fails rather than silently going direct.
            val client = HttpClientFactory.client(proxyConfig)
            val request = Request.Builder()
                .url(urlString)
                .header("Accept", "text/plain")
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw RecipientImportException("GitHub returned HTTP ${response.code}.")
                }
                val body = response.body
                    ?: throw RecipientImportException("GitHub returned an empty response.")
                // Read through a cap rather than string(), which buffers whatever arrives: a
                // hostile proxy or endpoint could otherwise send an endless body.
                if (body.contentLength() > MAX_GITHUB_KEYS_BYTES) throw tooLarge()
                val bytes = body.byteStream().use { readCapped(it, MAX_GITHUB_KEYS_BYTES) }
                return String(bytes, Charsets.UTF_8)
            }
        } catch (e: RecipientImportException) {
            throw e
        } catch (e: Exception) {
            throw RecipientImportException("Network error: ${e.message}")
        }
    }

    private fun tooLarge() = RecipientImportException(
        "GitHub's response is larger than ${MAX_GITHUB_KEYS_BYTES / 1024} KiB, which isn't a normal key list. Nothing was imported."
    )

    /** Read [input] to the end, failing once more than [max] bytes arrive. */
    private fun readCapped(input: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (out.size() + n > max) throw tooLarge()
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }
}
