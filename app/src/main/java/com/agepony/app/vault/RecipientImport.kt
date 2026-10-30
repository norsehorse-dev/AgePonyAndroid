package com.agepony.app.vault

import android.content.Context
import com.agepony.app.R
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

/**
 * A recipient couldn't be read or fetched. [reason] is what the app shows, with [subject] (the
 * GitHub user) and [httpStatus] where they help; the message is internal (5.1.0, UI plan U5).
 * [cause] is the parser or network error, read by the message mapper only for its type.
 */
class RecipientImportException(
    val reason: RecipientImportException.Reason,
    val subject: String? = null,
    val httpStatus: Int = 0,
    cause: Throwable? = null,
) : Exception(reason.name, cause) {
    enum class Reason {
        EMPTY, BAD_QUANTUM_SAFE, BAD_HARDWARE_TAG, BAD_YUBIKEY, BAD_AGE, BAD_SSH, BAD_SSH_ED25519,
        UNRECOGNIZED, INVALID_USERNAME, NO_KEYS, NO_USABLE_KEYS, HTTP_ERROR, EMPTY_RESPONSE,
        NETWORK, TOO_LARGE,
    }
}

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
    fun parsePastedText(raw: String, names: DefaultKeyNames): RecipientCandidate {
        val t = raw.trim()
        if (t.isEmpty()) throw RecipientImportException(RecipientImportException.Reason.EMPTY)

        // Post-quantum recipients must be checked before "age1" — their HRP is "age1pq",
        // so they also start with "age1" and would otherwise route to the X25519 parser.
        if (t.startsWith("age1pq")) {
            val recipient = try {
                HybridRecipient(t)
            } catch (e: Exception) {
                throw RecipientImportException(RecipientImportException.Reason.BAD_QUANTUM_SAFE, cause = e)
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
                throw RecipientImportException(RecipientImportException.Reason.BAD_HARDWARE_TAG, cause = e)
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
                throw RecipientImportException(RecipientImportException.Reason.BAD_YUBIKEY, cause = e)
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
                throw RecipientImportException(RecipientImportException.Reason.BAD_AGE, cause = e)
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
            return sshCandidate(t, StoredRecipientSource.PASTE_SSH, null, names)
        }

        throw RecipientImportException(RecipientImportException.Reason.UNRECOGNIZED)
    }

    /** Fetch https://github.com/<username>.keys and return every parsable recipient. */
    suspend fun fetchFromGitHub(
        username: String,
        proxyConfig: ProxyConfig = ProxyConfig.DIRECT,
        names: DefaultKeyNames,
    ): List<RecipientCandidate> =
        withContext(Dispatchers.IO) {
            val user = username.trim()
            if (!isValidGitHubUsername(user)) {
                throw RecipientImportException(RecipientImportException.Reason.INVALID_USERNAME)
            }

            val text = httpGet("https://github.com/$user.keys", proxyConfig)
            val metadata = "github.com/$user"
            val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }

            val raw = lines.mapNotNull { line ->
                if (!line.startsWith("ssh-ed25519 ") && !line.startsWith("ssh-rsa ")) return@mapNotNull null
                try {
                    // The comment matches iOS, so a key moved between the two reads the same.
                    sshCandidate(line, StoredRecipientSource.GITHUB, metadata, names, comment = "from $metadata")
                } catch (_: Exception) {
                    null
                }
            }
            if (raw.isEmpty()) {
                // Found none (U5): say whether the account has no keys at all or none AgePony takes.
                throw RecipientImportException(
                    if (lines.isEmpty()) RecipientImportException.Reason.NO_KEYS
                    else RecipientImportException.Reason.NO_USABLE_KEYS,
                    subject = user,
                )
            }
            // Name them: bare username for a single key, numbered when several.
            if (raw.size == 1) {
                listOf(raw[0].copy(defaultName = user))
            } else {
                raw.mapIndexed { i, c -> c.copy(defaultName = names.gitHubKey(user, i + 1)) }
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
    fun rsaTooSmallMessage(context: Context, bits: Int?): String =
        if (bits != null) {
            context.getString(R.string.identities_rsa_too_small_bits, bits, MIN_RSA_RECIPIENT_BITS)
        } else {
            context.getString(R.string.identities_rsa_too_small, MIN_RSA_RECIPIENT_BITS)
        }

    // MARK: - Helpers

    private fun sshCandidate(
        line: String,
        source: StoredRecipientSource,
        metadata: String?,
        names: DefaultKeyNames,
        comment: String? = trailingComment(line),
    ): RecipientCandidate {
        val parsed = try {
            OpenSSHPublicKey.parse(line)
        } catch (e: Exception) {
            throw RecipientImportException(RecipientImportException.Reason.BAD_SSH, cause = e)
        }
        if (parsed is OpenSSHPublicKey.Ed25519) {
            // The line parser only checks the length; a 32-byte value that isn't a curve point
            // would save fine and then fail every encryption, so refuse it here.
            try {
                SSHEd25519Recipient(parsed.publicKey)
            } catch (e: Exception) {
                throw RecipientImportException(RecipientImportException.Reason.BAD_SSH_ED25519, cause = e)
            }
        }
        return when (parsed) {
            is OpenSSHPublicKey.Ed25519 -> RecipientCandidate(
                type = StoredRecipientType.SSH_ED25519,
                publicKeyB64 = b64e(parsed.publicKey),
                sshComment = comment,
                defaultName = comment?.takeIf { it.isNotBlank() } ?: names.sshRecipient(rsa = false),
                source = source,
                sourceMetadata = metadata,
            )

            is OpenSSHPublicKey.RSA -> RecipientCandidate(
                type = StoredRecipientType.SSH_RSA,
                publicKeyB64 = b64e(line.trim().toByteArray(Charsets.UTF_8)),
                sshComment = comment,
                defaultName = comment?.takeIf { it.isNotBlank() } ?: names.sshRecipient(rsa = true),
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
                    throw RecipientImportException(RecipientImportException.Reason.HTTP_ERROR, httpStatus = response.code)
                }
                val body = response.body
                    ?: throw RecipientImportException(RecipientImportException.Reason.EMPTY_RESPONSE)
                // Read through a cap rather than string(), which buffers whatever arrives: a
                // hostile proxy or endpoint could otherwise send an endless body.
                if (body.contentLength() > MAX_GITHUB_KEYS_BYTES) throw tooLarge()
                val bytes = body.byteStream().use { readCapped(it, MAX_GITHUB_KEYS_BYTES) }
                return String(bytes, Charsets.UTF_8)
            }
        } catch (e: RecipientImportException) {
            throw e
        } catch (e: Exception) {
            throw RecipientImportException(RecipientImportException.Reason.NETWORK, cause = e)
        }
    }

    private fun tooLarge() = RecipientImportException(RecipientImportException.Reason.TOO_LARGE)

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
