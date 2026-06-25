package com.agepony.app.vault

import com.agepony.core.recipients.X25519Recipient
import com.agepony.core.ssh.OpenSSHPublicKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

//
// Android counterpart of iOS's RecipientImportService. Two import paths funnel
// into a single RecipientCandidate: paste (age1… / ssh-* line) and GitHub
// (.keys fetch). QR is deferred (needs camera). Each candidate carries the
// publicKeyB64 already in the storage shape the hydration layer expects.
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

    /** Parse a single pasted blob (age1… recipient or one-line OpenSSH public key). */
    fun parsePastedText(raw: String): RecipientCandidate {
        val t = raw.trim()
        if (t.isEmpty()) throw RecipientImportException("Nothing to parse.")

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
            "Expected an age1… recipient or an ssh-ed25519 / ssh-rsa line."
        )
    }

    /** Fetch https://github.com/<username>.keys and return every parsable recipient. */
    suspend fun fetchFromGitHub(username: String): List<RecipientCandidate> =
        withContext(Dispatchers.IO) {
            val user = username.trim()
            if (user.isEmpty() || !user.all { it.isLetterOrDigit() || it == '-' || it == '_' }) {
                throw RecipientImportException(
                    "Usernames may only contain letters, numbers, hyphens, and underscores."
                )
            }

            val text = httpGet("https://github.com/$user.keys")
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

    private fun httpGet(urlString: String): String {
        val conn = (URL(urlString).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000
            readTimeout = 15000
            requestMethod = "GET"
            instanceFollowRedirects = true
        }
        try {
            val code = conn.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                throw RecipientImportException("GitHub returned HTTP $code.")
            }
            return conn.inputStream.bufferedReader().use { it.readText() }
        } catch (e: RecipientImportException) {
            throw e
        } catch (e: Exception) {
            throw RecipientImportException("Network error: ${e.message}")
        } finally {
            conn.disconnect()
        }
    }
}
