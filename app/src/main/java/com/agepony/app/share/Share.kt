package com.agepony.app.share

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import com.agepony.app.ui.files.SafIo

/**
 * What another app handed AgePony through the share sheet or the text-selection menu.
 *
 * Everything stays in memory or streams straight from the sender's content URI. Nothing is
 * copied into app storage on the way in.
 */
sealed class SharePayload {
    /**
     * Shared or selected text. [processText] is true when it came from the text-selection menu
     * (ACTION_PROCESS_TEXT); [canReplace] is true when the sending app will take a result back to
     * replace the selection.
     */
    data class Text(val text: String, val processText: Boolean, val canReplace: Boolean) : SharePayload()

    /** One or more shared files, read through the sender's content URIs. */
    data class Files(val uris: List<Uri>) : SharePayload()

    companion object {
        /** Largest shared text handled in memory. Binder caps real shares well below this. */
        const val MAX_TEXT_CHARS = 4 * 1024 * 1024

        /** Parse an incoming intent. Returns null for anything AgePony should not act on. */
        fun from(intent: Intent?): SharePayload? {
            if (intent == null) return null
            return when (intent.action) {
                Intent.ACTION_PROCESS_TEXT -> {
                    val text = intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
                    val readOnly = intent.getBooleanExtra(Intent.EXTRA_PROCESS_TEXT_READONLY, false)
                    text?.takeIf { it.isNotEmpty() && it.length <= MAX_TEXT_CHARS }
                        ?.let { Text(it, processText = true, canReplace = !readOnly) }
                }
                Intent.ACTION_SEND -> {
                    val stream = streamExtra(intent)
                    if (stream != null) {
                        Files(listOf(stream))
                    } else {
                        intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
                            ?.takeIf { it.isNotEmpty() && it.length <= MAX_TEXT_CHARS }
                            ?.let { Text(it, processText = false, canReplace = false) }
                    }
                }
                Intent.ACTION_SEND_MULTIPLE -> {
                    val uris = streamListExtra(intent)
                    if (uris.isNotEmpty()) Files(uris) else null
                }
                else -> null
            }
        }

        /**
         * [payload] with every file URI AgePony must not read on the sender's behalf removed, or
         * null when nothing is left (audit L-20). Only content:// URIs are accepted: a file:// URI
         * would be opened with AgePony's own file permissions, so another app could hand it
         * `files/vault/...` and have AgePony read its own private files as share input. For the
         * same reason a content:// URI served by one of this app's own providers ([ownPackage] or
         * `ownPackage.*`, the convention for `${applicationId}` authorities) is refused.
         */
        fun restrictTo(payload: SharePayload, ownPackage: String): SharePayload? = when (payload) {
            is Text -> payload
            is Files -> payload.uris.filter { isForeignContentUri(it, ownPackage) }
                .takeIf { it.isNotEmpty() }
                ?.let { Files(it) }
        }

        /** True for a content:// URI whose provider is not part of [ownPackage]. */
        fun isForeignContentUri(uri: Uri, ownPackage: String): Boolean {
            if (!uri.scheme.equals("content", ignoreCase = true)) return false
            // "userId@authority" resolves to the same provider as "authority", so compare the
            // part after any '@'.
            val authority = uri.authority?.substringAfterLast('@')?.lowercase() ?: return false
            if (authority.isEmpty()) return false
            val own = ownPackage.lowercase()
            return authority != own && !authority.startsWith("$own.")
        }

        @Suppress("DEPRECATION")
        private fun streamExtra(intent: Intent): Uri? {
            val uri = if (Build.VERSION.SDK_INT >= 33) {
                intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                intent.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri
            }
            return uri ?: intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.uri
        }

        @Suppress("DEPRECATION")
        private fun streamListExtra(intent: Intent): List<Uri> {
            val list = if (Build.VERSION.SDK_INT >= 33) {
                intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
            }
            if (!list.isNullOrEmpty()) return list.filterNotNull()
            val clip = intent.clipData ?: return emptyList()
            return (0 until clip.itemCount).mapNotNull { clip.getItemAt(it).uri }
        }
    }
}

object ShareSniff {
    private const val AGE_MAGIC = "age-encryption.org/v1"
    private const val ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----"

    /** True if [text] carries an armored age block anywhere in it. */
    fun textLooksEncrypted(text: String): Boolean = text.contains(ARMOR_BEGIN)

    /** Pull the first armored block out of [text], so surrounding chat text doesn't break decrypt. */
    fun extractArmor(text: String): String {
        val start = text.indexOf(ARMOR_BEGIN)
        if (start < 0) return text
        val endMarker = "-----END AGE ENCRYPTED FILE-----"
        val end = text.indexOf(endMarker, start)
        return if (end < 0) text.substring(start) else text.substring(start, end + endMarker.length)
    }

    /** Reads only the first bytes of [uri] to tell an age file (binary or armored) from anything else. */
    fun fileLooksEncrypted(context: Context, uri: Uri): Boolean = try {
        SafIo.openInput(context, uri).use { input ->
            val buf = ByteArray(128)
            var n = 0
            while (n < buf.size) {
                val r = input.read(buf, n, buf.size - n)
                if (r <= 0) break
                n += r
            }
            val head = String(buf, 0, n, Charsets.ISO_8859_1).trimStart()
            head.startsWith(AGE_MAGIC) || head.startsWith(ARMOR_BEGIN)
        }
    } catch (_: Exception) {
        false
    }
}

/** Sending results back out. Only ciphertext goes out without a confirmation step. */
object ShareOut {
    fun text(context: Context, text: String, title: String = "Share") {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
        }
        context.startActivity(Intent.createChooser(send, title))
    }

    /** Share a document AgePony wrote (an encrypted output), granting read access to the target. */
    fun file(context: Context, uri: Uri, name: String, title: String = "Share encrypted file") {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = SafIo.MIME_OCTET
            putExtra(Intent.EXTRA_STREAM, uri)
            clipData = ClipData.newUri(context.contentResolver, name, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(send, title))
    }
}
