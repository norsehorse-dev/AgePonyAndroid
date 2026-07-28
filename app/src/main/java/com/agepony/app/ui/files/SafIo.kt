package com.agepony.app.ui.files

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import java.io.File
import java.io.FilterInputStream
import java.io.InputStream
import java.io.OutputStream

//
// Storage Access Framework plumbing shared by the Files flows.
//
// The rule these helpers exist to keep: a file's bytes go straight from the provider's input
// stream to the provider's output stream, one chunk at a time. Nothing here ever returns a
// ByteArray of a whole file.
//

/** A file the user picked, with whatever the provider was willing to say about it. */
data class SourceRef(val uri: Uri, val name: String, val size: Long)

/**
 * A source ready to stream: [size] is exact, and [open] may be called more than once, because
 * sign-and-encrypt reads the input twice (once to hash, once to encrypt).
 *
 * [cleanup] removes the staging copy, if one was needed. Always call it when finished.
 */
class PreparedSource(
    val name: String,
    val size: Long,
    private val opener: () -> InputStream,
    private val staged: File?,
) {
    fun open(): InputStream = opener()

    fun cleanup() {
        staged?.delete()
    }
}

object SafIo {
    const val MIME_OCTET = "application/octet-stream"

    private const val COPY_BUFFER = 64 * 1024

    fun queryNameSize(context: Context, uri: Uri): Pair<String, Long> {
        var name = "file"
        var size = 0L
        context.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
            if (c.moveToFirst()) {
                if (nameIdx >= 0) c.getString(nameIdx)?.let { name = it }
                if (sizeIdx >= 0 && !c.isNull(sizeIdx)) size = c.getLong(sizeIdx)
            }
        }
        return name to size
    }

    fun sourceRef(context: Context, uri: Uri): SourceRef {
        val (name, size) = queryNameSize(context, uri)
        return SourceRef(uri, name, size)
    }

    fun openInput(context: Context, uri: Uri): InputStream =
        context.contentResolver.openInputStream(uri)
            ?: throw IllegalStateException("Couldn't open the file.")

    /**
     * Open for writing, truncating first. Some providers hand back an append-style stream for
     * plain "w", which would leave the tail of a previous, longer file behind the new one.
     */
    fun openOutput(context: Context, uri: Uri): OutputStream {
        val truncating = try {
            context.contentResolver.openOutputStream(uri, "wt")
        } catch (_: Exception) {
            null
        }
        return truncating
            ?: context.contentResolver.openOutputStream(uri)
            ?: throw IllegalStateException("Couldn't open the destination.")
    }

    /** Create [displayName] inside a tree the user granted, returning the new document's uri. */
    fun createInTree(context: Context, treeUri: Uri, displayName: String, mime: String = MIME_OCTET): Uri {
        val parent = DocumentsContract.buildDocumentUriUsingTree(
            treeUri,
            DocumentsContract.getTreeDocumentId(treeUri),
        )
        return DocumentsContract.createDocument(context.contentResolver, parent, mime, displayName)
            ?: throw IllegalStateException("Couldn't create '$displayName' in that folder.")
    }

    /**
     * Guarantee an exact size. A tar header carries the entry size ahead of the bytes, so a
     * provider that reports no size (some cloud providers do not) forces a staging copy into the
     * app cache. Only used when the size is actually needed.
     */
    fun prepare(context: Context, ref: SourceRef, needSize: Boolean): PreparedSource {
        if (!needSize || ref.size > 0) {
            return PreparedSource(ref.name, ref.size, { openInput(context, ref.uri) }, null)
        }
        val staged = File.createTempFile("agepony-stage", null, context.cacheDir)
        openInput(context, ref.uri).use { input ->
            staged.outputStream().use { out -> input.copyTo(out, COPY_BUFFER) }
        }
        return PreparedSource(ref.name, staged.length(), { staged.inputStream() }, staged)
    }

    /** `report.pdf` -> `report-1.pdf` when the name is already taken in the destination. */
    fun uniqueName(name: String, used: MutableSet<String>): String {
        val safe = name.ifBlank { "file" }
        if (used.add(safe)) return safe
        val dot = safe.lastIndexOf('.')
        val base = if (dot > 0) safe.substring(0, dot) else safe
        val ext = if (dot > 0) safe.substring(dot) else ""
        var i = 1
        while (true) {
            val candidate = "$base-$i$ext"
            if (used.add(candidate)) return candidate
            i++
        }
    }

    fun humanSize(bytes: Long): String {
        if (bytes <= 0) return "—"
        val units = arrayOf("B", "KB", "MB", "GB")
        var b = bytes.toDouble()
        var i = 0
        while (b >= 1024 && i < units.size - 1) { b /= 1024; i++ }
        return if (i == 0) "$bytes B" else String.format("%.1f %s", b, units[i])
    }
}

/**
 * Reports bytes as they are read, so a long encrypt can show real progress.
 *
 * Reports are batched to [granularity] because the caller writes them to Compose state: a report
 * per 64 KiB chunk would ask for a recomposition roughly two thousand times per 130 MB file.
 * [close] flushes whatever is left over.
 */
class CountingInputStream(
    source: InputStream,
    private val onBytes: (Long) -> Unit,
    private val granularity: Long = 512L * 1024,
) : FilterInputStream(source) {

    private var pending = 0L

    override fun read(): Int {
        val b = super.read()
        if (b >= 0) add(1L)
        return b
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val r = super.read(b, off, len)
        if (r > 0) add(r.toLong())
        return r
    }

    override fun close() {
        flushPending()
        super.close()
    }

    private fun add(n: Long) {
        pending += n
        if (pending >= granularity) flushPending()
    }

    private fun flushPending() {
        if (pending > 0) {
            onBytes(pending)
            pending = 0L
        }
    }
}
