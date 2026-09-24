package com.agepony.app.security

import android.content.Context
import java.io.File
import java.nio.file.Files

/**
 * Sweeps AgePony's plaintext staging files out of the app cache (audits L-19, M-8).
 *
 * SafIo stages a copy of a file whose size the provider won't report as
 * cacheDir/agepony-stage*.tmp. A copy that throws, or a process that dies mid-flow, leaves
 * that plaintext behind. This runs on app start, on every lock and in reset and the duress
 * wipe, so nothing staged outlives the unlocked session that made it.
 *
 * Any cacheDir entry whose name starts with [PREFIX] is treated as AgePony staging and
 * removed, directories included. New temp files should use that prefix so they are covered.
 */
object TempFiles {

    /** Name prefix for every AgePony temp file or directory under cacheDir. */
    const val PREFIX = "agepony-"

    fun sweep(context: Context) {
        val dir = context.cacheDir ?: return
        val entries = dir.listFiles() ?: return
        for (entry in entries) {
            if (!entry.name.startsWith(PREFIX)) continue
            runCatching { deleteTree(entry) }
        }
    }

    private fun deleteTree(file: File) {
        // Never follow a link out of the cache; just remove the link itself.
        if (file.isDirectory && !Files.isSymbolicLink(file.toPath())) {
            file.listFiles()?.forEach { deleteTree(it) }
        }
        file.delete()
    }
}
