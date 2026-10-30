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
 *
 * 5.1.0 check against iOS 5.1.1 M-2: decrypted output never goes through a temp file on
 * Android. File decrypt streams straight into the document the user picked (and deletes it if
 * the decrypt fails, audit L-18), and Text, passphrase mode and the share sheet keep plaintext in
 * memory only. The only plaintext on disk is an encrypt's staging copy of its input, in the
 * app-private cache, removed in a finally by the flow that made it, and swept here at process
 * start (AgePonyApplication) and on every lock.
 */
object TempFiles {

    /** Name prefix for every AgePony temp file or directory under cacheDir. */
    const val PREFIX = "agepony-"

    fun sweep(context: Context) {
        sweepDir(context.cacheDir ?: return)
    }

    /** [sweep] for one directory: removes every entry named with [PREFIX], nothing else. */
    fun sweepDir(dir: File) {
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
