package com.agepony.app.vault

import android.content.Context
import com.agepony.core.crypto.Diceware

/**
 * The bundled diceware word list.
 *
 * The file is the EFF long list (7776 words), shipped verbatim as an asset rather than reformatted,
 * so its provenance can be checked against the published original. See NOTICE for attribution.
 *
 * It is loaded from `assets` rather than `res/raw` deliberately: a missing asset is a runtime
 * absence rather than a compile error, so the generator simply does not appear if the list is not
 * there, and nothing else in the app is affected.
 */
object Wordlist {
    const val ASSET_NAME = "eff_large_wordlist.txt"

    @Volatile
    private var cached: List<String>? = null

    /**
     * The word list, or an empty list if the asset is missing or does not look like the real EFF
     * list. Callers should hide the generator when this is empty rather than fall back to a
     * smaller list, because a silently shrunken list would silently weaken every passphrase.
     */
    fun effLong(context: Context): List<String> {
        cached?.let { return it }
        val loaded = try {
            val text = context.assets.open(ASSET_NAME).bufferedReader().use { it.readText() }
            val words = Diceware.parseWordlist(text)
            if (words.size == Diceware.EFF_LONG_LIST_SIZE) words else emptyList()
        } catch (e: Exception) {
            emptyList()
        }
        cached = loaded
        return loaded
    }
}
