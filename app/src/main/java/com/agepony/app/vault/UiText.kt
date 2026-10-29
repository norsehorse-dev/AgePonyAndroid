package com.agepony.app.vault

import android.content.Context
import androidx.annotation.PluralsRes
import androidx.annotation.StringRes

/**
 * User-visible text picked outside composition: a string (or plurals) resource and its format
 * arguments. The code that decides what to say stays free of Android types, so host tests can
 * check it, and the words are resolved in the user's language where they are shown. An argument
 * that is itself a [UiText] is resolved first.
 */
data class UiText(
    val id: Int,
    val args: List<Any> = emptyList(),
    /** The quantity that picks the plural form, or null for a plain string resource. */
    val quantity: Int? = null,
) {
    fun resolve(context: Context): String {
        val resolved = args.map { if (it is UiText) it.resolve(context) else it }.toTypedArray()
        return when {
            quantity != null && resolved.isEmpty() -> context.resources.getQuantityString(id, quantity)
            quantity != null -> context.resources.getQuantityString(id, quantity, *resolved)
            resolved.isEmpty() -> context.getString(id)
            else -> context.getString(id, *resolved)
        }
    }

    companion object {
        fun res(@StringRes id: Int, vararg args: Any): UiText = UiText(id, args.toList())
        fun plural(@PluralsRes id: Int, quantity: Int, vararg args: Any): UiText = UiText(id, args.toList(), quantity)
    }
}
