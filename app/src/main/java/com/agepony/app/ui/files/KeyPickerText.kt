package com.agepony.app.ui.files

import android.content.Context
import com.agepony.app.R
import com.agepony.app.vault.KeyPortability
import com.agepony.app.vault.StoredIdentity
import com.agepony.app.vault.StoredRecipient

/**
 * How a key reads where one is picked (5.1.0 item 3): its name, its type in words, and enough
 * of its public key to tell two keys with the same name apart. The key part is
 * [KeyPortability.keySummary], the short form the key-transfer preview already uses (the public
 * string shortened in the middle, or the SHA256 fingerprint for SSH keys, whose public lines all
 * start the same way). The type words are the ones the Identities and Recipients lists use.
 * Mirrors iOS `KeyPickerText`.
 */
object KeyPickerText {

    /** Second line of a list row, under the name: `age X25519 · age1qyqszqgp…7k3m3x9a`. */
    fun subtitle(context: Context, identity: StoredIdentity): String = context.getString(
        R.string.identities_transfer_type_key,
        KeyPortability.typeLabel(context, identity.type),
        KeyPortability.keySummary(context, identity),
    )

    fun subtitle(context: Context, recipient: StoredRecipient): String = context.getString(
        R.string.identities_transfer_type_key,
        KeyPortability.typeLabel(context, recipient.type),
        KeyPortability.keySummary(context, recipient),
    )

    /**
     * One line for a menu picker (a dropdown gets one line per option):
     * `Work · age X25519 · age1qyqszqgp…7k3m3x9a`.
     */
    fun menuLine(context: Context, identity: StoredIdentity): String = context.getString(
        R.string.identities_picker_menu_line,
        identity.name,
        KeyPortability.typeLabel(context, identity.type),
        KeyPortability.keySummary(context, identity),
    )

    fun menuLine(context: Context, recipient: StoredRecipient): String = context.getString(
        R.string.identities_picker_menu_line,
        recipient.name,
        KeyPortability.typeLabel(context, recipient.type),
        KeyPortability.keySummary(context, recipient),
    )
}
