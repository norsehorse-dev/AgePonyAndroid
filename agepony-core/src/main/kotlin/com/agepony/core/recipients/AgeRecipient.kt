package com.agepony.core.recipients

import com.agepony.core.Stanza

/**
 * An age recipient: knows how to wrap a file key into a stanza.
 */
fun interface AgeRecipient {
    fun wrap(fileKey: ByteArray): Stanza
}

/**
 * An age identity: knows how to attempt to unwrap a stanza to recover the file key.
 * Returns null if this identity cannot or did not unwrap the given stanza (wrong type,
 * not my key, etc.); throws on malformed input that is unambiguously bad.
 */
fun interface AgeIdentity {
    fun unwrap(stanza: Stanza): ByteArray?
}
