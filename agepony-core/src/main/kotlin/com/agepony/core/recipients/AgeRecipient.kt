package com.agepony.core.recipients

import com.agepony.core.Stanza

/**
 * An age recipient: knows how to wrap a file key into a stanza.
 */
fun interface AgeRecipient {
    fun wrap(fileKey: ByteArray): Stanza
}

/**
 * An age recipient that carries labels constraining which other recipients it may share
 * a file with. Per age's labels mechanism, every recipient in a file must agree on the
 * exact same label set; otherwise encryption is refused. This is how a post-quantum
 * recipient (label "postquantum") declines to be mixed with a non-post-quantum recipient
 * that would defeat its quantum resistance.
 *
 * A recipient that does not implement this interface is treated as having an empty label
 * set, so mixing a labeled recipient with an unlabeled one is rejected.
 */
interface LabeledAgeRecipient : AgeRecipient {
    fun labels(): Set<String>
}

/**
 * An age identity: knows how to attempt to unwrap a stanza to recover the file key.
 * Returns null if this identity cannot or did not unwrap the given stanza (wrong type,
 * not my key, etc.); throws on malformed input that is unambiguously bad.
 */
fun interface AgeIdentity {
    fun unwrap(stanza: Stanza): ByteArray?
}
