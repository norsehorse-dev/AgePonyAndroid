package com.agepony.core.recipients

import com.agepony.core.Stanza

/**
 * An identity whose private operation happens somewhere slow or interactive: secure hardware
 * behind a user prompt, or a YubiKey that has to be tapped. [matches] answers from public data
 * alone (a stanza's key tag), so callers can find out which key a file needs, and try every
 * software key first, without making the hardware do anything.
 */
interface HardwareIdentity : AgeIdentity {
    fun matches(stanza: Stanza): Boolean
}
