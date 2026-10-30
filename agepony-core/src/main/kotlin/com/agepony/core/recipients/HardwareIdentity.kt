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

    /**
     * True for a key that has to be held to the phone (a YubiKey). Those are tried after the
     * keys in the phone's own hardware, so a working Keystore key never asks for a tap, and one
     * that fails still leaves the tap on offer (5.1.0, M-4).
     */
    val isExternalDevice: Boolean get() = false
}
