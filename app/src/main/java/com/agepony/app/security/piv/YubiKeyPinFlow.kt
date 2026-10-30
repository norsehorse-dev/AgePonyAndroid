package com.agepony.app.security.piv

import com.agepony.core.piv.Piv
import com.agepony.core.piv.YubiKeyPinPolicy

/** What the YubiKey PIN prompt gave back, for one tap only. Not a data class, so the PIN never lands in a toString. */
sealed class YubiKeyPinEntry {
    class Pin(val value: String) : YubiKeyPinEntry()

    /** "This key has no PIN": tap without one. */
    object NoPin : YubiKeyPinEntry()
}

/** Why the PIN prompt is shown again. Null on the first ask. */
sealed class YubiKeyPinNote {
    /** The key answered "PIN required" to a tap without one. */
    object NeedsPin : YubiKeyPinNote()

    /** The PIN typed isn't 6 to 8 characters; asked again without spending a tap. */
    object PinLength : YubiKeyPinNote()

    data class WrongPin(val triesLeft: Int) : YubiKeyPinNote()
}

/** What one decrypt tap gave: the shared x-coordinate, and the slot's PIN policy when the tap read it. */
class YubiKeyTap(val sharedX: ByteArray, val pinPolicy: YubiKeyPinPolicy = YubiKeyPinPolicy.UNKNOWN)

/**
 * The PIN-before-the-tap decision for one YubiKey ECDH (5.1.0 item 1). Pure, so it is tested on
 * the host; [YubiKeyBroker] supplies the prompt, the tap and where a learned policy goes.
 *
 * | Policy | First step | Tap |
 * | required | PIN prompt | VERIFY, then the ECDH |
 * | unknown | PIN prompt with "This key has no PIN" | with the PIN, or without after "no PIN" |
 * | notRequired | none | without the PIN |
 *
 * A tap without the PIN that works teaches notRequired; "PIN required" teaches required, asks
 * (no "no PIN" button) and taps again, the safety net for a key whose policy changed. With a PIN
 * and an unknown policy the tap also reads GET METADATA, so a 5.0.1 identity learns its policy
 * after one decrypt on firmware 5.3+. Same table as iOS `DecryptIdentities.prepare`.
 */
class YubiKeyPinFlow(
    initialPolicy: YubiKeyPinPolicy,
    /** Show the prompt and wait; throws when the user cancels. */
    private val askPin: (note: YubiKeyPinNote?, offersNoPin: Boolean) -> YubiKeyPinEntry,
    /** One tap: VERIFY when [pin] is set, the ECDH, then GET METADATA when [readPolicy]. */
    private val tap: (pin: String?, readPolicy: Boolean) -> YubiKeyTap,
    /** A policy this flow learned, to store. Called only when it changes. */
    private val learn: (YubiKeyPinPolicy) -> Unit,
) {
    var policy: YubiKeyPinPolicy = initialPolicy
        private set

    fun run(): ByteArray {
        var entry: YubiKeyPinEntry? =
            if (policy == YubiKeyPinPolicy.NOT_REQUIRED) null else askPin(null, policy == YubiKeyPinPolicy.UNKNOWN)
        while (true) {
            val pin: String? = when (val e = entry) {
                is YubiKeyPinEntry.Pin -> e.value
                YubiKeyPinEntry.NoPin, null -> null
            }
            if (pin != null && !pinLengthIsValid(pin)) {
                // A PIN of the wrong length would only fail on the key and could spend a try.
                entry = askPin(YubiKeyPinNote.PinLength, policy == YubiKeyPinPolicy.UNKNOWN)
                continue
            }
            try {
                val result = tap(pin, pin != null && policy == YubiKeyPinPolicy.UNKNOWN)
                if (pin == null) {
                    remember(YubiKeyPinPolicy.NOT_REQUIRED)
                } else if (result.pinPolicy != YubiKeyPinPolicy.UNKNOWN) {
                    remember(result.pinPolicy)
                }
                return result.sharedX
            } catch (e: Piv.PinRequiredException) {
                // Tapped without a PIN and the key wants one after all (its policy changed, or
                // "This key has no PIN" was wrong): ask, then tap again.
                remember(YubiKeyPinPolicy.REQUIRED)
                entry = askPin(YubiKeyPinNote.NeedsPin, false)
            } catch (e: Piv.WrongPinException) {
                if (e.retriesLeft == 0) throw e
                entry = askPin(YubiKeyPinNote.WrongPin(e.retriesLeft), policy == YubiKeyPinPolicy.UNKNOWN)
            }
        }
    }

    private fun remember(learned: YubiKeyPinPolicy) {
        if (learned == policy) return
        policy = learned
        learn(learned)
    }

    companion object {
        /** A YubiKey PIV PIN is 6 to 8 characters (bytes as sent to the key). */
        fun pinLengthIsValid(pin: String): Boolean = pin.toByteArray(Charsets.UTF_8).size in 6..8
    }
}
