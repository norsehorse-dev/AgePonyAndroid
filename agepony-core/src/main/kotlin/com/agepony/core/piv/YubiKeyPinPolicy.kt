package com.agepony.core.piv

/**
 * Whether a YubiKey PIV slot wants the PIN before it will do an ECDH (5.1.0 item 1).
 *
 * The 9-byte stub doesn't say, so the app learns it from the identity file's comment, from GET
 * METADATA on the import tap, or from what a decrypt tap answers, and asks for the PIN before the
 * tap when the key needs one.
 *
 * [raw] is what the vault and `agepony.json` store as `pinPolicy`, the same strings iOS writes. A
 * missing value means [UNKNOWN].
 */
enum class YubiKeyPinPolicy(val raw: String) {
    /** Not known yet (a 5.0.1 identity, a bare stub on old firmware). Ask for the PIN first, with a way to say the key has none. */
    UNKNOWN("unknown"),

    /**
     * PIN policy Once or Always (age-plugin-yubikey's default is Once). Every NFC tap is a new PIV
     * session, so either one needs the PIN on every tap.
     */
    REQUIRED("required"),

    /** PIN policy Never: one tap, no PIN. */
    NOT_REQUIRED("notRequired");

    companion object {
        /**
         * A stored value. Null, or a value this version doesn't know (written by a newer one),
         * reads as [UNKNOWN] instead of failing the record, so the vault and a transfer still open.
         */
        fun fromRaw(raw: String?): YubiKeyPinPolicy = entries.firstOrNull { it.raw == raw } ?: UNKNOWN

        /**
         * The value of age-plugin-yubikey's `#    PIN policy: Never|Once|Always` comment. Takes
         * the first word, so `Once   (A PIN is required once per session, if set)` reads as Once.
         */
        fun fromIdentityFileValue(value: String): YubiKeyPinPolicy =
            when (value.trim().takeWhile { !it.isWhitespace() }.lowercase()) {
                "never" -> NOT_REQUIRED
                "once", "always" -> REQUIRED
                else -> UNKNOWN
            }

        /**
         * Byte 0 of tag 02 in a GET METADATA answer: 1 never, 2 once, 3 always, 0 the slot's
         * default (a PIN for the retired key-management slots). 4 and 5 are the Bio "match"
         * policies, which also gate the key.
         */
        fun fromMetadataByte(byte: Int): YubiKeyPinPolicy = when (byte and 0xff) {
            1 -> NOT_REQUIRED
            0, 2, 3, 4, 5 -> REQUIRED
            else -> UNKNOWN
        }
    }
}
