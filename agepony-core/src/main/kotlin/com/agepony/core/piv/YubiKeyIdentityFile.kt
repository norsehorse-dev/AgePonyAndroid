package com.agepony.core.piv

import com.agepony.core.recipients.P256Recipient
import com.agepony.core.recipients.YubiKeyStub

/**
 * What an age-plugin-yubikey identity file (or a bare stub line) holds (5.1.0 item 1): the stub;
 * when the file has its `# Recipient:` comment, the public key, which saves a tap on import; and
 * the slot's PIN policy from its `#    PIN policy:` comment, [YubiKeyPinPolicy.UNKNOWN] without
 * one. A recipient that doesn't belong to the stub is ignored. Mirrors iOS
 * `YubiKeyStub.parseIdentityFile`.
 */
class YubiKeyIdentityFile(
    val stub: YubiKeyStub,
    /** 33-byte compressed point from the `Recipient:` comment, or null when the file has none. */
    val publicKey: ByteArray?,
    val pinPolicy: YubiKeyPinPolicy,
) {
    companion object {
        /** True when [text] holds a stub line, alone or inside an identity file. */
        fun contains(text: String): Boolean = text.lineSequence().any { line ->
            val t = line.trim()
            !t.startsWith("#") && YubiKeyStub.isStub(t)
        }

        /** Parse [text]. Throws IllegalArgumentException when it holds no stub. */
        fun parse(text: String): YubiKeyIdentityFile {
            var stub: YubiKeyStub? = null
            val recipientKeys = ArrayList<ByteArray>()
            var pinPolicy = YubiKeyPinPolicy.UNKNOWN
            for (raw in text.lines()) {
                val line = raw.trim()
                if (line.isEmpty()) continue
                if (line.startsWith("#")) {
                    val at = line.indexOf("age1yubikey1", ignoreCase = true)
                    if (at >= 0) {
                        val token = line.substring(at).takeWhile { !it.isWhitespace() }.lowercase()
                        runCatching { P256Recipient(token).compressedPublicKey }.getOrNull()?.let { recipientKeys.add(it) }
                    } else if (stub == null) {
                        // Comments come before their stub: only the first identity's block counts,
                        // as only the first stub is read.
                        pinPolicyComment(line)?.let { pinPolicy = YubiKeyPinPolicy.fromIdentityFileValue(it) }
                    }
                } else if (stub == null && YubiKeyStub.isStub(line)) {
                    stub = YubiKeyStub.parse(line)
                }
            }
            val found = stub ?: throw IllegalArgumentException("expected an AGE-PLUGIN-YUBIKEY-1… identity")
            return YubiKeyIdentityFile(found, recipientKeys.firstOrNull { found.matchesKey(it) }, pinPolicy)
        }

        /** The text after `PIN policy:` in a comment line, or null for any other line. */
        internal fun pinPolicyComment(line: String): String? {
            val body = line.trimStart('#').trim()
            val label = "PIN policy:"
            if (!body.startsWith(label, ignoreCase = true)) return null
            return body.substring(label.length)
        }
    }
}
