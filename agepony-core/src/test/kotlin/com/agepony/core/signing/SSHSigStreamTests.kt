package com.agepony.core.signing

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.util.Random

/**
 * SSHSIG covers only the message hash, so signing and verifying a large file must not require
 * holding it. These check that the streamed-hash entry points agree exactly with the
 * whole-message ones (ed25519 signing is deterministic, so the armored output is comparable).
 */
class SSHSigStreamTests {

    private val message = ByteArray(300_000).also { Random(11).nextBytes(it) }
    private val seed = ByteArray(32).also { Random(12).nextBytes(it) }
    private val publicKey = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded

    @Test
    fun hashStream_matchesHashMessage() {
        assertArrayEquals(
            SSHSig.hashMessage(message),
            SSHSig.hashStream(ByteArrayInputStream(message)),
        )
        assertArrayEquals(
            SSHSig.hashMessage(message, SSHSig.HASH_SHA256),
            SSHSig.hashStream(ByteArrayInputStream(message), SSHSig.HASH_SHA256),
        )
        assertArrayEquals(
            SSHSig.hashMessage(ByteArray(0)),
            SSHSig.hashStream(ByteArrayInputStream(ByteArray(0))),
        )
    }

    @Test
    fun hashStream_rejectsUnknownAlgorithm() {
        try {
            SSHSig.hashStream(ByteArrayInputStream(message), "md5")
            throw AssertionError("expected SSHSigFormatException")
        } catch (e: SSHSig.SSHSigFormatException) {
            // expected
        }
    }

    @Test
    fun signEd25519Hashed_matchesSignEd25519() {
        val whole = SSHSigner.signEd25519(seed, publicKey, message)
        val streamed = SSHSigner.signEd25519Hashed(
            seed,
            publicKey,
            SSHSig.hashStream(ByteArrayInputStream(message)),
        )
        assertEquals(whole, streamed)
    }

    @Test
    fun verifyHashed_acceptsAStreamedHashAndRejectsAChangedMessage() {
        val signature = SSHSigner.signEd25519(seed, publicKey, message).toByteArray()

        val good = SSHSigVerifier.verifyHashed(signature) { alg ->
            SSHSig.hashStream(ByteArrayInputStream(message), alg)
        }
        assertTrue(good.valid, good.reason)

        val tampered = message.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val bad = SSHSigVerifier.verifyHashed(signature) { alg ->
            SSHSig.hashStream(ByteArrayInputStream(tampered), alg)
        }
        assertFalse(bad.valid)
    }

    @Test
    fun verifyHashed_stillChecksTheNamespace() {
        val signature = SSHSigner.signEd25519(seed, publicKey, message).toByteArray()
        val wrongNamespace = SSHSigVerifier.verifyHashed(signature, "not-agepony") { alg ->
            SSHSig.hashStream(ByteArrayInputStream(message), alg)
        }
        assertFalse(wrongNamespace.valid)
    }
}
