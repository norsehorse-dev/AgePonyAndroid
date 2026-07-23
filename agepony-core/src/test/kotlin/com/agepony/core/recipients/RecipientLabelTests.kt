package com.agepony.core.recipients

import com.agepony.core.Age
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Verifies age's recipient-labels rule: a post-quantum recipient (label "postquantum")
 * cannot be combined with a classical recipient that would defeat its quantum resistance,
 * while homogeneous recipient sets encrypt normally.
 */
class RecipientLabelTests {
    private val plaintext = "recipient label test\n".toByteArray()

    @Test
    fun mixingPostQuantumWithClassicalIsRejected() {
        val pq = HybridIdentity.generate().recipient()
        val classic = X25519Recipient(X25519Identity.generate().publicKey)
        assertThrows(IllegalArgumentException::class.java) {
            Age.encrypt(plaintext, listOf(pq, classic))
        }
        assertThrows(IllegalArgumentException::class.java) {
            Age.encrypt(plaintext, listOf(classic, pq))
        }
    }

    @Test
    fun allPostQuantumRecipientsAreAllowed() {
        val a = HybridIdentity.generate()
        val b = HybridIdentity.generate()
        val ciphertext = Age.encrypt(plaintext, listOf(a.recipient(), b.recipient()))
        assertArrayEquals(plaintext, Age.decrypt(ciphertext, listOf(a)))
        assertArrayEquals(plaintext, Age.decrypt(ciphertext, listOf(b)))
    }

    @Test
    fun allClassicalRecipientsAreAllowed() {
        val a = X25519Identity.generate()
        val b = X25519Identity.generate()
        val ciphertext = Age.encrypt(
            plaintext, listOf(X25519Recipient(a.publicKey), X25519Recipient(b.publicKey))
        )
        assertArrayEquals(plaintext, Age.decrypt(ciphertext, listOf(a)))
    }
}
