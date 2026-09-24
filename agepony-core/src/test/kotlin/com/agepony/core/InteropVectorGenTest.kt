package com.agepony.core

import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Throwaway generator for the Crake interop test vectors. Not a real test of
 * anything; it produces fresh AgePony-native age vectors and asserts each
 * round-trips through the core. Delete after use. Output: ~/pony-interop-vectors
 */
class InteropVectorGenTest {

    private val plaintext =
        "Crake <> Pony interop test vector. If you can read this, decryption works."

    private val outDir =
        File(System.getProperty("user.home"), "pony-interop-vectors").apply { mkdirs() }

    @Test
    fun generateAgeVectors() {
        val pt = plaintext.toByteArray(Charsets.UTF_8)

        val id = X25519Identity.generate()
        val rcpt = X25519Recipient(id.publicKey)
        val ct = Armor.encode(Age.encrypt(pt, listOf(rcpt)))
        assertArrayEquals(pt, Age.decrypt(Armor.decode(ct), listOf(id)))
        File(outDir, "age_x25519_identity.txt").writeText(id.toBech32() + "\n")
        File(outDir, "age_x25519_recipient.txt").writeText(rcpt.toBech32() + "\n")
        File(outDir, "age_x25519_hello.age").writeText(ct)

        val pid = HybridIdentity.generate()
        val prcpt = pid.recipient()
        val pct = Armor.encode(Age.encrypt(pt, listOf(prcpt)))
        assertArrayEquals(pt, Age.decrypt(Armor.decode(pct), listOf(pid)))
        File(outDir, "age_pq_identity.txt").writeText(pid.toBech32() + "\n")
        File(outDir, "age_pq_recipient.txt").writeText(prcpt.toBech32() + "\n")
        File(outDir, "age_pq_hello.age").writeText(pct)

        println("AgePony vectors written to ${outDir.absolutePath}")
    }
}
