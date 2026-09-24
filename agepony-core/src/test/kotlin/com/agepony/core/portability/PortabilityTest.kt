package com.agepony.core.portability

import com.agepony.core.Age
import com.agepony.core.Armor
import com.agepony.core.archive.TarArchive
import com.agepony.core.interop.AgeCli
import com.agepony.core.recipients.HybridIdentity
import com.agepony.core.recipients.X25519Identity
import com.agepony.core.recipients.X25519Recipient
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class PortabilityTest {

    private fun sampleIdentityFile(): Pair<String, List<String>> {
        val x = X25519Identity.generate()
        val pq = HybridIdentity.generate()
        val txt = KeyTransfer.identityFile(
            listOf(
                KeyTransfer.IdentityLine("laptop", X25519Recipient(x.publicKey).toBech32(), x.toBech32(), "2026-09-22T00:00:00Z"),
                KeyTransfer.IdentityLine("pq\nkey", pq.recipient().toBech32(), pq.toBech32(), null),
            )
        )
        return txt to listOf(x.toBech32(), pq.toBech32())
    }

    @Test
    fun transferRoundTrip() {
        val (ids, secrets) = sampleIdentityFile()
        val receiver = HybridIdentity.generate()
        val bundle = KeyTransfer.Bundle(ids, mapOf("id_ed25519" to "PEM1", "id ed25519" to "PEM2", "id_ed25519 " to "PEM3"), "{\"v\":1}")
        val sealed = KeyTransfer.seal(bundle, KeyTransfer.parseRecipient(receiver.recipient().toBech32()))
        val back = KeyTransfer.open(sealed, receiver)
        assertEquals(ids, back.identitiesTxt)
        assertEquals("{\"v\":1}", back.metadataJson)
        assertEquals(3, back.sshKeys.size)
        assertEquals(setOf("PEM1", "PEM2", "PEM3"), back.sshKeys.values.toSet())
        assertEquals(secrets, PaperBackup.secretKeys(back.identitiesTxt))
        // Armored transfers open too.
        assertEquals(ids, KeyTransfer.open(Armor.encode(sealed).toByteArray(), receiver).identitiesTxt)
    }

    @Test
    fun transferRejectsOtherSessionAndNonTransfers() {
        val (ids, _) = sampleIdentityFile()
        val receiver = HybridIdentity.generate()
        val sealed = KeyTransfer.seal(KeyTransfer.Bundle(ids, emptyMap(), "{}"), receiver.recipient())
        assertThrows<KeyTransfer.TransferException> { KeyTransfer.open(sealed, HybridIdentity.generate()) }
        val notTransfer = Age.encrypt(TarArchive.create(listOf(TarArchive.Entry("x", byteArrayOf(1)))), listOf(receiver.recipient()))
        assertThrows<KeyTransfer.TransferException> { KeyTransfer.open(notTransfer, receiver) }
    }

    @Test
    fun namesAreOneLine() {
        val (ids, secrets) = sampleIdentityFile()
        assertEquals("pq key", PaperBackup.namesByKey(ids)[secrets[1]])
        assertEquals("laptop", PaperBackup.namesByKey(ids)[secrets[0]])
    }

    @Test
    fun confirmationCodeIsStableAndFormatted() {
        val r = HybridIdentity.generate().recipient().toBech32()
        val c = KeyTransfer.confirmationCode(r)
        assertTrue(Regex("^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$").matches(c), c)
        assertEquals(c, KeyTransfer.confirmationCode(" $r ".uppercase()))
    }

    @Test
    fun paperBackupRoundTrip() {
        val (ids, secrets) = sampleIdentityFile()
        val page = PaperBackup.seal(ids, "correct horse", workFactor = 10)
        assertTrue(PaperBackup.isSealed(page))
        assertEquals(ids, PaperBackup.open("scanned junk\n$page", "correct horse"))
        assertThrows<PaperBackup.PaperBackupException> { PaperBackup.open(page, "wrong") }
        assertEquals(secrets, PaperBackup.secretKeys(PaperBackup.open(page, "correct horse")))
        assertTrue(PaperBackup.transcriptionGroups("abcdefghij", 2).first() == "abcd efgh")
    }

    @Test
    fun plainAgeReadsTransferAndPaper() {
        val age = AgeCli.find(); assumeTrue(age != null, "age not on PATH")
        val (ids, _) = sampleIdentityFile()
        // Transfer: plain age with the receiver's identity yields the tar with identities.txt.
        val receiver = HybridIdentity.generate()
        assumeTrue(age!!.atLeast(1, 3), "needs age >= 1.3.0 for PQ")
        val sealed = KeyTransfer.seal(KeyTransfer.Bundle(ids, emptyMap(), "{}"), receiver.recipient())
        val tar = age.decrypt(sealed, receiver.toBech32())
        val entries = TarArchive.extract(tar).associate { it.name to it.data.toString(Charsets.UTF_8) }
        assertEquals(ids, entries["identities.txt"])
        // The identities file it carries is usable by age -i.
        val msg = "restored".toByteArray()
        val firstSecret = PaperBackup.secretKeys(ids).first()
        assertArrayEquals(msg, age.decrypt(Age.encrypt(msg, listOf(X25519Recipient(X25519Identity(firstSecret).publicKey))), ids))
    }
}

class PaperSizeTest {
    @Test
    fun pqPaperBackupFitsOneQrCode() {
        val pq = HybridIdentity.generate()
        val file = KeyTransfer.identityFile(
            listOf(KeyTransfer.IdentityLine("a fairly long key name for a phone", pq.recipient().toBech32(), pq.toBech32(), "2026-09-22T12:00:00Z")),
            includePublicKey = false,
        )
        val page = PaperBackup.seal(file, "pw", workFactor = 10)
        // QR version 40 at error correction M holds 2331 bytes.
        assertTrue(page.length < 2331, "sealed page is ${page.length} chars")
    }
}
