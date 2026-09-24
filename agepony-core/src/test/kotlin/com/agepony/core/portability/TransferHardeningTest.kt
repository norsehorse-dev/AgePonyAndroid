package com.agepony.core.portability

import com.agepony.core.Armor
import com.agepony.core.recipients.HybridIdentity
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The transfer code lets both people check the receiver holds the sender's exact transfer (audit
 * M-6), and the LAN receiver cannot be tied up by connections that never present the token
 * (audit AS-3).
 */
class TransferHardeningTest {

    // --- TransferCode ---

    @Test
    fun transferCodeIsStableAndFormatted() {
        val sealed = "age-encryption.org/v1\n-> X25519 abc\n".toByteArray()
        val code = TransferCode.of(sealed)
        assertTrue(Regex("[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}").matches(code), code)
        assertEquals(code, TransferCode.of(sealed.copyOf()))
        // Pinned so the iOS port can check its implementation against the same bytes.
        assertEquals(PINNED, code)
        // Domain separated: not the same as the confirmation-code formatting of plain SHA-256.
        assertNotEquals(KeyTransfer.code60(MessageDigest.getInstance("SHA-256").digest(sealed)), code)
    }

    @Test
    fun transferCodeChangesWithAnyByte() {
        val a = ByteArray(5000).also { SecureRandom().nextBytes(it) }
        val b = a.copyOf().also { it[4321] = (it[4321] + 1).toByte() }
        assertNotEquals(TransferCode.of(a), TransferCode.of(b))
    }

    @Test
    fun armoredAndBinaryTransfersGiveTheSameCode() {
        val receiver = HybridIdentity.generate()
        val sealed = KeyTransfer.seal(KeyTransfer.Bundle("AGE-SECRET-KEY-1TEST\n", emptyMap(), "{}"), receiver.recipient())
        val armored = Armor.encode(sealed)
        assertEquals(TransferCode.of(sealed), TransferCode.of(armored.toByteArray()))
        // The paste route trims and may carry CRLF.
        assertEquals(TransferCode.of(sealed), TransferCode.of(armored.replace("\n", "\r\n").trim().toByteArray()))
    }

    @Test
    fun bothEndsOfALanTransferSeeTheSameCode() {
        val receiver = HybridIdentity.generate()
        val server = ServerSocket(0, 5, InetAddress.getLoopbackAddress()).apply { soTimeout = 10_000 }
        val token = LanTransfer.newToken()
        val invite = LanTransfer.Invite(receiver.recipient().toBech32(), token, server.localPort, listOf("127.0.0.1"))
        var receiverCode: String? = null
        val pool = Executors.newSingleThreadExecutor()
        val got = pool.submit<ByteArray> { LanTransfer.receive(server, token) { bytes -> receiverCode = TransferCode.of(bytes); true } }
        val sealed = KeyTransfer.seal(KeyTransfer.Bundle("AGE-SECRET-KEY-1TEST\n", emptyMap(), "{}"), receiver.recipient())
        LanTransfer.send(invite, sealed, "A")
        assertArrayEquals(sealed, got.get(10, TimeUnit.SECONDS))
        assertEquals(TransferCode.of(sealed), receiverCode)
        server.close(); pool.shutdown()
    }

    // --- AS-3: slow connections ---

    @Test
    fun idleConnectionsDoNotBlockTheRealSender() {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress()).apply { soTimeout = 20_000 }
        val token = LanTransfer.newToken()
        val pool = Executors.newSingleThreadExecutor()
        val payload = ByteArray(10_000).also { SecureRandom().nextBytes(it) }
        val got = pool.submit<ByteArray> { LanTransfer.receive(server, token) }
        // More silent connections than there are slots, plus one that trickles a HELLO header.
        val squatters = (1..(LanTransfer.MAX_CONNECTIONS + 2)).map { Socket("127.0.0.1", server.localPort) }
        val trickler = Socket("127.0.0.1", server.localPort).also { it.getOutputStream().write(0x01) }
        Thread.sleep(300)

        val started = System.nanoTime()
        LanTransfer.send(LanTransfer.Invite("age1x", token, server.localPort, listOf("127.0.0.1")), payload, "real")
        assertArrayEquals(payload, got.get(5, TimeUnit.SECONDS))
        val tookMs = (System.nanoTime() - started) / 1_000_000
        assertTrue(tookMs < LanTransfer.HANDSHAKE_DEADLINE_MS, "real sender waited $tookMs ms")
        (squatters + trickler).forEach { runCatching { it.close() } }
        server.close(); pool.shutdown()
    }

    @Test
    fun aTricklingConnectionIsCutOffAtTheDeadline() {
        val server = ServerSocket(0, 5, InetAddress.getLoopbackAddress()).apply { soTimeout = 20_000 }
        val token = LanTransfer.newToken()
        val pool = Executors.newSingleThreadExecutor()
        val got = pool.submit<ByteArray> {
            LanTransfer.receive(server, token, LanTransfer.MAX_BYTES, { true }, 800L, LanTransfer.MAX_CONNECTIONS)
        }
        val slow = Socket("127.0.0.1", server.localPort)
        slow.soTimeout = 5_000
        val out: OutputStream = slow.getOutputStream()
        val started = System.nanoTime()
        // A well-formed HELLO frame header (100-byte payload), then one payload byte every 200 ms:
        // within every frame cap, and no single read waits long, so only the overall deadline stops it.
        val writer = Thread {
            runCatching {
                out.write(byteArrayOf(0x01, 0, 0, 0, 100)); out.flush()
                repeat(100) { out.write(0x01); out.flush(); Thread.sleep(200) }
            }
        }.apply { isDaemon = true; start() }
        // The receiver drops it: we read the refusal ACK (or EOF) well before the 20 s the trickle would take.
        val input = slow.getInputStream()
        runCatching { while (input.read() >= 0) { /* drain the ACK */ } }
        val tookMs = (System.nanoTime() - started) / 1_000_000
        assertTrue(tookMs in 600..4_000, "trickling connection lasted $tookMs ms")
        writer.interrupt()
        slow.close()

        // The receiver is still waiting for the real sender.
        val payload = byteArrayOf(9, 8, 7)
        LanTransfer.send(LanTransfer.Invite("age1x", token, server.localPort, listOf("127.0.0.1")), payload, "real")
        assertArrayEquals(payload, got.get(5, TimeUnit.SECONDS))
        server.close(); pool.shutdown()
    }

    @Test
    fun receiveStillTimesOutWhenNothingArrives() {
        val server = ServerSocket(0, 5, InetAddress.getLoopbackAddress()).apply { soTimeout = 600 }
        val started = System.nanoTime()
        val e = runCatching { LanTransfer.receive(server, LanTransfer.newToken()) }.exceptionOrNull()
        assertTrue(e is java.net.SocketTimeoutException, "got $e")
        assertTrue((System.nanoTime() - started) / 1_000_000 < 3_000)
        assertEquals(600, server.soTimeout) // restored
        server.close()
    }

    private companion object {
        const val PINNED = "QNED-DFQW-8WY0"
    }
}
