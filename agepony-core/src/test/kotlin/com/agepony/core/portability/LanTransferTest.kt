package com.agepony.core.portability

import com.agepony.core.recipients.HybridIdentity
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress
import java.net.ServerSocket
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class LanTransferTest {

    @Test
    fun inviteRoundTripsAndStaysInQrAlphanumericSet() {
        val r = HybridIdentity.generate().recipient().toBech32()
        val inv = LanTransfer.Invite(r, LanTransfer.newToken(), 41234, listOf("192.168.1.20", "10.0.0.5"))
        val s = inv.encode()
        assertTrue(s.all { it in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ \$%*+-./:" }, "not QR alphanumeric")
        val back = LanTransfer.Invite.decode(s)
        assertEquals(r, back.recipient)
        assertArrayEquals(inv.token, back.token)
        assertEquals(41234, back.port)
        assertEquals(listOf("192.168.1.20", "10.0.0.5"), back.hosts)
        assertTrue(LanTransfer.Invite.isInvite(s))
    }

    @Test
    fun deliversOverLoopbackAndRefusesAWrongToken() {
        val server = ServerSocket(0, 5, InetAddress.getLoopbackAddress()).apply { soTimeout = 10_000 }
        val token = LanTransfer.newToken()
        val payload = ByteArray(300_000).also { SecureRandom().nextBytes(it) }
        val pool = Executors.newSingleThreadExecutor()
        val received = pool.submit<ByteArray> { LanTransfer.receive(server, token) }

        // A stranger on the network with the wrong token is refused; the receiver keeps waiting.
        val stranger = LanTransfer.Invite("age1x", LanTransfer.newToken(), server.localPort, listOf("127.0.0.1"))
        assertThrows<LanTransfer.LanTransferException> { LanTransfer.send(stranger, byteArrayOf(1, 2, 3), "evil") }

        val real = LanTransfer.Invite("age1x", token, server.localPort, listOf("10.255.255.1", "127.0.0.1"))
        LanTransfer.send(real, payload, "phone A") { host, port ->
            if (host != "127.0.0.1") throw java.io.IOException("unreachable")
            java.net.Socket(host, port)
        }
        assertArrayEquals(payload, received.get(10, TimeUnit.SECONDS))
        server.close(); pool.shutdown()
    }

    @Test
    fun endToEndKeyTransferOverTheWire() {
        val receiverKey = HybridIdentity.generate()
        val server = ServerSocket(0, 5, InetAddress.getLoopbackAddress()).apply { soTimeout = 10_000 }
        val invite = LanTransfer.Invite(receiverKey.recipient().toBech32(), LanTransfer.newToken(), server.localPort, listOf("127.0.0.1"))
        val scanned = LanTransfer.Invite.decode(invite.encode())
        val pool = Executors.newSingleThreadExecutor()
        val got = pool.submit<ByteArray> { LanTransfer.receive(server, invite.token) }
        val bundle = KeyTransfer.Bundle("AGE-SECRET-KEY-1TEST\n", emptyMap(), "{}")
        LanTransfer.send(scanned, KeyTransfer.seal(bundle, KeyTransfer.parseRecipient(scanned.recipient)), "A")
        assertEquals("AGE-SECRET-KEY-1TEST\n", KeyTransfer.open(got.get(10, TimeUnit.SECONDS), receiverKey).identitiesTxt)
        server.close(); pool.shutdown()
    }

    @Test
    fun senderOnlyHearsAcceptedOnceTheReceiverTookIt() {
        val receiverKey = HybridIdentity.generate()
        val stale = HybridIdentity.generate()
        val server = ServerSocket(0, 5, InetAddress.getLoopbackAddress()).apply { soTimeout = 10_000 }
        val token = LanTransfer.newToken()
        val invite = LanTransfer.Invite(receiverKey.recipient().toBech32(), token, server.localPort, listOf("127.0.0.1"))
        val pool = Executors.newSingleThreadExecutor()
        val got = pool.submit<ByteArray> {
            LanTransfer.receive(server, token) { bytes -> runCatching { KeyTransfer.open(bytes, receiverKey) }.isSuccess }
        }
        val bundle = KeyTransfer.Bundle("AGE-SECRET-KEY-1TEST\n", emptyMap(), "{}")

        // Sealed to a key the receiver can't open: refused, and the receiver keeps listening.
        val e = assertThrows<LanTransfer.LanTransferException> {
            LanTransfer.send(invite, KeyTransfer.seal(bundle, stale.recipient()), "A")
        }
        assertTrue(e.message!!.contains("refused"))

        val good = KeyTransfer.seal(bundle, receiverKey.recipient())
        LanTransfer.send(invite, good, "A")
        assertArrayEquals(good, got.get(10, TimeUnit.SECONDS))
        server.close(); pool.shutdown()
    }
}
