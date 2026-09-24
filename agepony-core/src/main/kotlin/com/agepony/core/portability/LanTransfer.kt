package com.agepony.core.portability

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Phone-to-phone delivery of a key transfer over the local network (5.0.0), so both screens stay
 * open for the few seconds it takes and the receiver never has to leave AgePony to fetch a file.
 *
 * The receiving phone listens on a TCP port and puts everything the sender needs in its QR code:
 * the one-time `age1pq1` recipient, a random 16-byte token, the port and its local addresses. The
 * sender encrypts the transfer to that recipient exactly as for the file route, connects, and
 * pushes the ciphertext. The network only ever carries ciphertext; the token just stops anyone
 * else on the network from filling the receiver's slot.
 *
 * Framing is RelayPony's wire protocol (norsehorse-dev/RelayPonyAndroid, `transport` module,
 * Apache-2.0): frames are `type(1) | length(4, big-endian) | payload`, with RelayPony's frame
 * numbers and its v1 HELLO layout. One transfer is one "file":
 *
 *   sender   -> HELLO(v1, scheme age, device name, handle = token hex)
 *   sender   -> FILE_BEGIN(u64 size) FILE_CHUNK* FILE_END(sha256) DONE
 *   receiver -> ACK(1 byte: 1 accepted, 0 refused)
 *
 * Pure java.net so it runs in JVM tests over loopback; the app chooses which network the socket
 * uses (Wi-Fi, not cellular).
 */
object LanTransfer {
    // RelayPony WireProtocol v1 frame types and scheme id.
    private const val HELLO: Int = 0x01
    private const val FILE_BEGIN: Int = 0x03
    private const val FILE_CHUNK: Int = 0x04
    private const val FILE_END: Int = 0x05
    private const val ACK: Int = 0x06
    private const val DONE: Int = 0x07
    private const val WIRE_VERSION = 1
    private const val SCHEME_AGE = 0x01

    const val TOKEN_SIZE = 16
    const val MAX_BYTES = 16 * 1024 * 1024
    private const val CHUNK = 64 * 1024
    private const val PREFIX = "AGEPONY:XFER1/"

    class LanTransferException(message: String) : Exception(message)

    /**
     * What the receiver's QR code carries. Encoded upper-case in the QR alphanumeric character
     * set (`AGEPONY:XFER1/<RECIPIENT>/<TOKEN HEX>/<PORT>/<IP>+<IP>`), which keeps the ~2000-char
     * post-quantum recipient in a scannable code.
     */
    class Invite(val recipient: String, val token: ByteArray, val port: Int, val hosts: List<String>) {
        init {
            require(token.size == TOKEN_SIZE) { "token must be $TOKEN_SIZE bytes" }
            require(port in 1..65535) { "bad port" }
        }

        fun encode(): String =
            (PREFIX + recipient.trim() + "/" + hex(token) + "/" + port + "/" + hosts.joinToString("+")).uppercase()

        companion object {
            fun isInvite(s: String): Boolean = s.trim().uppercase().startsWith(PREFIX)

            fun decode(s: String): Invite {
                val t = s.trim().uppercase()
                if (!t.startsWith(PREFIX)) throw LanTransferException("That isn't an AgePony receive code.")
                val parts = t.removePrefix(PREFIX).split("/")
                if (parts.size != 4) throw LanTransferException("That receive code is damaged.")
                val token = unhex(parts[1]) ?: throw LanTransferException("That receive code is damaged.")
                val port = parts[2].toIntOrNull() ?: throw LanTransferException("That receive code is damaged.")
                val hosts = parts[3].split("+").filter { it.isNotBlank() }
                return Invite(parts[0].lowercase(), token, port, hosts)
            }
        }
    }

    fun newToken(): ByteArray = ByteArray(TOKEN_SIZE).also { SecureRandom().nextBytes(it) }

    // ---- receiver ----

    /** HELLO with the right token must arrive within this long of connecting (audit AS-3). */
    const val HANDSHAKE_DEADLINE_MS = 10_000L

    /** Once the token checks out, the whole transfer must arrive within this long. */
    const val TRANSFER_DEADLINE_MS = 120_000L

    /** Connections served at once; the oldest one without a valid token makes room for a new one. */
    const val MAX_CONNECTIONS = 4

    private const val IDLE_READ_MS = 30_000L
    private const val ACCEPT_POLL_MS = 200L

    /**
     * A listening socket for [receive] on an ephemeral port. Pass the Wi-Fi interface's address as
     * [bindAddress] so the listener is not reachable over other interfaces (null binds them all).
     */
    fun openListener(bindAddress: InetAddress? = null, backlog: Int = 8): ServerSocket =
        ServerSocket(0, backlog, bindAddress)

    /**
     * Wait on [server] until a sender presenting [token] delivers a transfer, and return its
     * bytes (the sealed age file). Connections with the wrong token, or that break the protocol,
     * are refused and the wait continues. [accept] runs before the ACK, so the sender only hears
     * "accepted" once the receiver has actually taken the bytes (the app opens the transfer there).
     * Throws [SocketTimeoutException] if nothing valid arrives
     * within the server's SO_TIMEOUT.
     *
     * [accept] gets the exact sealed bytes; show [TransferCode.of] over them before importing, so
     * the user can compare it with the code on the sender's screen (audit M-6).
     *
     * Each connection is served on its own thread, at most [MAX_CONNECTIONS] at once, and must
     * present HELLO with the right token within [HANDSHAKE_DEADLINE_MS] of connecting (a total,
     * not a per-read timeout), so a connection that trickles bytes, or never sends any, cannot hold
     * the slot the real sender needs (audit AS-3). When all slots are taken, the oldest connection
     * that has not yet shown the token is dropped for the newcomer. [accept] calls are serialized,
     * and after one returns true every other connection is refused.
     */
    fun receive(
        server: ServerSocket,
        token: ByteArray,
        maxBytes: Int = MAX_BYTES,
        accept: (ByteArray) -> Boolean = { true },
    ): ByteArray = receive(server, token, maxBytes, accept, HANDSHAKE_DEADLINE_MS, MAX_CONNECTIONS)

    /** [receive] with its limits exposed, for tests. */
    internal fun receive(
        server: ServerSocket,
        token: ByteArray,
        maxBytes: Int,
        accept: (ByteArray) -> Boolean,
        handshakeMs: Long,
        maxConnections: Int,
    ): ByteArray {
        val session = ReceiveSession(token, maxBytes, accept, handshakeMs)
        // The caller's SO_TIMEOUT keeps its meaning (how long to wait with nothing arriving); the
        // socket itself polls briefly so a finished connection is noticed promptly.
        val idleMs = server.soTimeout.toLong()
        var idleDeadline = if (idleMs > 0) System.currentTimeMillis() + idleMs else Long.MAX_VALUE
        try {
            while (true) {
                session.outcome()?.let { return it }
                val now = System.currentTimeMillis()
                if (now >= idleDeadline) {
                    if (session.active() == 0) throw SocketTimeoutException("no transfer arrived")
                    idleDeadline = now + idleMs // someone is mid-transfer: let them finish
                }
                server.soTimeout = minOf(ACCEPT_POLL_MS, idleDeadline - now).coerceAtLeast(1L).toInt()
                val socket = try {
                    server.accept()
                } catch (_: SocketTimeoutException) {
                    continue
                }
                if (idleMs > 0) idleDeadline = System.currentTimeMillis() + idleMs
                session.admit(socket, maxConnections)
            }
        } finally {
            session.shutdown()
            runCatching { server.soTimeout = idleMs.toInt() }
        }
    }

    /** The connections of one [receive] call and the transfer they produce. */
    private class ReceiveSession(
        private val token: ByteArray,
        private val maxBytes: Int,
        private val accept: (ByteArray) -> Boolean,
        private val handshakeMs: Long,
    ) {
        private class Conn(val socket: Socket) {
            val startedAt: Long = System.nanoTime()
            @Volatile var authenticated = false
        }

        private val lock = Any()
        private val conns = ArrayList<Conn>() // guarded by lock
        private val acceptLock = Any()
        private var taken = false // guarded by acceptLock
        @Volatile private var closed = false
        @Volatile private var payload: ByteArray? = null
        @Volatile private var failure: Throwable? = null

        /** The accepted transfer, null while waiting; rethrows a failure from [accept]. */
        fun outcome(): ByteArray? {
            payload?.let { return it }
            failure?.let { throw it }
            return null
        }

        fun active(): Int = synchronized(lock) { conns.size }

        fun admit(socket: Socket, max: Int) {
            synchronized(lock) {
                if (closed) { closeQuietly(socket); return }
                if (conns.size >= max) {
                    val victim = conns.filter { !it.authenticated }.minByOrNull { it.startedAt }
                    if (victim == null) { closeQuietly(socket); return }
                    conns.remove(victim)
                    closeQuietly(victim.socket)
                }
                val c = Conn(socket)
                conns += c
                try {
                    Thread({ serve(c) }, "agepony-xfer-conn").apply { isDaemon = true }.start()
                } catch (t: Throwable) {
                    conns.remove(c)
                    closeQuietly(socket)
                }
            }
        }

        fun shutdown() {
            val all = synchronized(lock) {
                closed = true
                ArrayList(conns).also { conns.clear() }
            }
            all.forEach { closeQuietly(it.socket) }
        }

        private fun serve(c: Conn) {
            try {
                c.socket.use { s ->
                    val raw = DeadlineInput(s, System.currentTimeMillis() + handshakeMs)
                    val input = BufferedInputStream(raw)
                    val out = BufferedOutputStream(s.getOutputStream())
                    val bytes = try {
                        readTransfer(input, token, maxBytes) {
                            c.authenticated = true
                            raw.deadline = System.currentTimeMillis() + TRANSFER_DEADLINE_MS
                        }
                    } catch (_: Exception) {
                        null
                    }
                    val ok = bytes != null && take(bytes)
                    runCatching { frame(out, ACK, byteArrayOf(if (ok) 1 else 0)); out.flush() }
                    if (ok) payload = bytes
                }
            } catch (_: Exception) {
                // A dropped or broken connection only ends itself.
            } finally {
                synchronized(lock) { conns.remove(c) }
            }
        }

        /** Hand [bytes] to [accept], one connection at a time, until one is taken. */
        private fun take(bytes: ByteArray): Boolean = synchronized(acceptLock) {
            if (taken || closed) return false
            val ok = try {
                accept(bytes)
            } catch (t: Throwable) {
                failure = t
                taken = true
                return false
            }
            if (ok) taken = true
            ok
        }
    }

    /**
     * The socket's input with an overall [deadline] (epoch millis): each read waits at most until
     * the deadline (and at most [IDLE_READ_MS]), so a sender that trickles bytes is cut off on
     * time rather than resetting a per-read timeout forever.
     */
    private class DeadlineInput(private val socket: Socket, @Volatile var deadline: Long) : InputStream() {
        private val inner = socket.getInputStream()

        override fun read(): Int {
            arm()
            return inner.read()
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            arm()
            return inner.read(b, off, len)
        }

        override fun close() = inner.close()

        private fun arm() {
            val left = deadline - System.currentTimeMillis()
            if (left <= 0) throw SocketTimeoutException("connection deadline passed")
            socket.soTimeout = minOf(left, IDLE_READ_MS).toInt()
        }
    }

    private fun closeQuietly(s: Socket) {
        runCatching { s.close() }
    }

    private fun readTransfer(
        input: InputStream,
        token: ByteArray,
        maxBytes: Int,
        onAuthenticated: () -> Unit = {},
    ): ByteArray {
        val hello = readFrame(input, 4096) ?: throw LanTransferException("no HELLO")
        if (hello.first != HELLO) throw LanTransferException("expected HELLO")
        val handle = parseHelloHandle(hello.second)
        if (!MessageDigest.isEqual(handle.toByteArray(Charsets.US_ASCII), hex(token).toByteArray(Charsets.US_ASCII))) {
            throw LanTransferException("wrong token")
        }
        onAuthenticated()
        val begin = readFrame(input, 64) ?: throw LanTransferException("no FILE_BEGIN")
        if (begin.first != FILE_BEGIN || begin.second.size != 8) throw LanTransferException("expected FILE_BEGIN")
        val size = begin.second.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
        if (size < 0 || size > maxBytes) throw LanTransferException("transfer too large")
        val body = ByteArrayOutputStream(size.toInt())
        while (true) {
            val f = readFrame(input, CHUNK) ?: throw LanTransferException("truncated")
            when (f.first) {
                FILE_CHUNK -> {
                    if (body.size() + f.second.size > size) throw LanTransferException("too much data")
                    body.write(f.second)
                }
                FILE_END -> {
                    val bytes = body.toByteArray()
                    if (bytes.size.toLong() != size) throw LanTransferException("size mismatch")
                    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
                    if (!MessageDigest.isEqual(digest, f.second)) throw LanTransferException("checksum mismatch")
                    val done = readFrame(input, 16) ?: throw LanTransferException("no DONE")
                    if (done.first != DONE) throw LanTransferException("expected DONE")
                    return bytes
                }
                else -> throw LanTransferException("unexpected frame")
            }
        }
    }

    // ---- sender ----

    /**
     * Deliver [sealed] to the receiver in [invite], trying each advertised address in turn.
     * [connect] opens the socket (the app routes it over Wi-Fi). Returns normally only when the
     * receiver acknowledged the transfer. Show [TransferCode.of] over [sealed] afterwards so the
     * receiver can check it got this transfer and not someone else's (audit M-6).
     */
    fun send(
        invite: Invite,
        sealed: ByteArray,
        deviceName: String,
        connect: (host: String, port: Int) -> Socket = { host, port ->
            Socket().apply { connect(InetSocketAddress(host, port), 5_000) }
        },
    ) {
        if (sealed.size > MAX_BYTES) throw LanTransferException("Transfer is too large to send directly.")
        var lastError: Exception? = null
        for (host in invite.hosts) {
            val socket = try {
                connect(host, invite.port)
            } catch (e: Exception) {
                lastError = e
                continue
            }
            socket.use { s ->
                s.soTimeout = 30_000
                val out = BufferedOutputStream(s.getOutputStream())
                val input = BufferedInputStream(s.getInputStream())
                frame(out, HELLO, hello(deviceName, hex(invite.token)))
                val size = sealed.size.toLong()
                frame(out, FILE_BEGIN, ByteArray(8) { i -> (size ushr (56 - 8 * i)).toByte() })
                var off = 0
                while (off < sealed.size) {
                    val n = minOf(CHUNK, sealed.size - off)
                    frame(out, FILE_CHUNK, sealed.copyOfRange(off, off + n))
                    off += n
                }
                frame(out, FILE_END, MessageDigest.getInstance("SHA-256").digest(sealed))
                frame(out, DONE, ByteArray(0))
                out.flush()
                val ack = readFrame(input, 16) ?: throw LanTransferException("The other phone closed the connection.")
                if (ack.first != ACK || ack.second.firstOrNull() != 1.toByte()) {
                    throw LanTransferException("The other phone refused the transfer. Start Receive keys again and rescan.")
                }
                return
            }
        }
        throw LanTransferException(
            "Couldn't reach the other phone. Put both on the same Wi-Fi (or one on the other's hotspot)." +
                (lastError?.message?.let { " ($it)" } ?: "")
        )
    }

    // ---- RelayPony framing ----

    private fun hello(deviceName: String, handle: String): ByteArray {
        val name = deviceName.toByteArray(Charsets.UTF_8).let { if (it.size > 200) it.copyOf(200) else it }
        val h = handle.toByteArray(Charsets.UTF_8)
        val b = ByteArrayOutputStream()
        b.write(WIRE_VERSION); b.write(SCHEME_AGE)
        b.write(name.size shr 8); b.write(name.size and 0xff); b.write(name)
        b.write(h.size shr 8); b.write(h.size and 0xff); b.write(h)
        return b.toByteArray()
    }

    private fun parseHelloHandle(p: ByteArray): String {
        var i = 0
        fun u8(): Int { if (i >= p.size) throw LanTransferException("HELLO truncated"); return p[i++].toInt() and 0xff }
        fun u16(): Int = (u8() shl 8) or u8()
        fun take(n: Int): ByteArray { if (i + n > p.size) throw LanTransferException("HELLO truncated"); return p.copyOfRange(i, i + n).also { i += n } }
        if (u8() < 1) throw LanTransferException("bad HELLO version")
        if (u8() != SCHEME_AGE) throw LanTransferException("not an age transfer")
        take(u16())
        return String(take(u16()), Charsets.UTF_8)
    }

    private fun frame(out: OutputStream, type: Int, payload: ByteArray) {
        out.write(type)
        out.write(payload.size ushr 24); out.write(payload.size ushr 16); out.write(payload.size ushr 8); out.write(payload.size)
        out.write(payload)
    }

    /** Read one frame, refusing payloads longer than [max]. Null at clean EOF. */
    private fun readFrame(input: InputStream, max: Int): Pair<Int, ByteArray>? {
        val t = input.read()
        if (t < 0) return null
        val lb = readN(input, 4)
        val len = ((lb[0].toInt() and 0xff) shl 24) or ((lb[1].toInt() and 0xff) shl 16) or
            ((lb[2].toInt() and 0xff) shl 8) or (lb[3].toInt() and 0xff)
        if (len < 0 || len > max) throw LanTransferException("frame too large")
        return t to readN(input, len)
    }

    private fun readN(input: InputStream, n: Int): ByteArray {
        val b = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(b, off, n - off)
            if (r < 0) throw LanTransferException("truncated")
            off += r
        }
        return b
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun unhex(s: String): ByteArray? {
        if (s.length != TOKEN_SIZE * 2) return null
        return runCatching { ByteArray(TOKEN_SIZE) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() } }.getOrNull()
    }
}
