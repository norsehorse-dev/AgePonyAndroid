package com.agepony.app.security.nfc

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * CTAP2-over-NFC transport. Drives an FIDO security key (YubiKey 5 NFC, Token2) using
 * NFC reader mode and ISO-DEP APDUs.
 *
 * Framing (FIDO NFC binding): select the FIDO applet (AID A0000006472F0001), then send
 * the CTAP frame in an NFCCTAP_MSG APDU (`80 10 00 00`). The authenticator may answer with
 * SW 0x9100 (keepalive) while waiting for a touch, in which case the platform polls with
 * NFCCTAP_GETRESPONSE (`80 11 00 00`) until the real response arrives; long responses chain
 * with ISO GET RESPONSE (0x61xx). Requests longer than 255 bytes use extended-length APDUs.
 *
 * [withSecurityKey] runs the whole exchange inside one tap, which the clientPin handshake
 * (key agreement + PIN token + command) requires to share a session.
 */
class SecurityKeyTransport(private val activity: FragmentActivity) {
    class NfcException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private val adapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(activity)

    fun isAvailable(): Boolean = adapter?.isEnabled == true

    /**
     * Wait for a security key tap, select the applet, and run [block] against the live
     * session. Reader mode is torn down when [block] returns or throws.
     */
    suspend fun <T> withSecurityKey(timeoutMs: Long = 60_000, block: suspend (Session) -> T): T {
        val nfc = adapter ?: throw NfcException("this device has no NFC")
        if (!nfc.isEnabled) throw NfcException("NFC is turned off")
        val tag = awaitTag(nfc, timeoutMs)
        val isoDep = IsoDep.get(tag) ?: throw NfcException("tag does not support ISO-DEP")
        try {
            isoDep.connect()
            isoDep.timeout = 7_000
            val session = Session(isoDep)
            session.selectApplet()
            return block(session)
        } catch (e: IOException) {
            throw NfcException("NFC communication failed: ${e.message}", e)
        } finally {
            runCatching { isoDep.close() }
            runCatching { nfc.disableReaderMode(activity) }
        }
    }

    private suspend fun awaitTag(nfc: NfcAdapter, timeoutMs: Long): Tag =
        suspendCancellableCoroutine { cont ->
            val callback = NfcAdapter.ReaderCallback { tag ->
                if (cont.isActive) cont.resume(tag)
            }
            val flags = NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
            val options = android.os.Bundle().apply {
                putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250)
            }
            try {
                nfc.enableReaderMode(activity, callback, flags, options)
            } catch (e: Exception) {
                cont.resumeWithException(NfcException("could not start NFC reader: ${e.message}", e))
            }
            cont.invokeOnCancellation { runCatching { nfc.disableReaderMode(activity) } }
        }

    /** A live ISO-DEP session with the FIDO applet selected. */
    class Session(private val isoDep: IsoDep) {
        private val fidoAid = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
        )

        fun selectApplet() {
            val select = buildApdu(0x00, 0xA4, 0x04, 0x00, fidoAid, le = 256)
            val (data, sw) = transceiveRetry(select)
            if (sw != 0x9000) throw NfcException("applet select failed: SW=%04x".format(sw))
            if (data.isEmpty()) { /* some keys return no FCI; acceptable */ }
        }

        /**
         * Send a CTAP2 frame (command byte + CBOR) and return the full CTAP response
         * (status byte + CBOR). Handles keepalive and response chaining.
         */
        fun ctap(frame: ByteArray): ByteArray {
            val msg = buildApdu(0x80, 0x10, 0x00, 0x00, frame, le = 65536)
            var (data, sw) = transceiveRetry(msg)
            val acc = ByteArrayOutputStream()
            acc.write(data)
            while (true) {
                when {
                    sw == 0x9000 -> return acc.toByteArray()
                    sw == 0x9100 -> {
                        // keepalive: poll for the result
                        val poll = buildApdu(0x80, 0x11, 0x00, 0x00, ByteArray(0), le = 65536)
                        val r = transceiveRetry(poll); data = r.first; sw = r.second
                        acc.reset(); acc.write(data)
                    }
                    sw shr 8 == 0x61 -> {
                        // ISO chaining: GET RESPONSE for the remaining (sw and 0xff) bytes
                        val remaining = sw and 0xff
                        val get = byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, remaining.toByte())
                        val r = transceiveRetry(get); sw = r.second
                        acc.write(r.first)
                    }
                    else -> throw NfcException("CTAP transport error: SW=%04x".format(sw))
                }
            }
        }

        /** One transient retry on a dropped transceive, then give up. */
        private fun transceiveRetry(apdu: ByteArray): Pair<ByteArray, Int> = try {
            split(isoDep.transceive(apdu))
        } catch (e: IOException) {
            if (!isoDep.isConnected) runCatching { isoDep.connect() }
            try {
                split(isoDep.transceive(apdu))
            } catch (e2: IOException) {
                throw NfcException("transceive failed after retry: ${e2.message}", e2)
            }
        }

        private fun split(response: ByteArray): Pair<ByteArray, Int> {
            if (response.size < 2) throw NfcException("APDU response too short")
            val sw = ((response[response.size - 2].toInt() and 0xff) shl 8) or
                (response[response.size - 1].toInt() and 0xff)
            return response.copyOfRange(0, response.size - 2) to sw
        }

        /** Build a short or extended-length APDU as the data size requires. */
        private fun buildApdu(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(cla); out.write(ins); out.write(p1); out.write(p2)
            val extended = data.size > 255 || le > 256
            if (data.isNotEmpty()) {
                if (extended) {
                    out.write(0x00)
                    out.write((data.size ushr 8) and 0xff)
                    out.write(data.size and 0xff)
                } else {
                    out.write(data.size and 0xff)
                }
                out.write(data)
            }
            if (le > 0) {
                if (extended) {
                    if (data.isEmpty()) out.write(0x00)
                    if (le >= 65536) { out.write(0x00); out.write(0x00) }
                    else { out.write((le ushr 8) and 0xff); out.write(le and 0xff) }
                } else {
                    out.write(if (le >= 256) 0x00 else le and 0xff)
                }
            }
            return out.toByteArray()
        }
    }
}
