package com.agepony.app.security.piv

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.fragment.app.FragmentActivity
import com.agepony.core.crypto.P256KeyAgreement
import com.agepony.core.piv.Piv
import com.agepony.core.recipients.YubiKeyStub
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.IOException
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * YubiKey PIV over NFC for age-plugin-yubikey keys (5.0.0).
 *
 * Decrypts run on worker threads deep inside the age code, so the key agreement blocks its
 * thread here while the UI (YubiKeyPromptHost) asks for a tap and, if the slot wants it, the
 * PIN. The PIN is asked before the tap once a key is known to need it, because the YubiKey has
 * to stay on the phone for the PIN check and the ECDH together.
 *
 * NFC only for now; USB-C YubiKeys need a CCID stack AgePony doesn't have yet.
 */
object YubiKeyBroker {
    class YubiKeyCancelled : Exception("Cancelled.")

    sealed class Prompt {
        data class Tap(val message: String) : Prompt()
        data class Pin(val message: String?) : Prompt()
    }

    private val _prompt = MutableStateFlow<Prompt?>(null)
    val prompt: StateFlow<Prompt?> = _prompt.asStateFlow()

    @Volatile private var current: WeakReference<FragmentActivity>? = null
    private var pinReply: ((String?) -> Unit)? = null
    private var cancelTap: (() -> Unit)? = null

    /** Serials whose slots have asked for a PIN this process, so the next use asks up front. */
    private val needsPin = HashSet<Long>()

    fun attach(activity: FragmentActivity) { current = WeakReference(activity) }
    fun detach(activity: FragmentActivity) { if (current?.get() === activity) current = null }

    val hasNfc: Boolean get() = current?.get()?.let { NfcAdapter.getDefaultAdapter(it) != null } ?: false

    // ---- called from the prompt UI ----

    fun submitPin(pin: String) { pinReply?.invoke(pin) }
    fun cancel() {
        pinReply?.invoke(null)
        cancelTap?.invoke()
    }

    // ---- operations (worker thread only) ----

    /** Key agreement for the age identity behind [stub]. */
    fun keyAgreement(stub: YubiKeyStub): P256KeyAgreement = P256KeyAgreement { peer -> ecdh(stub, peer) }

    /** Tap once to read the public key behind [stub]; checks it matches the stub's tag. */
    fun readPublicKey(stub: YubiKeyStub): ByteArray = withCard("Hold your YubiKey to the back of the phone to read its age key.", stub) { card ->
        val pub = Piv.readPublicKey(card, stub.slot)
        if (!stub.matchesKey(pub)) throw Piv.PivException("The key in that slot doesn't match this identity.")
        pub
    }

    private fun ecdh(stub: YubiKeyStub, peer: ByteArray): ByteArray {
        var pin: String? = if (stub.serial in needsPin) askPin(null) else null
        while (true) {
            try {
                return withCard("Hold your YubiKey to the back of the phone to decrypt.", stub) { card ->
                    pin?.let { Piv.verifyPin(card, it) }
                    Piv.ecdh(card, stub.slot, peer)
                }
            } catch (e: Piv.PinRequiredException) {
                synchronized(needsPin) { needsPin.add(stub.serial) }
                pin = askPin(null)
            } catch (e: Piv.WrongPinException) {
                if (e.retriesLeft == 0) throw e
                pin = askPin(e.message)
            }
        }
    }

    private fun askPin(message: String?): String {
        val latch = CountDownLatch(1)
        var answer: String? = null
        pinReply = { answer = it; pinReply = null; latch.countDown() }
        _prompt.value = Prompt.Pin(message)
        try {
            if (!latch.await(5, TimeUnit.MINUTES)) throw YubiKeyCancelled()
        } finally {
            _prompt.value = null
        }
        return answer ?: throw YubiKeyCancelled()
    }

    /** Wait for a tap, open PIV, check the serial, run [block], always tearing reader mode down. */
    private fun <T> withCard(message: String, stub: YubiKeyStub, block: (Piv.Card) -> T): T {
        check(Looper.myLooper() != Looper.getMainLooper()) { "YubiKey I/O must run off the main thread" }
        val activity = current?.get() ?: throw Piv.PivException("AgePony needs to be open to use a YubiKey.")
        val nfc = NfcAdapter.getDefaultAdapter(activity) ?: throw Piv.PivException("This phone has no NFC.")
        if (!nfc.isEnabled) throw Piv.PivException("NFC is turned off.")

        val latch = CountDownLatch(1)
        var tag: Tag? = null
        var cancelled = false
        cancelTap = { cancelled = true; latch.countDown() }
        _prompt.value = Prompt.Tap(message)
        val main = Handler(Looper.getMainLooper())
        main.post {
            runCatching {
                nfc.enableReaderMode(
                    activity,
                    { t -> tag = t; latch.countDown() },
                    NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                    Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250) },
                )
            }.onFailure { latch.countDown() }
        }
        try {
            if (!latch.await(2, TimeUnit.MINUTES) || cancelled) throw YubiKeyCancelled()
            val isoDep = IsoDep.get(tag ?: throw Piv.PivException("Couldn't start the NFC reader."))
                ?: throw Piv.PivException("That NFC tag isn't a smart card.")
            return try {
                isoDep.connect()
                isoDep.timeout = 10_000
                val card = Piv.Card { apdu -> isoDep.transceive(apdu) }
                Piv.select(card)
                Piv.serial(card)?.let { s ->
                    if (s != stub.serial) throw Piv.PivException("That's YubiKey $s; this key lives on YubiKey ${stub.serial}.")
                }
                block(card)
            } catch (e: IOException) {
                throw Piv.PivException("The YubiKey moved away too soon. Hold it still until it's done.")
            } finally {
                runCatching { isoDep.close() }
            }
        } finally {
            cancelTap = null
            _prompt.value = null
            main.post { runCatching { nfc.disableReaderMode(activity) } }
        }
    }
}
