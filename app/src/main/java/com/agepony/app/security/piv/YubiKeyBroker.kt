package com.agepony.app.security.piv

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.annotation.StringRes
import androidx.fragment.app.FragmentActivity
import com.agepony.app.R
import com.agepony.app.security.nfc.NfcResendPolicy
import com.agepony.app.vault.SharedVault
import com.agepony.app.vault.setYubiKeyPinPolicy
import com.agepony.core.crypto.P256KeyAgreement
import com.agepony.core.piv.Piv
import com.agepony.core.piv.YubiKeyPinPolicy
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
 * thread here while the UI (YubiKeyPromptHost) asks for the PIN and a tap. Whether the PIN comes
 * first is decided from the identity's stored PIN policy by [YubiKeyPinFlow] (5.1.0 item 1): a
 * key that needs it, or whose policy isn't known yet, gets the PIN prompt and then one tap that
 * runs VERIFY and the ECDH. What a tap learns about the policy goes back into the vault. The PIN
 * itself lives only for that one tap.
 *
 * NFC only for now; USB-C YubiKeys need a CCID stack AgePony doesn't have yet.
 */
object YubiKeyBroker {
    class YubiKeyCancelled : Exception("Cancelled.")

    sealed class Prompt {
        data class Tap(val message: String) : Prompt()

        /** [note] says why it is asked again; [offersNoPin] adds "This key has no PIN". */
        data class Pin(val note: YubiKeyPinNote?, val offersNoPin: Boolean) : Prompt()
    }

    private val _prompt = MutableStateFlow<Prompt?>(null)
    val prompt: StateFlow<Prompt?> = _prompt.asStateFlow()

    @Volatile private var current: WeakReference<FragmentActivity>? = null
    private var pinReply: ((YubiKeyPinEntry?) -> Unit)? = null
    private var cancelTap: (() -> Unit)? = null

    fun attach(activity: FragmentActivity) { current = WeakReference(activity) }
    fun detach(activity: FragmentActivity) { if (current?.get() === activity) current = null }

    val hasNfc: Boolean get() = current?.get()?.let { NfcAdapter.getDefaultAdapter(it) != null } ?: false

    // ---- called from the prompt UI ----

    fun submitPin(pin: String) { pinReply?.invoke(YubiKeyPinEntry.Pin(pin)) }

    /** "This key has no PIN": tap without one. */
    fun submitNoPin() { pinReply?.invoke(YubiKeyPinEntry.NoPin) }

    fun cancel() {
        pinReply?.invoke(null)
        cancelTap?.invoke()
    }

    // ---- operations (worker thread only) ----

    /**
     * Key agreement for the age identity behind [stub]. [pinPolicy] is the identity's stored
     * policy; what a tap learns is written back to the vault record [identityId].
     */
    fun keyAgreement(
        stub: YubiKeyStub,
        identityId: String? = null,
        pinPolicy: YubiKeyPinPolicy = YubiKeyPinPolicy.UNKNOWN,
    ): P256KeyAgreement {
        var policy = pinPolicy
        return P256KeyAgreement { peer ->
            YubiKeyPinFlow(
                initialPolicy = policy,
                askPin = ::askPin,
                tap = { pin, readPolicy -> tapEcdh(stub, peer, pin, readPolicy) },
                learn = { learned ->
                    policy = learned
                    if (identityId != null) storePolicy(identityId, learned)
                },
            ).run()
        }
    }

    /** Tap once to read the public key behind [stub]; checks it matches the stub's tag. */
    fun readPublicKey(stub: YubiKeyStub): ByteArray = readPublicKeyAndPinPolicy(stub).first

    /**
     * Tap once to read the public key behind [stub], plus the slot's PIN policy from GET
     * METADATA in the same tap (5.1.0 item 1). Firmware before 5.3 gives unknown; a failed
     * metadata read never fails the key read.
     */
    fun readPublicKeyAndPinPolicy(stub: YubiKeyStub): Pair<ByteArray, YubiKeyPinPolicy> =
        withCard(R.string.core_yubikey_tap_read, stub) { card ->
            val pub = Piv.readPublicKey(card, stub.slot)
            if (!stub.matchesKey(pub)) throw Piv.PivException("slot key doesn't match the stub", reason = Piv.PivException.Reason.KEY_MISMATCH)
            pub to readPinPolicy(card, stub.slot)
        }

    private fun tapEcdh(stub: YubiKeyStub, peer: ByteArray, pin: String?, readPolicy: Boolean): YubiKeyTap =
        withCard(R.string.core_yubikey_tap_decrypt, stub) { card ->
            pin?.let { Piv.verifyPin(card, it) }
            val shared = Piv.ecdh(card, stub.slot, peer)
            YubiKeyTap(shared, if (readPolicy) readPinPolicy(card, stub.slot) else YubiKeyPinPolicy.UNKNOWN)
        }

    private fun readPinPolicy(card: Piv.Card, slot: Int): YubiKeyPinPolicy =
        try {
            Piv.pinPolicy(card, slot)
        } catch (e: Exception) {
            YubiKeyPinPolicy.UNKNOWN
        }

    /** Best effort: if it can't be saved, the next decrypt just asks the way this one did. */
    private fun storePolicy(identityId: String, policy: YubiKeyPinPolicy) {
        val context = current?.get()?.applicationContext ?: return
        Handler(Looper.getMainLooper()).post {
            runCatching { SharedVault.get(context).setYubiKeyPinPolicy(identityId, policy) }
        }
    }

    private fun askPin(note: YubiKeyPinNote?, offersNoPin: Boolean): YubiKeyPinEntry {
        val latch = CountDownLatch(1)
        var answer: YubiKeyPinEntry? = null
        pinReply = { answer = it; pinReply = null; latch.countDown() }
        _prompt.value = Prompt.Pin(note, offersNoPin)
        try {
            if (!latch.await(5, TimeUnit.MINUTES)) throw YubiKeyCancelled()
        } finally {
            _prompt.value = null
        }
        return answer ?: throw YubiKeyCancelled()
    }

    /**
     * Wait for a tap, open PIV, check the serial, run [block], always tearing reader mode down.
     * [message] is the tap prompt's text, read from the foreground activity.
     */
    private fun <T> withCard(@StringRes message: Int, stub: YubiKeyStub, block: (Piv.Card) -> T): T {
        check(Looper.myLooper() != Looper.getMainLooper()) { "YubiKey I/O must run off the main thread" }
        val activity = current?.get() ?: throw Piv.PivException("no foreground activity", reason = Piv.PivException.Reason.APP_NOT_OPEN)
        val nfc = NfcAdapter.getDefaultAdapter(activity) ?: throw Piv.PivException("no NFC", reason = Piv.PivException.Reason.NO_NFC)
        if (!nfc.isEnabled) throw Piv.PivException("NFC is off", reason = Piv.PivException.Reason.NFC_OFF)

        val latch = CountDownLatch(1)
        var tag: Tag? = null
        var cancelled = false
        cancelTap = { cancelled = true; latch.countDown() }
        _prompt.value = Prompt.Tap(activity.getString(message))
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
            val isoDep = IsoDep.get(tag ?: throw Piv.PivException("no tag", reason = Piv.PivException.Reason.READER_FAILED))
                ?: throw Piv.PivException("not ISO-DEP", reason = Piv.PivException.Reason.NOT_A_SMART_CARD)
            return try {
                isoDep.connect()
                isoDep.timeout = 10_000
                val holdAgain = activity.getString(R.string.core_yubikey_hold_again)
                val card = Piv.Card { apdu -> transmit(isoDep, apdu, holdAgain) }
                Piv.select(card)
                Piv.serial(card)?.let { s ->
                    if (s != stub.serial) throw Piv.PivException(
                        "wrong YubiKey", reason = Piv.PivException.Reason.WRONG_YUBIKEY, foundSerial = s.toLong(), expectedSerial = stub.serial.toLong(),
                    )
                }
                block(card)
            } catch (e: IOException) {
                throw Piv.PivException("tag lost", reason = Piv.PivException.Reason.MOVED_AWAY)
            } finally {
                runCatching { isoDep.close() }
            }
        } finally {
            cancelTap = null
            _prompt.value = null
            main.post { runCatching { nfc.disableReaderMode(activity) } }
        }
    }

    /**
     * One APDU. A transient NFC error is retried once, but only for a command that is safe to
     * run twice; VERIFY never is, since a lost answer may already have spent a PIN try, so the
     * user holds the key again instead (5.1.0, L-8). No reconnect: a new connection would drop
     * the selected applet and the verified PIN.
     */
    private fun transmit(isoDep: IsoDep, apdu: ByteArray, holdAgain: String): ByteArray = try {
        isoDep.transceive(apdu)
    } catch (e: IOException) {
        if (NfcResendPolicy.isVerify(apdu)) throw Piv.PivException(holdAgain, reason = Piv.PivException.Reason.HOLD_AGAIN)
        if (!NfcResendPolicy.mayResend(apdu) || !isoDep.isConnected) throw e
        Thread.sleep(60)
        isoDep.transceive(apdu)
    }
}
