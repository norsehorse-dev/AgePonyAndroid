package com.agepony.app.security.piv

import com.agepony.core.piv.Piv
import com.agepony.core.piv.YubiKeyPinPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** 5.1.0 item 1: when the PIN is asked, how many taps it takes, and what is learned. Host test, no NFC. */
class YubiKeyPinFlowTest {
    private class Cancelled : Exception()

    /** A YubiKey with PIN 123456. [needsPin] is its real policy; [metadata] is what GET METADATA says. */
    private class FakeKey(
        val needsPin: Boolean,
        val metadata: YubiKeyPinPolicy = YubiKeyPinPolicy.UNKNOWN,
        var triesLeft: Int = 3,
    ) {
        val taps = ArrayList<Pair<String?, Boolean>>()

        fun tap(pin: String?, readPolicy: Boolean): YubiKeyTap {
            taps += pin to readPolicy
            if (pin != null && pin != "123456") {
                triesLeft--
                throw Piv.WrongPinException(triesLeft)
            }
            if (pin == null && needsPin) throw Piv.PinRequiredException()
            return YubiKeyTap(ByteArray(32) { 1 }, if (readPolicy) metadata else YubiKeyPinPolicy.UNKNOWN)
        }
    }

    private class FakePrompt(vararg answers: YubiKeyPinEntry) {
        private val queue = ArrayDeque(answers.toList())
        val asks = ArrayList<Pair<YubiKeyPinNote?, Boolean>>()

        fun ask(note: YubiKeyPinNote?, offersNoPin: Boolean): YubiKeyPinEntry {
            asks += note to offersNoPin
            return queue.removeFirstOrNull() ?: throw Cancelled()
        }
    }

    private class Run(policy: YubiKeyPinPolicy, val key: FakeKey, val prompt: FakePrompt) {
        val learned = ArrayList<YubiKeyPinPolicy>()
        val flow = YubiKeyPinFlow(policy, prompt::ask, key::tap) { learned += it }
    }

    private fun pin(p: String = "123456") = YubiKeyPinEntry.Pin(p)

    @Test
    fun requiredAsksFirstThenTapsOnce() {
        val r = Run(YubiKeyPinPolicy.REQUIRED, FakeKey(needsPin = true), FakePrompt(pin()))
        r.flow.run()
        assertEquals(listOf<Pair<YubiKeyPinNote?, Boolean>>(null to false), r.prompt.asks)
        assertEquals(listOf<Pair<String?, Boolean>>("123456" to false), r.key.taps)
        assertTrue(r.learned.isEmpty())
    }

    @Test
    fun unknownAsksWithNoPinOptionAndLearnsFromMetadata() {
        val r = Run(YubiKeyPinPolicy.UNKNOWN, FakeKey(needsPin = true, metadata = YubiKeyPinPolicy.REQUIRED), FakePrompt(pin()))
        r.flow.run()
        assertEquals(listOf<Pair<YubiKeyPinNote?, Boolean>>(null to true), r.prompt.asks)
        // One tap, which also reads GET METADATA.
        assertEquals(listOf<Pair<String?, Boolean>>("123456" to true), r.key.taps)
        assertEquals(listOf(YubiKeyPinPolicy.REQUIRED), r.learned)
    }

    @Test
    fun unknownOnOldFirmwareStaysUnknown() {
        val r = Run(YubiKeyPinPolicy.UNKNOWN, FakeKey(needsPin = true), FakePrompt(pin()))
        r.flow.run()
        assertEquals(1, r.key.taps.size)
        assertTrue(r.learned.isEmpty())
        assertEquals(YubiKeyPinPolicy.UNKNOWN, r.flow.policy)
    }

    @Test
    fun noPinOnANeverKeyLearnsNotRequired() {
        val r = Run(YubiKeyPinPolicy.UNKNOWN, FakeKey(needsPin = false), FakePrompt(YubiKeyPinEntry.NoPin))
        r.flow.run()
        assertEquals(listOf<Pair<String?, Boolean>>(null to false), r.key.taps)
        assertEquals(listOf(YubiKeyPinPolicy.NOT_REQUIRED), r.learned)
    }

    @Test
    fun noPinOnAKeyThatWantsOneAsksAgainWithoutTheOption() {
        val r = Run(YubiKeyPinPolicy.UNKNOWN, FakeKey(needsPin = true), FakePrompt(YubiKeyPinEntry.NoPin, pin()))
        r.flow.run()
        assertEquals(listOf<Pair<YubiKeyPinNote?, Boolean>>(null to true, YubiKeyPinNote.NeedsPin to false), r.prompt.asks)
        assertEquals(listOf<Pair<String?, Boolean>>(null to false, "123456" to false), r.key.taps)
        assertEquals(listOf(YubiKeyPinPolicy.REQUIRED), r.learned)
    }

    @Test
    fun notRequiredTapsOnceWithoutAsking() {
        val r = Run(YubiKeyPinPolicy.NOT_REQUIRED, FakeKey(needsPin = false), FakePrompt())
        r.flow.run()
        assertTrue(r.prompt.asks.isEmpty())
        assertEquals(listOf<Pair<String?, Boolean>>(null to false), r.key.taps)
        assertTrue(r.learned.isEmpty())
    }

    @Test
    fun notRequiredKeyThatNowWantsAPinFallsBack() {
        val r = Run(YubiKeyPinPolicy.NOT_REQUIRED, FakeKey(needsPin = true), FakePrompt(pin()))
        r.flow.run()
        assertEquals(listOf<Pair<YubiKeyPinNote?, Boolean>>(YubiKeyPinNote.NeedsPin to false), r.prompt.asks)
        assertEquals(2, r.key.taps.size)
        assertEquals(listOf(YubiKeyPinPolicy.REQUIRED), r.learned)
    }

    @Test
    fun wrongPinShowsTriesLeft() {
        val r = Run(YubiKeyPinPolicy.REQUIRED, FakeKey(needsPin = true), FakePrompt(pin("000000"), pin()))
        r.flow.run()
        assertEquals(listOf<Pair<YubiKeyPinNote?, Boolean>>(null to false, YubiKeyPinNote.WrongPin(2) to false), r.prompt.asks)
        assertEquals(2, r.key.taps.size)
    }

    @Test
    fun blockedPinFailsWithoutAskingAgain() {
        val r = Run(YubiKeyPinPolicy.REQUIRED, FakeKey(needsPin = true, triesLeft = 1), FakePrompt(pin("000000"), pin()))
        try {
            r.flow.run()
            fail("expected a blocked PIN")
        } catch (e: Piv.WrongPinException) {
            assertEquals(0, e.retriesLeft)
        }
        assertEquals(1, r.prompt.asks.size)
    }

    @Test
    fun wrongLengthAsksAgainWithoutATap() {
        val r = Run(YubiKeyPinPolicy.REQUIRED, FakeKey(needsPin = true), FakePrompt(pin("12345"), pin("123456789"), pin()))
        r.flow.run()
        assertEquals(
            listOf<Pair<YubiKeyPinNote?, Boolean>>(null to false, YubiKeyPinNote.PinLength to false, YubiKeyPinNote.PinLength to false),
            r.prompt.asks,
        )
        assertEquals(listOf<Pair<String?, Boolean>>("123456" to false), r.key.taps)
    }

    @Test
    fun cancellingThePromptNeverTaps() {
        val r = Run(YubiKeyPinPolicy.UNKNOWN, FakeKey(needsPin = true), FakePrompt())
        try {
            r.flow.run()
            fail("expected a cancel")
        } catch (_: Cancelled) {
        }
        assertTrue(r.key.taps.isEmpty())
    }
}
