package com.agepony.app.security

import com.agepony.app.vault.VaultCrypto
import com.agepony.core.crypto.Scrypt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The crypto-level half of the duress acceptance criteria (plan B4). The three that
 * matter here (real unlocks, decoy is detected, nothing but the exact decoy triggers)
 * are provable without a device. The remaining two (post-wipe screen is state-identical
 * to a wrong password, and the statistical timing test) are on-device checks and live in
 * AgePony_4.0.0_DeviceTests.md.
 *
 * 5.0.1 adds the v2 blob (KEK bound to a device key, audit M-2), v1 compatibility, the
 * constant Keystore call pattern, the duress re-wrap without a second scrypt (audit M-8)
 * and the minimum-length policy (audit M-1). The AndroidKeyStore HMAC key is replaced by
 * a software HMAC with the same contract.
 *
 * JUnit 4, matching the rest of the app module's unit tests. Uses the real scrypt KDF
 * (Bouncy Castle) and real AES-GCM, so these are slow by unit standards (a handful of
 * 2^16 scrypt runs), but they exercise the shipping path, not a stub.
 */
class PasswordVaultTest {

    /** Software stand-in for PasswordDeviceKey that also counts calls. */
    private class SoftwareBinding : PasswordVault.DeviceBinding {
        private var key: ByteArray? = null
        var ensureCalls = 0
        var macCalls = 0

        override fun ensureKey(): Boolean {
            ensureCalls++
            if (key != null) return false
            key = ByteArray(32).also { SecureRandom().nextBytes(it) }
            return true
        }

        override fun mac(data: ByteArray): ByteArray {
            macCalls++
            val k = key ?: throw IllegalStateException("no device key")
            return Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(k, "HmacSHA256")) }.doFinal(data)
        }

        fun delete() { key = null }

        fun resetCounts() { ensureCalls = 0; macCalls = 0 }
    }

    private val vk = VaultCrypto.randomKey()
    private val device = SoftwareBinding()

    private fun wrap(secret: String, key: ByteArray = vk) = PasswordVault.wrapVaultKey(secret.toCharArray(), key, device)
    private fun duress(secret: String) = PasswordVault.duressBlob(secret.toCharArray(), device)
    private fun open(secret: String, real: ByteArray?, duress: ByteArray?, binding: PasswordVault.DeviceBinding = device) =
        PasswordVault.tryUnlock(secret.toCharArray(), real, duress, binding)

    /** A blob exactly as 4.0.0 to 5.0.0 wrote it: v1, scrypt-only KEK. */
    private fun v1Blob(secret: String, key: ByteArray, logN: Int = 15): ByteArray {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val kek = Scrypt.derive(secret.toByteArray(Charsets.UTF_8), salt, 1 shl logN, 8, 1, 32)
        return byteArrayOf(1, logN.toByte()) + salt + VaultCrypto.seal(kek, key)
    }

    @Test
    fun realSecretUnlocksAndReturnsTheVaultKey() {
        val real = wrap("correct horse")
        val outcome = open("correct horse", real, null)
        assertTrue(outcome is PasswordVault.Outcome.Real)
        assertTrue((outcome as PasswordVault.Outcome.Real).vaultKey.contentEquals(vk))
        assertFalse("a fresh v2 blob needs no re-wrap", outcome.needsRewrap)
    }

    @Test
    fun decoySecretIsReportedAsDuress() {
        val real = wrap("real-pw-1")
        val duress = duress("decoy-pw-1")
        assertTrue(open("decoy-pw-1", real, duress) is PasswordVault.Outcome.Duress)
    }

    @Test
    fun realBeatsDuressWhenBothArePresent() {
        // Enrollment forbids this collision, but the resolution order is pinned anyway.
        val real = wrap("shared-pw")
        val duress = duress("shared-pw")
        assertTrue(open("shared-pw", real, duress) is PasswordVault.Outcome.Real)
    }

    @Test
    fun wrongSecretIsWrong_notDuress() {
        val real = wrap("real-pw-1")
        val duress = duress("decoy-pw-1")
        assertTrue(open("neither", real, duress) is PasswordVault.Outcome.Wrong)
    }

    @Test
    fun nothingButTheExactDecoyTriggersTheWipe() {
        val real = wrap("real-pw-1")
        val duress = duress("decoy-pw")
        // A prefix, a suffix, and a case change must all be plain-wrong.
        for (near in listOf("decoy-p", "decoy-pw ", "Decoy-pw", "ecoy-pw")) {
            assertTrue(
                "near-miss \"$near\" must not trigger duress",
                open(near, real, duress) is PasswordVault.Outcome.Wrong
            )
        }
    }

    @Test
    fun removingTheDecoyMakesItAnOrdinaryWrongPassword() {
        val real = wrap("real-pw-1")
        assertTrue(open("decoy-pw-1", real, null) is PasswordVault.Outcome.Wrong)
    }

    @Test
    fun newBlobsAreVersion2AtWorkFactor16AndDistinct() {
        val real = wrap("pw-pw-pw")
        val duress = duress("pw-pw-pw")
        assertEquals(2, real[0].toInt())
        assertEquals(2, duress[0].toInt())
        assertEquals(16, real[1].toInt())
        assertFalse("salts differ, so blobs differ", real.contentEquals(duress))
    }

    @Test
    fun aVersion1BlobStillUnlocksAndAsksForARewrap() {
        val legacy = v1Blob("old-pin", vk)
        val outcome = open("old-pin", legacy, null)
        assertTrue(outcome is PasswordVault.Outcome.Real)
        outcome as PasswordVault.Outcome.Real
        assertTrue(outcome.vaultKey.contentEquals(vk))
        assertTrue(outcome.needsRewrap)
        // And the re-wrap the caller then writes opens as a current blob.
        val upgraded = PasswordVault.wrapVaultKey("old-pin".toCharArray(), outcome.vaultKey, device)
        val again = open("old-pin", upgraded, null)
        assertTrue(again is PasswordVault.Outcome.Real)
        assertFalse((again as PasswordVault.Outcome.Real).needsRewrap)
    }

    @Test
    fun aVersion1BlobRejectsAWrongSecret() {
        val legacy = v1Blob("old-pin", vk)
        assertTrue(open("old-pim", legacy, null) is PasswordVault.Outcome.Wrong)
    }

    @Test
    fun aVersion1DuressBlobStillFires() {
        val real = wrap("real-pw-1")
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val kek = Scrypt.derive("decoy".toByteArray(), salt, 1 shl 15, 8, 1, 32)
        val legacyDuress = byteArrayOf(1, 15) + salt + VaultCrypto.seal(kek, ByteArray(32))
        assertTrue(open("decoy", real, legacyDuress) is PasswordVault.Outcome.Duress)
    }

    @Test
    fun aVersion2BlobIsUselessWithAnotherDevicesKey() {
        // The M-2 property: a copied blob can't be tried against a different device key.
        val real = wrap("correct horse")
        val otherDevice = SoftwareBinding().also { it.ensureKey() }
        assertTrue(open("correct horse", real, null, otherDevice) is PasswordVault.Outcome.Wrong)
    }

    @Test
    fun aLostDeviceKeyIsReportedNotTreatedAsAWrongSecret() {
        val real = wrap("correct horse")
        device.delete()
        assertThrows(PasswordVault.PasswordVaultException::class.java) {
            open("correct horse", real, null)
        }
    }

    @Test
    fun keystoreWorkIsTheSameWhateverBlobsExist() {
        val real = wrap("real-pw-1")
        val duress = duress("decoy-pw-1")
        val legacy = v1Blob("real-pw-1", vk)
        val cases = listOf(
            "both" to Pair<ByteArray?, ByteArray?>(real, duress),
            "real only" to Pair<ByteArray?, ByteArray?>(real, null),
            "none" to Pair<ByteArray?, ByteArray?>(null, null),
            "legacy real" to Pair<ByteArray?, ByteArray?>(legacy, null),
        )
        for ((name, blobs) in cases) {
            device.resetCounts()
            open("anything-1", blobs.first, blobs.second).wipe()
            assertEquals("$name: key checks", 1, device.ensureCalls)
            assertEquals("$name: HMACs", 2, device.macCalls)
        }
    }

    @Test
    fun duressOutcomeWrapsTheNewVaultKeyUnderTheDecoy() {
        val real = wrap("real-pw-1")
        val duressBlob = duress("decoy-pw-1")
        val outcome = open("decoy-pw-1", real, duressBlob)
        assertTrue(outcome is PasswordVault.Outcome.Duress)
        outcome as PasswordVault.Outcome.Duress
        // The wipe deletes the device key; the new blob is bound to a fresh one.
        device.delete()
        val newVk = VaultCrypto.randomKey()
        val rebuilt = outcome.wrapNewVaultKey(newVk, device)
        assertEquals(2, rebuilt[0].toInt())
        val reopened = open("decoy-pw-1", rebuilt, null)
        assertTrue(reopened is PasswordVault.Outcome.Real)
        assertTrue((reopened as PasswordVault.Outcome.Real).vaultKey.contentEquals(newVk))
        // Anything else stays wrong, and the held material can't be used twice.
        assertTrue(open("real-pw-1", rebuilt, null) is PasswordVault.Outcome.Wrong)
        assertThrows(IllegalStateException::class.java) { outcome.wrapNewVaultKey(newVk, device) }
    }

    @Test
    fun aFreshVaultKeyRoundTripsThroughAReEnrollment() {
        // The decoy-becomes-real wipe re-wraps a brand-new VK under the decoy; prove that
        // wrap/unwrap cycle independently of the ViewModel orchestration.
        val newVk = VaultCrypto.randomKey()
        val blob = wrap("decoy-pw-1", newVk)
        val outcome = open("decoy-pw-1", blob, null)
        assertTrue(outcome is PasswordVault.Outcome.Real)
        assertTrue((outcome as PasswordVault.Outcome.Real).vaultKey.contentEquals(newVk))
    }

    @Test
    fun wipeZeroesTheRecoveredKey() {
        val outcome = open("correct horse", wrap("correct horse"), null) as PasswordVault.Outcome.Real
        outcome.wipe()
        assertTrue(outcome.vaultKey.all { it == 0.toByte() })
    }

    @Test
    fun corruptBlobsAreRejected() {
        val real = wrap("correct horse")
        val badVersion = real.copyOf().also { it[0] = 3 }
        assertThrows(PasswordVault.PasswordVaultException::class.java) { open("correct horse", badVersion, null) }
        val badWorkFactor = real.copyOf().also { it[1] = 30 }
        assertThrows(PasswordVault.PasswordVaultException::class.java) { open("correct horse", badWorkFactor, null) }
        assertThrows(PasswordVault.PasswordVaultException::class.java) {
            open("correct horse", real.copyOf(20), null)
        }
    }

    @Test
    fun newSecretsMustMeetTheMinimumLength() {
        assertNotNull(PasswordVault.secretPolicyError("12345", "pin"))
        assertNull(PasswordVault.secretPolicyError("123456", "pin"))
        assertNotNull("a PIN is digits only", PasswordVault.secretPolicyError("12345a", "pin"))
        assertNotNull(PasswordVault.secretPolicyError("", "pin"))
        assertNotNull(PasswordVault.secretPolicyError("seven77", "password"))
        assertNull(PasswordVault.secretPolicyError("eight888", "password"))
        assertNull("passwords may be anything", PasswordVault.secretPolicyError("p ss w0rd!", "password"))
    }
}
