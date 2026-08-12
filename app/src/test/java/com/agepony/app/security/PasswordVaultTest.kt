package com.agepony.app.security

import com.agepony.app.vault.VaultCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The crypto-level half of the duress acceptance criteria (plan B4). The three that
 * matter here — real unlocks, decoy is detected, nothing but the exact decoy triggers —
 * are provable without a device. The remaining two (post-wipe screen is state-identical
 * to a wrong password, and the statistical timing test) are on-device checks and live in
 * AgePony_4.0.0_DeviceTests.md.
 *
 * JUnit 4, matching the rest of the app module's unit tests. Uses the real scrypt KDF
 * (Bouncy Castle) and real AES-GCM, so these are slow by unit standards — a handful of
 * 2^15 scrypt runs — but they exercise the shipping path, not a stub.
 */
class PasswordVaultTest {

    private val vk = VaultCrypto.randomKey()

    @Test
    fun realSecretUnlocksAndReturnsTheVaultKey() {
        val real = PasswordVault.wrapVaultKey("correct horse".toCharArray(), vk)
        val outcome = PasswordVault.tryUnlock("correct horse".toCharArray(), real, null)
        assertTrue(outcome is PasswordVault.Outcome.Real)
        assertTrue((outcome as PasswordVault.Outcome.Real).vaultKey.contentEquals(vk))
    }

    @Test
    fun decoySecretIsReportedAsDuress() {
        val real = PasswordVault.wrapVaultKey("real-pw".toCharArray(), vk)
        val duress = PasswordVault.duressBlob("decoy-pw".toCharArray())
        assertTrue(
            PasswordVault.tryUnlock("decoy-pw".toCharArray(), real, duress)
                is PasswordVault.Outcome.Duress
        )
    }

    @Test
    fun realBeatsDuressWhenBothArePresent() {
        // Enrollment forbids this collision, but the resolution order is pinned anyway.
        val real = PasswordVault.wrapVaultKey("shared".toCharArray(), vk)
        val duress = PasswordVault.duressBlob("shared".toCharArray())
        assertTrue(
            PasswordVault.tryUnlock("shared".toCharArray(), real, duress)
                is PasswordVault.Outcome.Real
        )
    }

    @Test
    fun wrongSecretIsWrong_notDuress() {
        val real = PasswordVault.wrapVaultKey("real-pw".toCharArray(), vk)
        val duress = PasswordVault.duressBlob("decoy-pw".toCharArray())
        assertTrue(
            PasswordVault.tryUnlock("neither".toCharArray(), real, duress)
                is PasswordVault.Outcome.Wrong
        )
    }

    @Test
    fun nothingButTheExactDecoyTriggersTheWipe() {
        val real = PasswordVault.wrapVaultKey("real-pw".toCharArray(), vk)
        val duress = PasswordVault.duressBlob("decoy-pw".toCharArray())
        // A prefix, a suffix, and a case change must all be plain-wrong.
        for (near in listOf("decoy-p", "decoy-pw ", "Decoy-pw", "ecoy-pw")) {
            assertTrue(
                "near-miss \"$near\" must not trigger duress",
                PasswordVault.tryUnlock(near.toCharArray(), real, duress)
                    is PasswordVault.Outcome.Wrong
            )
        }
    }

    @Test
    fun removingTheDecoyMakesItAnOrdinaryWrongPassword() {
        val real = PasswordVault.wrapVaultKey("real-pw".toCharArray(), vk)
        assertTrue(
            PasswordVault.tryUnlock("decoy-pw".toCharArray(), real, null)
                is PasswordVault.Outcome.Wrong
        )
    }

    @Test
    fun blobsAreVersionedAndDistinct() {
        val real = PasswordVault.wrapVaultKey("pw".toCharArray(), vk)
        val duress = PasswordVault.duressBlob("pw".toCharArray())
        assertEquals(1, real[0].toInt())
        assertEquals(1, duress[0].toInt())
        assertFalse("salts differ, so blobs differ", real.contentEquals(duress))
    }

    @Test
    fun aFreshVaultKeyRoundTripsThroughAReEnrollment() {
        // The decoy-becomes-real wipe re-wraps a brand-new VK under the decoy; prove that
        // wrap/unwrap cycle independently of the ViewModel orchestration.
        val newVk = VaultCrypto.randomKey()
        val blob = PasswordVault.wrapVaultKey("decoy-pw".toCharArray(), newVk)
        val outcome = PasswordVault.tryUnlock("decoy-pw".toCharArray(), blob, null)
        assertTrue(outcome is PasswordVault.Outcome.Real)
        assertTrue((outcome as PasswordVault.Outcome.Real).vaultKey.contentEquals(newVk))
    }
}
