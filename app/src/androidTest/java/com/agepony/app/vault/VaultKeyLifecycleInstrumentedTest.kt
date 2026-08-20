package com.agepony.app.vault

import android.content.Context
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Regression test for the password/device-credential lockout (issue #9): a
 * BAD_DECRYPT on vault.dat after the first re-unlock.
 *
 * The bootstrap callers (bootstrapWithPassword, bootstrapWithDeviceCredential,
 * performDuressWipe) wipe their transient VK buffer with vk.fill(0) right after
 * calling vault.bootstrap(vk). Vault.bootstrap used to store that array by
 * reference, so the wipe zeroed the vault's own live key. The first persist()
 * after that (adding an identity) then sealed vault.dat under an all-zero key,
 * and the next unlock — which recovers the real VK from vault.key.pw — failed
 * GCM tag verification. Vault.bootstrap/unlock now copy the incoming key.
 *
 * This exercises the exact sequence with a real Context, so it fails (unlock
 * throws AEADBadTagException) on the pre-fix code and passes on the fixed code.
 */
@RunWith(AndroidJUnit4::class)
class VaultKeyLifecycleInstrumentedTest {

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun clean() {
        Vault(context).reset()
    }

    @After
    fun cleanup() {
        Vault(context).reset()
    }

    @Test
    fun vaultDataSurvivesCallerWipingItsKeyBufferAfterBootstrap() {
        val vault = Vault(context)

        // The real VK, and the copy the password blob would independently hold.
        val vk = VaultCrypto.randomKey()
        val recoveredVk = vk.copyOf()

        // Bootstrap, then wipe the caller's buffer exactly as the real bootstrap
        // paths do. Pre-fix this zeroed the vault's live key.
        vault.bootstrap(vk)
        vk.fill(0)

        // The identity created right after setup: this persist() is where the
        // pre-fix bug sealed vault.dat under the zeroed key.
        val identity = StoredIdentity(
            id = "issue9-regression",
            name = "Regression",
            type = StoredIdentityType.X25519,
            publicKeyB64 = Base64.encodeToString(ByteArray(32) { 1 }, Base64.NO_WRAP),
            privateKeyB64 = Base64.encodeToString(ByteArray(32) { 2 }, Base64.NO_WRAP),
            createdAt = 0L,
        )
        vault.addIdentity(identity)

        // Lock (drops the in-memory VK) and re-open from disk with a fresh Vault,
        // unlocking with the independently-held real VK — the app's re-unlock path.
        vault.lock()

        val reopened = Vault(context)
        reopened.unlock(recoveredVk) // pre-fix: throws AEADBadTagException (BAD_DECRYPT)

        assertTrue("vault should be unlocked after re-open", reopened.isUnlocked)
        assertEquals(1, reopened.identities.size)
        assertEquals("issue9-regression", reopened.identities.first().id)
    }
}
