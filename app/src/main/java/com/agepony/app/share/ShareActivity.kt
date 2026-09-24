package com.agepony.app.share

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.fragment.app.FragmentActivity
import com.agepony.app.installWindowProtection
import com.agepony.app.security.ClipboardGuard
import com.agepony.app.security.keystore.HardwareAuthBroker
import com.agepony.app.security.piv.YubiKeyBroker
import com.agepony.app.ui.security.YubiKeyPromptHost
import com.agepony.app.ui.VaultGate
import com.agepony.app.ui.passphrase.PassphraseOnlyScreen
import com.agepony.app.ui.theme.AgePonyTheme
import com.agepony.app.vault.VaultViewModel

/**
 * Entry point for the share sheet (ACTION_SEND / ACTION_SEND_MULTIPLE) and the text-selection
 * menu (ACTION_PROCESS_TEXT).
 *
 * It runs inside the sending app's task, so finishing returns the user to where they shared from.
 * The vault gate applies as usual: a share into a locked AgePony shows the lock screen first and
 * then carries on with the shared content. Input is streamed from the sender's URIs or held in
 * memory; nothing is copied into AgePony's storage.
 */
class ShareActivity : FragmentActivity() {

    private val vaultViewModel: VaultViewModel by viewModels()

    override fun onResume() {
        super.onResume()
        HardwareAuthBroker.attach(this)
        YubiKeyBroker.attach(this)
    }

    override fun onPause() {
        HardwareAuthBroker.detach(this)
        YubiKeyBroker.detach(this)
        super.onPause()
    }

    override fun onStart() {
        super.onStart()
        ClipboardGuard.onForeground(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Drop URIs AgePony must not read on another app's behalf (audit L-20): anything left
        // with nothing actionable finishes, as before.
        val parsed = SharePayload.from(intent)?.let { SharePayload.restrictTo(it, packageName) }
        if (parsed == null) {
            finish()
            return
        }
        // A replacement only reaches the other app if it started us for a result. Some apps set
        // the read-only flag correctly but still don't wait for one, so check both.
        val payload = if (parsed is SharePayload.Text && parsed.canReplace && callingActivity == null) {
            parsed.copy(canReplace = false)
        } else {
            parsed
        }
        // This activity sits in the sender's task, so its Recents card would show plaintext
        // without FLAG_SECURE (audit M-5).
        installWindowProtection(vaultViewModel.vault)
        enableEdgeToEdge()
        setContent {
            AgePonyTheme {
                VaultGate(
                    vaultViewModel,
                    passphraseOnlyContent = { close ->
                        PassphraseOnlyScreen(
                            vault = vaultViewModel.vault,
                            onClose = close,
                            initialText = (payload as? SharePayload.Text)?.text,
                            initialFile = (payload as? SharePayload.Files)?.uris?.singleOrNull(),
                        )
                    },
                ) {
                    ShareScreen(
                        vault = vaultViewModel.vault,
                        payload = payload,
                        onReplaceText = { replacement -> finishWithReplacement(replacement) },
                        onDone = { finish() },
                    )
                }
                YubiKeyPromptHost()
            }
        }
    }

    private fun finishWithReplacement(text: String) {
        setResult(RESULT_OK, Intent().putExtra(Intent.EXTRA_PROCESS_TEXT, text))
        finish()
    }
}
