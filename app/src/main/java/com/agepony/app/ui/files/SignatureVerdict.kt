package com.agepony.app.ui.files

import android.content.Context
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import com.agepony.app.signing.FileVerifier
import com.agepony.app.ui.components.StatusText
import com.agepony.app.ui.components.VerdictPanel
import com.agepony.app.ui.theme.AgeStatus
import com.agepony.app.vault.TextDecryptor

//
// The signature verdict shown after a decrypt, shared by the Files decrypt flow and Text decrypt
// (5.1.0, iOS L-1, L-3). Color and icon come from the kind, never from the text. A failed
// signature also changes the headline above the result, so a forged file never sits under a
// plain green "Decrypted".
//

/** What a signature check found. The UI picks color and icon from [kind], never from the text. */
internal enum class VerdictKind { TRUSTED, UNKNOWN_SIGNER, NOT_TRUSTED, FAILED }

internal class SignatureVerdict(val kind: VerdictKind, val text: String)

internal fun verdictFor(context: Context, result: FileVerifier.Result): SignatureVerdict =
    when (result.trust) {
        FileVerifier.Trust.TRUSTED -> {
            val name = result.signerName
            SignatureVerdict(
                VerdictKind.TRUSTED,
                if (name != null) {
                    context.getString(R.string.files_decrypt_signed_by, name)
                } else {
                    context.getString(R.string.files_decrypt_signed_by_known)
                },
            )
        }
        FileVerifier.Trust.VALID_UNKNOWN -> {
            val listed = result.untrustedSignerName
            if (listed != null) {
                val reason = result.untrustedReason
                SignatureVerdict(
                    VerdictKind.NOT_TRUSTED,
                    if (reason != null) {
                        context.getString(R.string.files_decrypt_not_trusted, listed, reason.resolve(context))
                    } else {
                        context.getString(R.string.files_decrypt_not_trusted_default, listed)
                    },
                )
            } else {
                SignatureVerdict(VerdictKind.UNKNOWN_SIGNER, context.getString(R.string.files_decrypt_valid_unknown))
            }
        }
        FileVerifier.Trust.INVALID -> {
            val reason = result.reason
            SignatureVerdict(
                VerdictKind.FAILED,
                if (reason != null) {
                    context.getString(R.string.files_decrypt_invalid, reason.resolve(context))
                } else {
                    context.getString(R.string.files_decrypt_invalid_default)
                },
            )
        }
    }

/** The verdict for a signature found in decrypted text (L-1), worded as the file flow words it. */
internal fun textVerdict(context: Context, check: TextDecryptor.SignatureCheck): SignatureVerdict =
    when (check) {
        is TextDecryptor.SignatureCheck.Checked -> verdictFor(context, check.result)
        is TextDecryptor.SignatureCheck.Unreadable ->
            SignatureVerdict(VerdictKind.FAILED, context.getString(R.string.files_decrypt_unreadable))
        TextDecryptor.SignatureCheck.DamagedBundle ->
            SignatureVerdict(VerdictKind.FAILED, context.getString(R.string.text_bundle_damaged))
    }

/** What an older (v1) signature in decrypted text does not cover, or null. */
internal fun textVerdictNote(context: Context, check: TextDecryptor.SignatureCheck): String? =
    when ((check as? TextDecryptor.SignatureCheck.Checked)?.olderFormat) {
        TextDecryptor.OlderFormat.STANZA_V1 -> context.getString(R.string.files_decrypt_v1_stanza_note)
        TextDecryptor.OlderFormat.BUNDLE_V1 -> context.getString(R.string.files_decrypt_v1_bundle_note)
        null -> null
    }

/** The verdict as a bordered panel: status color on the icon and title only. */
@Composable
internal fun SignatureVerdictPanel(verdict: SignatureVerdict, modifier: Modifier = Modifier) {
    val (title, color, icon) = when (verdict.kind) {
        VerdictKind.TRUSTED -> Triple(
            stringResource(R.string.decrypt_verdict_trusted),
            AgeStatus.colors.success,
            Icons.Filled.CheckCircle,
        )
        VerdictKind.UNKNOWN_SIGNER -> Triple(
            stringResource(R.string.decrypt_verdict_unknown),
            MaterialTheme.colorScheme.onSurfaceVariant,
            Icons.Filled.Info,
        )
        VerdictKind.NOT_TRUSTED -> Triple(
            stringResource(R.string.decrypt_verdict_untrusted),
            AgeStatus.colors.warning,
            Icons.Filled.Warning,
        )
        VerdictKind.FAILED -> Triple(
            stringResource(R.string.decrypt_verdict_failed),
            AgeStatus.colors.failure,
            Icons.Filled.Warning,
        )
    }
    VerdictPanel(title = title, detail = verdict.text, color = color, icon = icon, modifier = modifier)
}

/**
 * The headline over a decrypted result: "Decrypted" in the success color, or "Decrypted,
 * signature failed" in the failure color when the signature failed (5.1.0, iOS L-3).
 */
@Composable
internal fun DecryptedHeadline(signatureFailed: Boolean, modifier: Modifier = Modifier) {
    if (signatureFailed) {
        StatusText(
            text = stringResource(R.string.files_decrypt_done_signature_failed),
            color = AgeStatus.colors.failure,
            icon = Icons.Filled.Warning,
            modifier = modifier,
        )
    } else {
        StatusText(
            text = stringResource(R.string.files_decrypt_done),
            color = AgeStatus.colors.success,
            icon = Icons.Filled.CheckCircle,
            modifier = modifier,
        )
    }
}
