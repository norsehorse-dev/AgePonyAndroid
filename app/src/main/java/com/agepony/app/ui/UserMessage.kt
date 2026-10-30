package com.agepony.app.ui

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.annotation.StringRes
import androidx.biometric.BiometricPrompt
import com.agepony.app.R
import com.agepony.app.security.BiometricGate
import com.agepony.app.security.BiometricGateException
import com.agepony.app.security.PasswordVault
import com.agepony.app.security.SecurityKeyService
import com.agepony.app.security.keystore.HardwareAuthBroker
import com.agepony.app.security.keystore.HardwareKeyService
import com.agepony.app.security.keystore.HardwareTagKeyService
import com.agepony.app.security.nfc.SecurityKeyTransport
import com.agepony.app.security.piv.YubiKeyBroker
import com.agepony.app.signing.FileSigner
import com.agepony.app.vault.FileEncryptorException
import com.agepony.app.vault.IdentityImportException
import com.agepony.app.vault.KekUnavailableException
import com.agepony.app.vault.NoMatchingVaultIdentityException
import com.agepony.app.vault.OwnerCheckNeededException
import com.agepony.app.vault.RecipientImportException
import com.agepony.app.vault.ScryptMemoryException
import com.agepony.app.vault.ShownMessageException
import com.agepony.app.vault.SigningOnlyKeyException
import com.agepony.app.vault.StoredKeyDamagedException
import com.agepony.app.vault.UiText
import com.agepony.app.vault.WrongPassphraseException
import com.agepony.core.Age
import com.agepony.core.AgeHeader
import com.agepony.core.AgePayload
import com.agepony.core.Armor
import com.agepony.core.Stanza
import com.agepony.core.archive.SignedBundle
import com.agepony.core.archive.TarArchive
import com.agepony.core.bech32.Bech32
import com.agepony.core.crypto.AESCBC
import com.agepony.core.crypto.AESCTR
import com.agepony.core.crypto.BcryptPBKDF
import com.agepony.core.crypto.ChaChaPoly
import com.agepony.core.crypto.Diceware
import com.agepony.core.crypto.HpkeMlkem768X25519
import com.agepony.core.crypto.RSAOAEP
import com.agepony.core.fido.Cbor
import com.agepony.core.fido.Ctap2
import com.agepony.core.piv.Piv
import com.agepony.core.portability.KeyTransfer
import com.agepony.core.portability.LanTransfer
import com.agepony.core.portability.PaperBackup
import com.agepony.core.signing.SSHSig
import com.agepony.core.signing.SSHSigner
import com.agepony.core.ssh.OpenSSHEncryptedKey
import com.agepony.core.ssh.OpenSSHPrivateKey
import com.agepony.core.ssh.OpenSSHPublicKey
import com.agepony.core.ssh.SSHMPInt
import com.agepony.core.ssh.SSHWire
import java.io.FileNotFoundException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.Locale
import java.util.concurrent.CancellationException
import javax.crypto.AEADBadTagException
import javax.net.ssl.SSLException

/**
 * One place that turns any failure the app can show into a plain sentence from resources
 * (5.1.0, UI plan U5; Android counterpart of iOS `UserMessage`). Screens never show an
 * exception's own message, `toString()` or class name. Where a code helps a report (an NFC
 * status word, a CTAP status, a Keystore or BiometricPrompt error, an HTTP status), it follows
 * the sentence in parentheses.
 *
 * Errors the app doesn't know get the caller's fallback, which names the operation ("Couldn't
 * decrypt the file."). Security failures stay failures: a header MAC, a payload tag, an AEAD
 * check, a bad signature or a refused transfer each have their own sentence, never a softer one.
 *
 * [uiText] is pure (no Android calls), so host tests check the mapping; [text] resolves it.
 */
object UserMessage {

    /** The sentence for [error], or [fallback] (naming what failed) when the app doesn't know it. */
    fun text(context: Context, error: Throwable, @StringRes fallback: Int): String =
        uiText(error, UiText.res(fallback)).resolve(context)

    /** [text], or null when the person cancelled (a prompt, a tap sheet), where screens show nothing. */
    fun textUnlessCancelled(context: Context, error: Throwable, @StringRes fallback: Int): String? =
        if (isCancellation(error)) null else text(context, error, fallback)

    /** [text] before it is resolved. */
    fun uiText(error: Throwable, fallback: UiText): UiText = known(error) ?: fallback

    /**
     * Whether [error] means the person cancelled (a system prompt, the YubiKey or NFC sheet, a
     * coroutine). Screens usually show nothing for these.
     */
    fun isCancellation(error: Throwable): Boolean {
        var t: Throwable? = error
        var depth = 0
        while (t != null && depth < MAX_DEPTH) {
            when (t) {
                is CancellationException, is YubiKeyBroker.YubiKeyCancelled -> return true
                is BiometricGateException -> return BiometricGate.isCancelCode(t.code)
                is HardwareAuthBroker.AuthCancelled ->
                    if (t.reason == HardwareAuthBroker.AuthCancelled.Reason.CANCELLED) return true
            }
            t = t.cause
            depth++
        }
        return false
    }

    /** The Android Keystore's numeric error code in [error] or its causes (API 33+), or null. */
    fun keystoreCode(error: Throwable): Int? = runCatching {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return@runCatching null
        var t: Throwable? = error
        var depth = 0
        while (t != null && depth < MAX_DEPTH) {
            keystoreCode33(t)?.let { return@runCatching it }
            t = t.cause
            depth++
        }
        null
    }.getOrNull()

    private const val MAX_DEPTH = 6

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun keystoreCode33(t: Throwable): Int? = (t as? android.security.KeyStoreException)?.numericErrorCode

    private fun res(@StringRes id: Int, vararg args: Any): UiText = UiText.res(id, *args)

    private fun hex4(sw: Int): String = String.format(Locale.ROOT, "%04X", sw and 0xFFFF)

    private fun hex2(code: Int): String = String.format(Locale.ROOT, "0x%02X", code and 0xFF)

    /** The message for [error], else for the first cause the app knows, else null. */
    private fun known(error: Throwable): UiText? {
        var t: Throwable? = error
        var depth = 0
        while (t != null && depth < MAX_DEPTH) {
            direct(t)?.let { return it }
            t = t.cause
            depth++
        }
        return null
    }

    @Suppress("CyclomaticComplexMethod")
    private fun direct(e: Throwable): UiText? = when (e) {
        // Already a finished sentence from resources.
        is ShownMessageException -> res(R.string.error_passthrough, e.shown)
        is OwnerCheckNeededException -> res(R.string.core_owner_check_needed)

        // Encrypt and decrypt
        is FileEncryptorException -> fileEncryptor(e)
        is NoMatchingVaultIdentityException -> res(R.string.error_no_matching_identity)
        is WrongPassphraseException -> res(R.string.error_wrong_passphrase)
        is ScryptMemoryException ->
            if (e.whileDecrypting) {
                res(R.string.error_scrypt_memory_decrypt, e.needed shr 20, e.available shr 20)
            } else {
                res(R.string.error_scrypt_memory_encrypt, e.workFactor, e.needed shr 20, e.available shr 20)
            }

        // Vault and stored keys
        is KekUnavailableException -> res(R.string.error_vault_key_missing)
        is PasswordVault.PasswordVaultException ->
            if (e.deviceKeyMissing) res(R.string.error_password_device_key_missing) else res(R.string.error_password_data_damaged)
        is SigningOnlyKeyException -> res(R.string.error_signing_only_key)
        is StoredKeyDamagedException -> res(R.string.error_stored_key_damaged)

        // Imports
        is IdentityImportException -> when (e.kind) {
            IdentityImportException.Kind.PASSPHRASE_REQUIRED -> res(R.string.error_import_passphrase_required)
            IdentityImportException.Kind.WRONG_PASSPHRASE -> res(R.string.error_import_wrong_passphrase)
            IdentityImportException.Kind.UNSUPPORTED -> res(R.string.error_import_unsupported)
            IdentityImportException.Kind.MALFORMED -> res(R.string.error_import_malformed)
        }
        is RecipientImportException -> recipientImport(e)

        // Signing
        is FileSigner.FileSignerException -> when (e.reason) {
            FileSigner.FileSignerException.Reason.X25519_CANNOT_SIGN -> res(R.string.error_sign_x25519)
            FileSigner.FileSignerException.Reason.QUANTUM_SAFE_CANNOT_SIGN -> res(R.string.error_sign_quantum_safe)
            FileSigner.FileSignerException.Reason.DECRYPT_ONLY_KEY -> res(R.string.error_sign_decrypt_only)
            FileSigner.FileSignerException.Reason.SECURITY_KEY_NOT_HERE -> res(R.string.error_sign_security_key_here)
            FileSigner.FileSignerException.Reason.KEY_DAMAGED -> res(R.string.error_sign_key_damaged)
        }

        // Biometrics, screen lock, Keystore
        is BiometricGateException -> biometric(e.code)
        is HardwareAuthBroker.AuthCancelled -> when (e.reason) {
            HardwareAuthBroker.AuthCancelled.Reason.APP_NOT_OPEN -> res(R.string.error_hardware_app_not_open)
            HardwareAuthBroker.AuthCancelled.Reason.CANCELLED -> res(R.string.error_cancelled)
            HardwareAuthBroker.AuthCancelled.Reason.TIMED_OUT -> res(R.string.error_auth_timed_out)
            // The prompt's own error, by its code, when it had one.
            HardwareAuthBroker.AuthCancelled.Reason.FAILED ->
                e.cause?.let { direct(it) } ?: res(R.string.error_auth_failed)
        }
        is android.security.keystore.KeyPermanentlyInvalidatedException -> res(R.string.error_key_invalidated)
        is android.security.keystore.UserNotAuthenticatedException -> res(R.string.error_not_authenticated)
        is HardwareKeyService.HardwareKeyException ->
            keystoreCode(e)?.let { res(R.string.error_keystore_code, it) } ?: res(R.string.error_hardware_sign_failed)
        is HardwareTagKeyService.HardwareTagException -> when {
            e.keyGone -> res(R.string.error_hardware_key_gone)
            else -> keystoreCode(e)?.let { res(R.string.error_keystore_code, it) } ?: res(R.string.error_hardware_decrypt_failed)
        }

        // Security keys over NFC
        is SecurityKeyService.PinRequiredException -> res(R.string.error_sk_pin_required)
        is SecurityKeyService.WrongPinException -> res(R.string.error_sk_wrong_pin)
        is SecurityKeyService.SecurityKeyException -> when (e.reason) {
            SecurityKeyService.SecurityKeyException.Reason.NO_PIN_SET -> res(R.string.error_sk_no_pin_set)
            SecurityKeyService.SecurityKeyException.Reason.KEY_ERROR -> ctap(e.ctapCode ?: -1)
            SecurityKeyService.SecurityKeyException.Reason.BAD_ANSWER -> res(R.string.error_sk_bad_answer)
        }
        is Ctap2.CtapError -> ctap(e.code)
        is Cbor.CborException -> res(R.string.error_sk_bad_answer)
        is SecurityKeyTransport.NfcException -> nfc(e)
        is android.nfc.TagLostException -> res(R.string.error_nfc_lost)

        // YubiKey (PIV)
        is YubiKeyBroker.YubiKeyCancelled -> res(R.string.error_cancelled)
        is Piv.PinRequiredException -> res(R.string.error_piv_pin_required)
        is Piv.WrongPinException ->
            if (e.retriesLeft <= 0) res(R.string.error_piv_pin_blocked)
            else UiText.plural(R.plurals.error_piv_wrong_pin, e.retriesLeft, e.retriesLeft)
        is Piv.PivException -> piv(e)

        // age format
        is Age.NoMatchingIdentityException -> res(R.string.error_no_matching_identity)
        is Age.MismatchedRecipientLabelsException -> res(R.string.error_mismatched_labels)
        is AgeHeader.HeaderException -> when (e.reason) {
            AgeHeader.HeaderException.Reason.NOT_AGE -> res(R.string.error_not_age_file)
            AgeHeader.HeaderException.Reason.TOO_LARGE -> res(R.string.error_header_too_large)
            AgeHeader.HeaderException.Reason.MAC_FAILED -> res(R.string.error_header_mac)
            AgeHeader.HeaderException.Reason.SCRYPT_NOT_ALONE -> res(R.string.error_header_scrypt_not_alone)
            AgeHeader.HeaderException.Reason.TRUNCATED -> res(R.string.error_file_truncated)
            AgeHeader.HeaderException.Reason.DAMAGED -> res(R.string.error_header_damaged)
        }
        is AgePayload.PayloadException -> when (e.reason) {
            AgePayload.PayloadException.Reason.AUTH_FAILED -> res(R.string.error_payload_auth)
            AgePayload.PayloadException.Reason.DAMAGED -> res(R.string.error_payload_damaged)
        }
        is Armor.ArmorException -> res(R.string.error_armor_damaged)
        is Stanza.Companion.StanzaException -> res(R.string.error_header_damaged)
        is Bech32.Bech32Exception -> res(R.string.error_bech32)
        is ChaChaPoly.AeadException, is AEADBadTagException -> res(R.string.error_integrity)
        is HpkeMlkem768X25519.LowOrderPointException -> res(R.string.error_low_order)
        is RSAOAEP.RSAOAEPException -> res(R.string.error_rsa_unwrap)
        is Diceware.DicewareException -> res(R.string.error_diceware)

        // SSH keys and signatures
        is OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException,
        is OpenSSHPublicKey.Companion.OpenSSHPublicKeyException,
        is OpenSSHEncryptedKey.OpenSSHEncryptedKeyException,
        is SSHMPInt.SSHMPIntException,
        is SSHWire.SSHWireException -> res(R.string.error_ssh_key_damaged)
        is AESCTR.AESCTRException, is AESCBC.AESCBCException -> res(R.string.error_ssh_key_decrypt)
        is BcryptPBKDF.BcryptPBKDFException -> res(R.string.error_ssh_kdf)
        is SSHSig.SSHSigFormatException -> res(R.string.sign_reason_malformed)
        is SSHSigner.SSHSignerException -> res(R.string.error_sign_failed)
        is SignedBundle.BundleException -> res(R.string.error_bundle_damaged)
        is TarArchive.TarException -> res(R.string.error_tar_damaged)

        // Moving keys
        is KeyTransfer.TransferException -> when (e.reason) {
            KeyTransfer.TransferException.Reason.NOT_A_TRANSFER -> res(R.string.error_transfer_not_transfer)
            KeyTransfer.TransferException.Reason.TOO_MANY_ENTRIES -> res(R.string.error_transfer_too_many)
            KeyTransfer.TransferException.Reason.UNSUPPORTED_FORMAT -> res(R.string.error_transfer_newer)
            KeyTransfer.TransferException.Reason.WRONG_SESSION -> res(R.string.error_transfer_wrong_session)
            KeyTransfer.TransferException.Reason.NOT_A_RECIPIENT -> res(R.string.error_transfer_not_recipient)
        }
        is LanTransfer.LanTransferException -> when (e.reason) {
            LanTransfer.LanTransferException.Reason.NOT_AN_INVITE -> res(R.string.error_lan_not_invite)
            LanTransfer.LanTransferException.Reason.DAMAGED_INVITE -> res(R.string.error_lan_damaged_invite)
            LanTransfer.LanTransferException.Reason.PROTOCOL -> res(R.string.error_lan_protocol)
            LanTransfer.LanTransferException.Reason.WRONG_TOKEN -> res(R.string.error_lan_wrong_token)
            LanTransfer.LanTransferException.Reason.TOO_LARGE -> res(R.string.error_lan_too_large)
            LanTransfer.LanTransferException.Reason.CLOSED -> res(R.string.error_lan_closed)
            LanTransfer.LanTransferException.Reason.REFUSED -> res(R.string.error_lan_refused)
            LanTransfer.LanTransferException.Reason.UNREACHABLE -> res(R.string.error_lan_unreachable)
        }
        is PaperBackup.PaperBackupException -> when (e.reason) {
            PaperBackup.PaperBackupException.Reason.NOT_SEALED -> res(R.string.error_paper_not_sealed)
            PaperBackup.PaperBackupException.Reason.DAMAGED -> res(R.string.error_paper_damaged)
            PaperBackup.PaperBackupException.Reason.WRONG_PASSPHRASE -> res(R.string.error_paper_wrong_passphrase)
        }

        // System
        is OutOfMemoryError -> res(R.string.error_out_of_memory)
        is CancellationException -> res(R.string.error_cancelled)
        is FileNotFoundException -> res(R.string.error_file_missing)
        is SecurityException -> res(R.string.error_file_permission)
        is UnknownHostException -> res(R.string.error_network_offline)
        is SocketTimeoutException -> res(R.string.error_network_timeout)
        is ConnectException -> res(R.string.error_network_connect)
        is SSLException -> res(R.string.error_network_tls)
        is android.system.ErrnoException -> if (e.errno == ENOSPC) res(R.string.error_no_space) else null
        else -> keystoreCode(e)?.let { res(R.string.error_keystore_code, it) }
    }

    private const val ERROR_SECURITY_UPDATE_REQUIRED = 15

    /** Linux ENOSPC; a literal so the mapping stays free of Android calls. */
    private const val ENOSPC = 28

    private fun fileEncryptor(e: FileEncryptorException): UiText = when (e.reason) {
        FileEncryptorException.Reason.NO_RECIPIENTS -> res(R.string.error_no_recipients)
        FileEncryptorException.Reason.PASSPHRASE_WITH_RECIPIENTS -> res(R.string.error_passphrase_with_recipients)
        // The core error underneath says what really failed (a MAC, a tag, a cut-off file).
        FileEncryptorException.Reason.ENCRYPT_FAILED -> e.cause?.let { known(it) } ?: res(R.string.error_encrypt_failed)
        FileEncryptorException.Reason.DECRYPT_FAILED -> e.cause?.let { known(it) } ?: res(R.string.error_decrypt_failed)
        FileEncryptorException.Reason.ARMOR_UNREADABLE -> res(R.string.error_armor_damaged)
    }

    private fun recipientImport(e: RecipientImportException): UiText = when (e.reason) {
        RecipientImportException.Reason.EMPTY -> res(R.string.error_recipient_empty)
        RecipientImportException.Reason.BAD_QUANTUM_SAFE -> res(R.string.error_recipient_bad_quantum_safe)
        RecipientImportException.Reason.BAD_HARDWARE_TAG -> res(R.string.error_recipient_bad_tag)
        RecipientImportException.Reason.BAD_YUBIKEY -> res(R.string.error_recipient_bad_yubikey)
        RecipientImportException.Reason.BAD_AGE -> res(R.string.error_recipient_bad_age)
        RecipientImportException.Reason.BAD_SSH -> res(R.string.error_recipient_bad_ssh)
        RecipientImportException.Reason.BAD_SSH_ED25519 -> res(R.string.error_recipient_bad_ssh_ed25519)
        RecipientImportException.Reason.UNRECOGNIZED -> res(R.string.error_recipient_unrecognized)
        RecipientImportException.Reason.INVALID_USERNAME -> res(R.string.error_github_username)
        RecipientImportException.Reason.NO_KEYS -> res(R.string.error_github_no_keys, e.subject.orEmpty())
        RecipientImportException.Reason.NO_USABLE_KEYS -> res(R.string.error_github_no_usable_keys, e.subject.orEmpty())
        RecipientImportException.Reason.HTTP_ERROR ->
            if (e.httpStatus == 404 && e.subject != null) res(R.string.error_github_no_user, e.subject)
            else res(R.string.error_github_http, e.httpStatus)
        RecipientImportException.Reason.EMPTY_RESPONSE -> res(R.string.error_github_empty)
        RecipientImportException.Reason.NETWORK -> when (e.cause) {
            is UnknownHostException -> res(R.string.error_network_offline)
            is SocketTimeoutException -> res(R.string.error_network_timeout)
            is SSLException -> res(R.string.error_network_tls)
            else -> res(R.string.error_github_network)
        }
        RecipientImportException.Reason.TOO_LARGE -> res(R.string.error_github_too_large)
    }

    private fun biometric(code: Int): UiText = when {
        code == BiometricGate.CODE_ENROLMENT_CHANGED -> res(R.string.security_biometric_changed)
        code == BiometricGate.CODE_UNAVAILABLE -> res(R.string.security_biometric_unavailable)
        code == BiometricGate.CODE_NO_RESULT -> res(R.string.error_auth_no_result)
        BiometricGate.isCancelCode(code) -> res(R.string.error_cancelled)
        code == BiometricPrompt.ERROR_LOCKOUT -> res(R.string.error_biometric_lockout)
        code == BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> res(R.string.error_biometric_lockout_permanent)
        code == BiometricPrompt.ERROR_NO_BIOMETRICS -> res(R.string.error_biometric_none_enrolled)
        code == BiometricPrompt.ERROR_HW_UNAVAILABLE || code == BiometricPrompt.ERROR_HW_NOT_PRESENT ->
            res(R.string.error_biometric_hardware)
        code == BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> res(R.string.error_no_screen_lock)
        code == BiometricPrompt.ERROR_TIMEOUT -> res(R.string.error_auth_timed_out)
        // BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED, written out so it builds on any biometric version.
        code == ERROR_SECURITY_UPDATE_REQUIRED -> res(R.string.error_security_update)
        else -> res(R.string.error_auth_failed_code, code)
    }

    /** CTAP2 status bytes (FIDO CTAP 2.1, section 8.2). */
    private fun ctap(code: Int): UiText = when (code) {
        0x27 -> res(R.string.error_sk_denied)
        0x2E -> res(R.string.error_sk_no_credential)
        0x2F -> res(R.string.error_sk_touch_timeout)
        0x31 -> res(R.string.error_sk_wrong_pin)
        0x32 -> res(R.string.error_sk_pin_blocked)
        0x34 -> res(R.string.error_sk_pin_auth_blocked)
        0x35 -> res(R.string.error_sk_no_pin_set)
        0x36 -> res(R.string.error_sk_pin_required)
        -1 -> res(R.string.error_sk_bad_answer)
        else -> res(R.string.error_sk_code, hex2(code))
    }

    private fun nfc(e: SecurityKeyTransport.NfcException): UiText = when (e.reason) {
        SecurityKeyTransport.NfcException.Reason.NO_NFC -> res(R.string.error_nfc_missing)
        SecurityKeyTransport.NfcException.Reason.NFC_OFF -> res(R.string.error_nfc_off)
        SecurityKeyTransport.NfcException.Reason.NOT_ISO_DEP -> res(R.string.error_nfc_not_security_key)
        SecurityKeyTransport.NfcException.Reason.READER_FAILED -> res(R.string.error_nfc_reader)
        SecurityKeyTransport.NfcException.Reason.COMMUNICATION -> res(R.string.error_nfc_lost)
        SecurityKeyTransport.NfcException.Reason.SELECT_FAILED -> res(R.string.error_nfc_no_fido, hex4(e.sw))
        SecurityKeyTransport.NfcException.Reason.TOO_LARGE,
        SecurityKeyTransport.NfcException.Reason.CHAINING -> res(R.string.error_nfc_bad_answer)
        SecurityKeyTransport.NfcException.Reason.TIMED_OUT -> res(R.string.error_nfc_timeout)
        SecurityKeyTransport.NfcException.Reason.TRANSPORT ->
            if (e.sw != 0) res(R.string.error_nfc_status, hex4(e.sw)) else res(R.string.error_nfc_bad_answer)
        SecurityKeyTransport.NfcException.Reason.HOLD_AGAIN -> res(R.string.core_nfc_hold_key_again)
    }

    private fun piv(e: Piv.PivException): UiText = when (e.reason) {
        Piv.PivException.Reason.NOT_PIV -> res(R.string.error_piv_not_piv, hex4(e.sw))
        Piv.PivException.Reason.PIN_CHECK_FAILED -> res(R.string.error_piv_pin_check, hex4(e.sw))
        Piv.PivException.Reason.NO_KEY_IN_SLOT ->
            if (e.sw != 0) res(R.string.error_piv_no_key_code, hex4(e.sw)) else res(R.string.error_piv_no_key)
        Piv.PivException.Reason.NOT_P256 -> res(R.string.error_piv_not_p256)
        Piv.PivException.Reason.REFUSED -> res(R.string.error_piv_refused, hex4(e.sw))
        Piv.PivException.Reason.MALFORMED -> res(R.string.error_piv_bad_answer)
        Piv.PivException.Reason.KEY_MISMATCH -> res(R.string.error_piv_key_mismatch)
        Piv.PivException.Reason.WRONG_YUBIKEY ->
            res(R.string.error_piv_wrong_yubikey, e.foundSerial?.toString().orEmpty(), e.expectedSerial?.toString().orEmpty())
        Piv.PivException.Reason.APP_NOT_OPEN -> res(R.string.error_piv_app_not_open)
        Piv.PivException.Reason.NO_NFC -> res(R.string.error_nfc_missing)
        Piv.PivException.Reason.NFC_OFF -> res(R.string.error_nfc_off)
        Piv.PivException.Reason.READER_FAILED -> res(R.string.error_nfc_reader)
        Piv.PivException.Reason.NOT_A_SMART_CARD -> res(R.string.error_piv_not_smart_card)
        Piv.PivException.Reason.MOVED_AWAY -> res(R.string.error_piv_moved_away)
        Piv.PivException.Reason.HOLD_AGAIN -> res(R.string.core_yubikey_hold_again)
    }
}
