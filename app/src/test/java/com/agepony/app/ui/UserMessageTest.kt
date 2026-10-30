package com.agepony.app.ui

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
import com.agepony.app.vault.StoredIdentityType
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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.FileNotFoundException
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.CancellationException
import javax.crypto.AEADBadTagException
import javax.net.ssl.SSLException

/**
 * The error mapper (5.1.0, UI plan U5): every failure the app throws maps to a sentence from
 * resources, and no output ever carries the exception's own message or class name. Runs on the
 * host: the mapping is pure and resolved to text only on screen.
 */
class UserMessageTest {

    /** Text an exception's message is built from in these tests; it must never reach the output. */
    private val raw = "RAW-INTERNAL-DETAIL"

    private val fallback = UiText.res(R.string.files_decrypt_failed)

    private fun everyException(): List<Throwable> = buildList {
        // Encrypt and decrypt
        FileEncryptorException.Reason.entries.forEach { add(FileEncryptorException(it, IllegalStateException(raw))) }
        add(NoMatchingVaultIdentityException())
        add(WrongPassphraseException())
        add(ScryptMemoryException(20, 1L shl 30, 200L shl 20, whileDecrypting = true))
        add(ScryptMemoryException(18, 256L shl 20, 100L shl 20))

        // Vault and stored keys
        add(KekUnavailableException(raw))
        add(PasswordVault.PasswordVaultException(raw))
        add(PasswordVault.PasswordVaultException(raw, deviceKeyMissing = true))
        add(SigningOnlyKeyException(StoredIdentityType.HARDWARE_KEY))
        add(StoredKeyDamagedException(raw))
        add(OwnerCheckNeededException(raw))

        // Imports
        IdentityImportException.Kind.entries.forEach { add(IdentityImportException(it, raw)) }
        RecipientImportException.Reason.entries.forEach {
            add(RecipientImportException(it, subject = "octocat", httpStatus = 500, cause = IOException(raw)))
        }
        add(RecipientImportException(RecipientImportException.Reason.HTTP_ERROR, subject = "octocat", httpStatus = 404))

        // Signing
        FileSigner.FileSignerException.Reason.entries.forEach { add(FileSigner.FileSignerException(it, IllegalStateException(raw))) }

        // Biometrics, Keystore, hardware keys
        for (code in listOf(
            BiometricGate.CODE_ENROLMENT_CHANGED, BiometricGate.CODE_UNAVAILABLE, BiometricGate.CODE_NO_RESULT,
            1, 3, 5, 7, 9, 10, 11, 12, 13, 14, 15, 99,
        )) add(BiometricGateException(code, raw))
        HardwareAuthBroker.AuthCancelled.Reason.entries.forEach { add(HardwareAuthBroker.AuthCancelled(it, IllegalStateException(raw))) }
        add(HardwareAuthBroker.AuthCancelled(HardwareAuthBroker.AuthCancelled.Reason.FAILED, BiometricGateException(7, raw)))
        add(HardwareKeyService.HardwareKeyException(raw, IllegalStateException(raw)))
        add(HardwareTagKeyService.HardwareTagException(raw))
        add(HardwareTagKeyService.HardwareTagException(raw, keyGone = true))

        // Security keys over NFC
        add(SecurityKeyService.PinRequiredException(raw))
        add(SecurityKeyService.WrongPinException(raw))
        SecurityKeyService.SecurityKeyException.Reason.entries.forEach {
            add(SecurityKeyService.SecurityKeyException(raw, null, it, 0x2B))
        }
        for (code in listOf(0x27, 0x2E, 0x2F, 0x31, 0x32, 0x34, 0x35, 0x36, 0x2B)) add(Ctap2.CtapError(code))
        add(Cbor.CborException(raw))
        SecurityKeyTransport.NfcException.Reason.entries.forEach {
            add(SecurityKeyTransport.NfcException(raw, IOException(raw), it, 0x6A82))
        }

        // YubiKey
        add(YubiKeyBroker.YubiKeyCancelled())
        add(Piv.PinRequiredException())
        add(Piv.WrongPinException(0))
        add(Piv.WrongPinException(2))
        Piv.PivException.Reason.entries.forEach {
            add(Piv.PivException(raw, 0x6A82, it, foundSerial = 123L, expectedSerial = 456L))
        }
        add(Piv.PivException(raw, 0, Piv.PivException.Reason.NO_KEY_IN_SLOT))

        // age format
        add(Age.NoMatchingIdentityException())
        add(Age.MismatchedRecipientLabelsException())
        AgeHeader.HeaderException.Reason.entries.forEach { add(AgeHeader.HeaderException(raw, it)) }
        AgePayload.PayloadException.Reason.entries.forEach { add(AgePayload.PayloadException(raw, null, it)) }
        add(Armor.ArmorException(raw))
        add(Stanza.Companion.StanzaException(raw))
        add(Bech32.Bech32Exception(raw))
        add(ChaChaPoly.AeadException(raw))
        add(AEADBadTagException(raw))
        add(HpkeMlkem768X25519.LowOrderPointException(raw))
        add(RSAOAEP.RSAOAEPException(raw))
        add(Diceware.DicewareException(raw))

        // SSH keys and signatures
        add(OpenSSHPrivateKey.Companion.OpenSSHPrivateKeyException(raw))
        add(OpenSSHPublicKey.Companion.OpenSSHPublicKeyException(raw))
        add(OpenSSHEncryptedKey.OpenSSHEncryptedKeyException(raw))
        add(SSHMPInt.SSHMPIntException(raw))
        add(SSHWire.SSHWireException(raw))
        add(AESCTR.AESCTRException(raw))
        add(AESCBC.AESCBCException(raw))
        add(BcryptPBKDF.BcryptPBKDFException(raw))
        add(SSHSig.SSHSigFormatException(raw))
        add(SSHSigner.SSHSignerException(raw))
        add(SignedBundle.BundleException(raw))
        add(TarArchive.TarException(raw))

        // Moving keys
        KeyTransfer.TransferException.Reason.entries.forEach { add(KeyTransfer.TransferException(raw, null, it)) }
        LanTransfer.LanTransferException.Reason.entries.forEach { add(LanTransfer.LanTransferException(raw, it)) }
        PaperBackup.PaperBackupException.Reason.entries.forEach { add(PaperBackup.PaperBackupException(raw, null, it)) }

        // System
        add(OutOfMemoryError(raw))
        add(CancellationException(raw))
        add(FileNotFoundException(raw))
        add(SecurityException(raw))
        add(UnknownHostException(raw))
        add(SocketTimeoutException(raw))
        add(ConnectException(raw))
        add(SSLException(raw))
    }

    /** Every string argument, after resolving nested texts' arguments too. */
    private fun argStrings(t: UiText): List<String> = t.args.flatMap { if (it is UiText) argStrings(it) else listOf(it.toString()) }

    @Test
    fun everyKnownExceptionMapsToItsOwnResourceSentence() {
        for (e in everyException()) {
            val text = UserMessage.uiText(e, fallback)
            assertNotEquals("${e.javaClass.name} fell back to the caller's text", fallback.id, text.id)
            assertNotEquals("${e.javaClass.name} has no resource", 0, text.id)
        }
    }

    @Test
    fun noOutputCarriesTheExceptionsOwnTextOrClassName() {
        for (e in everyException()) {
            val args = argStrings(UserMessage.uiText(e, fallback))
            for (arg in args) {
                assertFalse("${e.javaClass.name} leaked its message: $arg", arg.contains(raw))
                assertFalse("${e.javaClass.name} leaked its class name: $arg", arg.contains(e.javaClass.simpleName))
                e.message?.takeIf { it.length > 3 }?.let { m ->
                    assertFalse("${e.javaClass.name} leaked its message: $arg", arg.contains(m))
                }
            }
        }
    }

    @Test
    fun unknownErrorsGetTheCallersSentenceAndNothingElse() {
        for (e in listOf(IllegalStateException(raw), IllegalArgumentException(raw), RuntimeException(raw), IOException(raw))) {
            val text = UserMessage.uiText(e, fallback)
            assertEquals(fallback, text)
        }
    }

    @Test
    fun aKnownCauseUnderAnUnknownWrapperIsFound() {
        val wrapped = RuntimeException(raw, AgePayload.PayloadException(raw, null, AgePayload.PayloadException.Reason.AUTH_FAILED))
        assertEquals(R.string.error_payload_auth, UserMessage.uiText(wrapped, fallback).id)
    }

    @Test
    fun securityFailuresStayFailures() {
        // The header MAC, the payload tag and an AEAD check each say the data was changed or damaged.
        assertEquals(
            R.string.error_header_mac,
            UserMessage.uiText(AgeHeader.HeaderException(raw, AgeHeader.HeaderException.Reason.MAC_FAILED), fallback).id,
        )
        assertEquals(
            R.string.error_payload_auth,
            UserMessage.uiText(AgePayload.PayloadException(raw, null, AgePayload.PayloadException.Reason.AUTH_FAILED), fallback).id,
        )
        assertEquals(R.string.error_integrity, UserMessage.uiText(ChaChaPoly.AeadException(raw), fallback).id)
        // A decrypt wrapper reports what failed underneath, not a softer "couldn't decrypt".
        val decrypt = FileEncryptorException(
            FileEncryptorException.Reason.DECRYPT_FAILED,
            AgeHeader.HeaderException(raw, AgeHeader.HeaderException.Reason.MAC_FAILED),
        )
        assertEquals(R.string.error_header_mac, UserMessage.uiText(decrypt, fallback).id)
        // A transfer sealed for someone else, and a refused one, stay refusals.
        assertEquals(
            R.string.error_transfer_wrong_session,
            UserMessage.uiText(KeyTransfer.TransferException(raw, null, KeyTransfer.TransferException.Reason.WRONG_SESSION), fallback).id,
        )
        assertEquals(
            R.string.error_lan_refused,
            UserMessage.uiText(LanTransfer.LanTransferException(raw, LanTransfer.LanTransferException.Reason.REFUSED), fallback).id,
        )
    }

    @Test
    fun codesAreStatusNumbersOnly() {
        val nfc = UserMessage.uiText(
            SecurityKeyTransport.NfcException(raw, null, SecurityKeyTransport.NfcException.Reason.TRANSPORT, 0x6A82),
            fallback,
        )
        assertEquals(R.string.error_nfc_status, nfc.id)
        assertEquals(listOf("6A82"), argStrings(nfc))
        val ctap = UserMessage.uiText(Ctap2.CtapError(0x2B), fallback)
        assertEquals(R.string.error_sk_code, ctap.id)
        assertEquals(listOf("0x2B"), argStrings(ctap))
        val http = UserMessage.uiText(RecipientImportException(RecipientImportException.Reason.HTTP_ERROR, httpStatus = 503), fallback)
        assertEquals(R.string.error_github_http, http.id)
        assertEquals(listOf("503"), argStrings(http))
    }

    @Test
    fun gitHubFoundNoneNamesTheAccount() {
        val none = UserMessage.uiText(RecipientImportException(RecipientImportException.Reason.NO_KEYS, subject = "octocat"), fallback)
        assertEquals(R.string.error_github_no_keys, none.id)
        assertEquals(listOf("octocat"), argStrings(none))
    }

    @Test
    fun aFinishedSentenceIsShownAsItIs() {
        val text = UserMessage.uiText(ShownMessageException("Already a sentence."), fallback)
        assertEquals(R.string.error_passthrough, text.id)
        assertEquals(listOf("Already a sentence."), argStrings(text))
    }

    @Test
    fun cancellationsAreRecognised() {
        assertTrue(UserMessage.isCancellation(CancellationException()))
        assertTrue(UserMessage.isCancellation(YubiKeyBroker.YubiKeyCancelled()))
        assertTrue(UserMessage.isCancellation(BiometricGateException(10, raw)))
        assertTrue(
            UserMessage.isCancellation(
                FileEncryptorException(FileEncryptorException.Reason.DECRYPT_FAILED, YubiKeyBroker.YubiKeyCancelled()),
            ),
        )
        assertTrue(
            UserMessage.isCancellation(
                HardwareAuthBroker.AuthCancelled(HardwareAuthBroker.AuthCancelled.Reason.FAILED, BiometricGateException(13, raw)),
            ),
        )
        assertFalse(UserMessage.isCancellation(BiometricGateException(7, raw)))
        assertFalse(UserMessage.isCancellation(WrongPassphraseException()))
    }
}
