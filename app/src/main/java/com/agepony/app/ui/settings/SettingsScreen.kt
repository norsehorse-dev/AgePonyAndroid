package com.agepony.app.ui.settings

import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.agepony.app.review.ReviewPrompt
import com.agepony.app.security.BiometricGate
import com.agepony.app.security.PasswordVault
import com.agepony.app.security.UnlockAttempts
import com.agepony.app.ui.security.rememberSensitiveConfirm
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.LockMode
import com.agepony.app.vault.ProxyConfig
import com.agepony.app.vault.ProxyType
import com.agepony.app.vault.VaultViewModel
import com.agepony.app.ui.portability.PaperRestoreScreen
import com.agepony.app.ui.portability.ReceiveKeysScreen
import com.agepony.app.ui.portability.SendKeysScreen
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.Icon
import androidx.compose.ui.semantics.Role
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ChoiceField
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.files.KeyPickerText
import com.agepony.app.ui.components.QuietAction
import com.agepony.app.ui.components.RadioRow
import com.agepony.app.ui.components.SectionHeader
import com.agepony.app.ui.components.SwitchRow
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import com.agepony.app.R

//
// Settings tab (expanded in Phase 2d-3a). Android counterpart of iOS's
// SettingsView: security lock mode, encryption default, active identity,
// about, and a guarded reset. The lock-mode selector picks the Keystore/OS gate
// (Off / device credential / biometric) via VaultViewModel.applyLockMode.
//
// 5.0.1 (security audit): anything that loosens the lock asks the user to confirm it's
// them first (L-15): switching to No lock, changing or removing the password, removing the
// duress secret, lengthening the auto-lock delay, allowing screenshots, and turning off
// erase-after-failed-attempts. A duress secret makes the vault PIN-only, so the lock mode
// rows are disabled while one is set (H-1).
//
// 5.1.0: Biometrics only (iOS E6), listed when a strong biometric is enrolled and no duress
// secret is set. Choosing it explains what it means first; without a password it offers to set
// one and switches once it is saved. Leaving it asks for the app password (L-15), and the
// password can't be removed while it is the mode. Setting the first password asks the owner to
// confirm with a biometric or the screen lock first (iOS H-1).
//
private enum class SettingsSub { HELP, SECURITY, LICENSES, TRASH, SEND_KEYS, RECEIVE_KEYS, PAPER_RESTORE }
private enum class ProxyMode { OFF, ORBOT, CUSTOM }

@Composable
fun SettingsScreen(
    vm: VaultViewModel,
    modifier: Modifier = Modifier,
    onReplayOnboarding: () -> Unit = {},
) {
    val vault = vm.vault
    val context = LocalContext.current

    var encryptToSelf by remember { mutableStateOf(vault.encryptToSelfDefault) }
    var activeId by remember { mutableStateOf(vault.activeIdentityId) }
    var pendingReset by remember { mutableStateOf(false) }
    var showSetPassword by remember { mutableStateOf(false) }
    var showSetDuress by remember { mutableStateOf(false) }
    var confirmRemovePassword by remember { mutableStateOf(false) }
    var showBiometricOnlyDialog by remember { mutableStateOf(false) }
    // Set when the password sheet was opened from the Biometrics only dialog: switch once saved.
    var biometricOnlyAfterPassword by remember { mutableStateOf(false) }
    var passwordOnlyNotice by remember { mutableStateOf<String?>(null) }

    // Re-auth before loosening the lock (audit L-15). The second form always asks the app
    // password when one is set: switching to No lock leaves it as the only way in, so the
    // user has to show they still know it.
    val confirmIdentity = rememberSensitiveConfirm(vault)
    val confirmWithPassword = rememberSensitiveConfirm(vault, requireAppPassword = true)
    val isPin = vm.unlockSecretKind == "pin"
    // Resolved here so the onClick lambdas below can pass them to the confirm prompt.
    val confirmLockOffTitle = stringResource(R.string.settings_confirm_lock_off)
    val confirmChangeTitle = stringResource(
        if (isPin) R.string.settings_confirm_change_pin else R.string.settings_confirm_change_password
    )
    val confirmRemoveDuressTitle = stringResource(
        if (isPin) R.string.settings_confirm_remove_duress_pin else R.string.settings_confirm_remove_duress_password
    )
    val confirmRemoveSecretTitle = stringResource(
        if (isPin) R.string.settings_confirm_remove_pin else R.string.settings_confirm_remove_password
    )
    val confirmStopErasingTitle = stringResource(R.string.settings_confirm_stop_erasing)
    val allowScreenshotsTitle = stringResource(R.string.settings_screenshots)
    val confirmLockLessTitle = stringResource(R.string.settings_confirm_lock_less)
    val confirmSetSecretTitle = stringResource(R.string.settings_confirm_set_secret)
    val confirmChangeLockTitle = stringResource(R.string.settings_confirm_change_lock)

    fun openUrl(url: String) {
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }

    // From the installed package (the build's versionName), never a hard-coded fallback.
    val versionName = remember {
        runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull().orEmpty()
    }

    // In-app feedback: a mailto to the public address, prefilled with version and
    // device context so reports are actionable. ACTION_SENDTO + mailto: keeps it
    // to email apps only.
    fun sendFeedback() {
        val subject = "AgePony Android feedback (v$versionName)"
        val body = "\n\n\n---\nApp version: $versionName" +
            "\nDevice: ${Build.MANUFACTURER} ${Build.MODEL}" +
            "\nAndroid: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\n"
        val intent = Intent(Intent.ACTION_SENDTO).apply {
            data = Uri.parse("mailto:")
            putExtra(Intent.EXTRA_EMAIL, arrayOf("NorseHorse@norsehor.se"))
            putExtra(Intent.EXTRA_SUBJECT, subject)
            putExtra(Intent.EXTRA_TEXT, body)
        }
        runCatching { context.startActivity(intent) }
    }

    var subScreen by remember { mutableStateOf<SettingsSub?>(null) }
    when (subScreen) {
        SettingsSub.HELP -> { HelpScreen(onBack = { subScreen = null }, modifier = modifier); return }
        SettingsSub.SECURITY -> { SecurityInfoScreen(onBack = { subScreen = null }, modifier = modifier); return }
        SettingsSub.LICENSES -> { LicensesScreen(onBack = { subScreen = null }, modifier = modifier); return }
        SettingsSub.TRASH -> { RecentlyDeletedScreen(vault = vault, onBack = { subScreen = null }, modifier = modifier); return }
        SettingsSub.SEND_KEYS -> { SendKeysScreen(vault = vault, onBack = { subScreen = null }, modifier = modifier); return }
        SettingsSub.RECEIVE_KEYS -> { ReceiveKeysScreen(vault = vault, onBack = { subScreen = null }, modifier = modifier); return }
        SettingsSub.PAPER_RESTORE -> { PaperRestoreScreen(vault = vault, onBack = { subScreen = null }, modifier = modifier); return }
        null -> {}
    }

    AgeScreen(title = stringResource(R.string.settings_title), modifier = modifier) { padding ->
    Column(
        Modifier
            .fillMaxSize()
            .padding(padding)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {

        // Security
        SectionHeader(stringResource(R.string.settings_section_security))
        val activity = context as FragmentActivity
        val hasBiometric = remember(vm.isBusy) { BiometricGate.hasBiometric(context) }
        val deviceSecure = remember(vm.isBusy) { BiometricGate.isDeviceSecure(context) }
        val legacy = Build.VERSION.SDK_INT < Build.VERSION_CODES.R
        // A duress secret makes the vault PIN-only; hardware unlock would let a coercer with
        // the phone's passcode skip the PIN field where the duress secret fires (audit H-1).
        val pinOnly = vm.duressEnrolled
        Text(
            stringResource(R.string.settings_lock_intro),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp),
        )
        if (pinOnly) {
            Text(
                stringResource(
                    if (isPin) R.string.settings_pin_only_note_pin else R.string.settings_pin_only_note_password
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        // Leaving Biometrics only lets the screen lock back in, and leaving password-only No lock
        // adds the screen lock or a biometric as a way in: the app password first either way
        // (L-15; iOS H-1).
        fun switchLock(target: LockMode) {
            if (target == vm.lockMode) return
            if ((vm.lockMode == LockMode.BIOMETRIC_ONLY || vault.passwordIsOnlyUnlock()) && vm.passwordEnrolled) {
                confirmWithPassword(confirmChangeLockTitle) { vm.applyLockMode(activity, target) }
            } else {
                vm.applyLockMode(activity, target)
            }
        }
        LockModeRow(
            selected = vm.lockMode == LockMode.BIOMETRIC,
            title = stringResource(R.string.settings_lock_biometric),
            subtitle = if (hasBiometric) {
                stringResource(R.string.settings_lock_biometric_detail)
            } else {
                stringResource(R.string.settings_lock_biometric_unavailable)
            },
            enabled = !vm.isBusy && hasBiometric && !pinOnly,
            onClick = { switchLock(LockMode.BIOMETRIC) },
        )
        // Biometrics only (5.1.0, iOS E6). Named after what the phone has.
        val fingerprintOnly = remember { BiometricGate.fingerprintOnlyHardware(context) }
        val biometricOnlyTitle = stringResource(
            if (fingerprintOnly) R.string.settings_lock_fingerprint_only else R.string.settings_lock_biometric_only
        )
        if (LockMode.biometricOnlyListed(vm.lockMode, pinOnly, hasBiometric)) {
            LockModeRow(
                selected = vm.lockMode == LockMode.BIOMETRIC_ONLY,
                title = biometricOnlyTitle,
                subtitle = when {
                    !hasBiometric -> stringResource(R.string.settings_lock_biometric_unavailable)
                    !vm.passwordEnrolled -> stringResource(R.string.settings_lock_biometric_only_detail_none)
                    isPin -> stringResource(R.string.settings_lock_biometric_only_detail_pin)
                    else -> stringResource(R.string.settings_lock_biometric_only_detail_password)
                },
                enabled = !vm.isBusy && !pinOnly && (hasBiometric || vm.lockMode == LockMode.BIOMETRIC_ONLY),
                onClick = { if (vm.lockMode != LockMode.BIOMETRIC_ONLY) showBiometricOnlyDialog = true },
            )
            // The mode's key stopped working (a biometric added or removed): offer a new one.
            val biometricOnlyBroken = remember(vm.isBusy, vm.lockMode) {
                vm.lockMode == LockMode.BIOMETRIC_ONLY && vault.isUnlocked &&
                    !BiometricGate.biometricOnlyUsable(context)
            }
            if (biometricOnlyBroken) {
                Text(
                    stringResource(R.string.settings_biometric_only_off_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TextButton(
                    onClick = { vm.restoreBiometricOnly(activity) },
                    enabled = !vm.isBusy && hasBiometric,
                ) { Text(stringResource(R.string.settings_biometric_only_turn_on_again)) }
            }
        }
        LockModeRow(
            selected = vm.lockMode == LockMode.DEVICE_CREDENTIAL,
            title = stringResource(R.string.settings_lock_device),
            subtitle = when {
                !deviceSecure -> stringResource(R.string.settings_lock_device_no_screen_lock)
                legacy -> stringResource(R.string.settings_lock_device_legacy)
                else -> stringResource(R.string.settings_lock_device_detail)
            },
            enabled = !vm.isBusy && deviceSecure && !pinOnly,
            onClick = { switchLock(LockMode.DEVICE_CREDENTIAL) },
        )
        LockModeRow(
            selected = vm.lockMode == LockMode.OFF,
            title = stringResource(R.string.settings_lock_off),
            subtitle = if (vm.passwordEnrolled) {
                stringResource(
                    if (isPin) R.string.settings_lock_off_detail_pin else R.string.settings_lock_off_detail_password
                )
            } else {
                stringResource(R.string.settings_lock_off_detail_open)
            },
            enabled = !vm.isBusy && !pinOnly,
            onClick = {
                if (vm.lockMode != LockMode.OFF) {
                    val confirm = if (vm.passwordEnrolled) confirmWithPassword else confirmIdentity
                    confirm(confirmLockOffTitle) { vm.applyLockMode(activity, LockMode.OFF) }
                }
            },
        )

        // App-owned password / PIN unlock (4.0.0). Coexists with biometric; also the
        // home of the duress password.
        if (!vm.passwordEnrolled) {
            OutlinedButton(
                // The first password is a new way in, and later owner checks trust it: the owner
                // confirms first, not just whoever holds the unlocked app (5.1.0, iOS H-1).
                onClick = { confirmIdentity(confirmSetSecretTitle) { showSetPassword = true } },
                enabled = vm.vault.isUnlocked && !vm.isBusy,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            ) { Text(stringResource(R.string.settings_set_secret_button)) }
            Text(
                stringResource(R.string.settings_set_secret_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            Text(
                stringResource(if (isPin) R.string.settings_secret_set_pin else R.string.settings_secret_set_password),
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(top = 8.dp),
            )
            if (vm.secretBelowMinimum) {
                Text(
                    if (isPin) {
                        stringResource(R.string.settings_pin_too_short, PasswordVault.MIN_PIN_LENGTH)
                    } else {
                        stringResource(R.string.settings_password_too_short, PasswordVault.MIN_PASSWORD_LENGTH)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Row {
                TextButton(
                    onClick = { confirmIdentity(confirmChangeTitle) { showSetPassword = true } },
                    enabled = vm.vault.isUnlocked && !vm.isBusy,
                ) {
                    Text(stringResource(R.string.settings_action_change))
                }
                TextButton(
                    onClick = {
                        // Never strand the vault (audit L-16), and keep Biometrics only's way back in (E6).
                        if (vm.passwordRemovalRefused()) {
                            passwordOnlyNotice = vm.passwordOnlyMessage()
                        } else {
                            confirmRemovePassword = true
                        }
                    },
                    enabled = !vm.isBusy,
                ) {
                    Text(stringResource(R.string.settings_action_remove), color = MaterialTheme.colorScheme.error)
                }
            }

            if (!vm.duressEnrolled) {
                OutlinedButton(
                    onClick = { showSetDuress = true },
                    enabled = vm.vault.isUnlocked && !vm.isBusy,
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                ) {
                    Text(
                        stringResource(
                            if (isPin) R.string.settings_set_duress_button_pin else R.string.settings_set_duress_button_password
                        )
                    )
                }
                Text(
                    stringResource(if (isPin) R.string.settings_duress_hint_pin else R.string.settings_duress_hint_password),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Text(
                    stringResource(if (isPin) R.string.settings_duress_set_pin else R.string.settings_duress_set_password),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp),
                )
                Row {
                    TextButton(
                        onClick = { showSetDuress = true },
                        enabled = vm.vault.isUnlocked && !vm.isBusy,
                    ) { Text(stringResource(R.string.settings_action_change)) }
                    TextButton(
                        onClick = { confirmIdentity(confirmRemoveDuressTitle) { vm.removeDuress() } },
                        enabled = !vm.isBusy,
                    ) {
                        Text(stringResource(R.string.settings_action_remove), color = MaterialTheme.colorScheme.error)
                    }
                }
            }

            SettingRow(
                title = pluralStringResource(
                    R.plurals.settings_erase_title,
                    UnlockAttempts.ERASE_AFTER,
                    UnlockAttempts.ERASE_AFTER,
                ),
                subtitle = pluralStringResource(
                    if (isPin) R.plurals.settings_erase_detail_pin else R.plurals.settings_erase_detail_password,
                    UnlockAttempts.ERASE_AFTER,
                    UnlockAttempts.ERASE_AFTER,
                    UnlockAttempts.BACKOFF_AFTER,
                ),
                checked = vault.eraseAfterFailedAttempts,
                enabled = !vm.isBusy,
                onCheckedChange = { on ->
                    if (on) {
                        vault.eraseAfterFailedAttempts = true
                    } else {
                        confirmIdentity(confirmStopErasingTitle) { vault.eraseAfterFailedAttempts = false }
                    }
                },
            )
        }

        // Screenshots (5.0.1). FLAG_SECURE is applied from this setting by the activities.
        SettingRow(
            title = allowScreenshotsTitle,
            subtitle = stringResource(R.string.settings_screenshots_detail),
            checked = vault.allowScreenshots,
            enabled = true,
            onCheckedChange = { on ->
                if (on) {
                    confirmIdentity(allowScreenshotsTitle) { vault.allowScreenshots = true }
                } else {
                    vault.allowScreenshots = false
                }
            },
        )

        if (vm.error != null) {
            Text(
                vm.error!!,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(top = 4.dp),
            )
        }

        ListDivider()

        // Encryption
        SectionHeader(stringResource(R.string.files_section_encryption))
        SettingRow(
            title = stringResource(R.string.settings_encrypt_to_self),
            subtitle = stringResource(R.string.settings_encrypt_to_self_detail),
            checked = encryptToSelf,
            enabled = true,
            onCheckedChange = { encryptToSelf = it; vault.encryptToSelfDefault = it },
        )

        SettingRow(
            title = stringResource(R.string.settings_armor_default),
            subtitle = stringResource(R.string.settings_armor_default_detail),
            checked = vault.armorDefault,
            enabled = true,
            onCheckedChange = { vault.armorDefault = it },
        )

        SettingRow(
            title = stringResource(R.string.settings_passphrase_default),
            subtitle = stringResource(R.string.settings_passphrase_default_detail),
            checked = vault.passphraseModeDefault,
            enabled = true,
            onCheckedChange = { vault.passphraseModeDefault = it },
        )

        if (vault.sessionPassphrase != null) {
            ActionRow(
                label = stringResource(R.string.settings_forget_passphrase),
                trailing = stringResource(R.string.settings_forget),
                onClick = { vault.forgetSessionPassphrase() },
            )
            Text(
                stringResource(R.string.settings_forget_passphrase_detail),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        var workFactor by remember { mutableStateOf(vault.scryptWorkFactor) }
        // A menu of the allowed factors, as on iOS, instead of Less and More buttons squeezed
        // beside the label (5.1.0, U4).
        ChoiceField(
            label = stringResource(R.string.settings_work_factor),
            selected = workFactor,
            options = (FileEncryptor.MIN_SCRYPT_WORK_FACTOR..FileEncryptor.MAX_SCRYPT_WORK_FACTOR).toList(),
            optionLabel = { factor ->
                stringResource(
                    if (factor == FileEncryptor.DEFAULT_SCRYPT_WORK_FACTOR) R.string.settings_work_factor_option_default
                    else R.string.settings_work_factor_option,
                    factor,
                    FileEncryptor.scryptMemoryBytes(factor) shr 20,
                )
            },
            onSelect = { factor -> workFactor = factor; vault.scryptWorkFactor = factor },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        Text(
            if (workFactor == FileEncryptor.DEFAULT_SCRYPT_WORK_FACTOR) {
                stringResource(
                    R.string.settings_work_factor_detail_default,
                    workFactor,
                    FileEncryptor.scryptMemoryBytes(workFactor) shr 20,
                )
            } else {
                stringResource(
                    R.string.settings_work_factor_detail_custom,
                    workFactor,
                    FileEncryptor.scryptMemoryBytes(workFactor) shr 20,
                    FileEncryptor.DEFAULT_SCRYPT_WORK_FACTOR,
                )
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ListDivider()

        // Auto-lock
        SectionHeader(stringResource(R.string.settings_section_autolock))
        ChoiceField(
            label = stringResource(R.string.settings_autolock_label),
            selected = vault.autoLockGraceSeconds,
            options = listOf(0, 15, 30, 60, 300),
            optionLabel = { autoLockLabel(it) },
            onSelect = { seconds ->
                // A longer delay loosens the lock: confirm it's you (audit L-15).
                if (seconds > vault.autoLockGraceSeconds) {
                    confirmIdentity(confirmLockLessTitle) { vault.autoLockGraceSeconds = seconds }
                } else {
                    vault.autoLockGraceSeconds = seconds
                }
            },
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
        )
        Text(
            stringResource(R.string.settings_autolock_detail),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        ListDivider()

        // Network
        SectionHeader(stringResource(R.string.settings_section_network))
        val proxyCtx = LocalContext.current
        val orbotInstalled = remember { ProxyConfig.isOrbotInstalled(proxyCtx) }

        var proxyMode by remember {
            mutableStateOf(
                when {
                    vault.proxyType == ProxyType.NONE -> ProxyMode.OFF
                    vault.proxyType == ProxyType.SOCKS &&
                        vault.proxyHost.trim() == ProxyConfig.ORBOT_HOST &&
                        vault.proxyPort == ProxyConfig.ORBOT_PORT -> ProxyMode.ORBOT
                    else -> ProxyMode.CUSTOM
                }
            )
        }
        var customIsSocks by remember { mutableStateOf(vault.proxyType != ProxyType.HTTP) }
        var proxyHostField by remember { mutableStateOf(vault.proxyHost) }
        var proxyPortField by remember {
            mutableStateOf(if (vault.proxyPort > 0) vault.proxyPort.toString() else "")
        }
        var proxyUserField by remember { mutableStateOf(vault.proxyUsername) }
        var proxyPassField by remember { mutableStateOf(vault.proxyPassword) }

        Text(
            stringResource(R.string.settings_network_intro),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        LockModeRow(
            selected = proxyMode == ProxyMode.OFF,
            title = stringResource(R.string.settings_proxy_off),
            subtitle = stringResource(R.string.settings_proxy_off_detail),
            enabled = true,
        ) {
            proxyMode = ProxyMode.OFF
            vault.proxyType = ProxyType.NONE
        }
        LockModeRow(
            selected = proxyMode == ProxyMode.ORBOT,
            title = stringResource(R.string.settings_proxy_orbot),
            subtitle = stringResource(R.string.settings_proxy_orbot_detail, ProxyConfig.ORBOT_HOST, ProxyConfig.ORBOT_PORT),
            enabled = true,
        ) {
            proxyMode = ProxyMode.ORBOT
            proxyHostField = ProxyConfig.ORBOT_HOST
            proxyPortField = ProxyConfig.ORBOT_PORT.toString()
            vault.proxyType = ProxyType.SOCKS
            vault.proxyHost = ProxyConfig.ORBOT_HOST
            vault.proxyPort = ProxyConfig.ORBOT_PORT
        }
        LockModeRow(
            selected = proxyMode == ProxyMode.CUSTOM,
            title = stringResource(R.string.settings_proxy_custom),
            subtitle = stringResource(R.string.settings_proxy_custom_detail),
            enabled = true,
        ) {
            proxyMode = ProxyMode.CUSTOM
            vault.proxyType = if (customIsSocks) ProxyType.SOCKS else ProxyType.HTTP
            vault.proxyHost = proxyHostField
            vault.proxyPort = proxyPortField.toIntOrNull() ?: 0
        }

        if (proxyMode == ProxyMode.ORBOT && !orbotInstalled) {
            Text(
                stringResource(R.string.settings_orbot_missing),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }

        if (proxyMode == ProxyMode.CUSTOM) {
            RadioRow(
                title = stringResource(R.string.settings_proxy_socks),
                selected = customIsSocks,
                onClick = { customIsSocks = true; vault.proxyType = ProxyType.SOCKS },
            )
            RadioRow(
                title = stringResource(R.string.settings_proxy_http),
                selected = !customIsSocks,
                onClick = { customIsSocks = false; vault.proxyType = ProxyType.HTTP },
            )
            OutlinedTextField(
                value = proxyHostField,
                onValueChange = { proxyHostField = it; vault.proxyHost = it },
                label = { Text(stringResource(R.string.settings_proxy_host)) },
                placeholder = { Text("127.0.0.1") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = proxyPortField,
                onValueChange = { v ->
                    val f = v.filter { ch -> ch.isDigit() }.take(5)
                    proxyPortField = f
                    vault.proxyPort = f.toIntOrNull() ?: 0
                },
                label = { Text(stringResource(R.string.settings_proxy_port)) },
                placeholder = { Text("9050") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
        }

        if (proxyMode != ProxyMode.OFF) {
            OutlinedTextField(
                value = proxyUserField,
                onValueChange = { proxyUserField = it; vault.proxyUsername = it },
                label = { Text(stringResource(R.string.settings_proxy_username)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = proxyPassField,
                onValueChange = { proxyPassField = it; vault.proxyPassword = it },
                label = { Text(stringResource(R.string.settings_proxy_password)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                stringResource(R.string.settings_proxy_credentials_detail),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                stringResource(R.string.settings_proxy_no_fallback),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        ListDivider()

        // Active identity
        SectionHeader(stringResource(R.string.settings_section_active_identity))
        if (vault.identities.isEmpty()) {
            Text(
                stringResource(R.string.settings_no_identities),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            val active = vault.identities.firstOrNull { it.id == activeId } ?: vault.identities.first()
            ChoiceField(
                label = stringResource(R.string.settings_identity_label),
                selected = active,
                options = vault.identities.toList(),
                // Name, type and key, as every key picker shows them (5.1.0 item 3).
                optionLabel = { KeyPickerText.menuLine(LocalContext.current, it) },
                onSelect = { identity ->
                    activeId = identity.id
                    vault.activeIdentityId = identity.id
                },
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            )
            Text(
                stringResource(R.string.settings_active_identity_detail),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        ListDivider()

        // Keys on other devices (5.0.0)
        SectionHeader(stringResource(R.string.settings_section_keys))
        // Each opens its own screen, so they are rows with a chevron, not buttons (5.1.0, U4).
        ActionRow(label = stringResource(R.string.settings_send_keys), onClick = { subScreen = SettingsSub.SEND_KEYS })
        ActionRow(label = stringResource(R.string.settings_receive_keys), onClick = { subScreen = SettingsSub.RECEIVE_KEYS })
        ActionRow(label = stringResource(R.string.settings_paper_restore), onClick = { subScreen = SettingsSub.PAPER_RESTORE })
        Text(
            stringResource(R.string.settings_keys_detail),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ListDivider()

        OutlinedButton(onClick = { vm.lock() }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.settings_lock_now)) }

        if (vm.error != null) {
            Text(vm.error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }

        ListDivider()

        // About
        SectionHeader(stringResource(R.string.settings_section_about))
        AboutRow(stringResource(R.string.settings_version), versionName)
        LinkRow(stringResource(R.string.settings_website)) { openUrl("https://agepony.com") }
        LinkRow(stringResource(R.string.settings_source_code)) { openUrl("https://github.com/norsehorse-dev/AgePonyAndroid") }
        LinkRow(stringResource(R.string.settings_age_spec)) { openUrl("https://age-encryption.org/v1") }
        ActionRow(label = stringResource(R.string.settings_licenses), onClick = { subScreen = SettingsSub.LICENSES })
        AboutRow(stringResource(R.string.settings_made_by), "NorseHorse")

        ListDivider()

        // AgePony for Desktop — the same product on the desktop, not a sibling
        // app, so it sits above the More-from list. Mirrors PGPony's desktop promo.
        MoreRow(stringResource(R.string.settings_desktop), stringResource(R.string.settings_desktop_detail)) { openUrl("https://agepony.com/desktop") }

        ListDivider()

        // More from NorseHorse — the sibling apps, each linking to its product
        // site. AgePony itself is omitted since this is it. Mirrors PGPony's
        // section; kept to product sites only (no store links) so it's identical
        // in the foss and play flavors.
        SectionHeader(stringResource(R.string.settings_section_more))
        MoreRow(stringResource(R.string.settings_more_all), stringResource(R.string.settings_more_all_detail)) { openUrl("https://pony.norsehor.se") }
        MoreRow("PGPony", stringResource(R.string.settings_more_pgpony_detail)) { openUrl("https://pgpony.app") }
        MoreRow("QuorumPony", stringResource(R.string.settings_more_quorumpony_detail)) { openUrl("https://quorumpony.com") }
        MoreRow("CarrierPony", stringResource(R.string.settings_more_carrierpony_detail)) { openUrl("https://carrierpony.com") }
        MoreRow("BurnPony", stringResource(R.string.settings_more_burnpony_detail)) { openUrl("https://burnpony.app") }
        MoreRow("VaultPony", stringResource(R.string.settings_more_vaultpony_detail)) { openUrl("https://vaultpony.app") }
        MoreRow("PassPony", stringResource(R.string.settings_more_passpony_detail)) { openUrl("https://passpony.app") }
        MoreRow("RelayPony", stringResource(R.string.settings_more_relaypony_detail)) { openUrl("https://relaypony.app") }
        MoreRow("ScrubPony", stringResource(R.string.settings_more_scrubpony_detail)) { openUrl("https://scrubpony.app") }

        ListDivider()

        // Help & feedback
        SectionHeader(stringResource(R.string.settings_section_help))
        ActionRow(label = stringResource(R.string.settings_help), onClick = { subScreen = SettingsSub.HELP })
        ActionRow(label = stringResource(R.string.settings_security_info), onClick = { subScreen = SettingsSub.SECURITY })
        ActionRow(label = stringResource(R.string.settings_replay_intro), onClick = { onReplayOnboarding() })
        Text(
            stringResource(R.string.settings_replay_intro_detail),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ActionRow(label = stringResource(R.string.settings_rate), onClick = { ReviewPrompt.openRating(context) })
        Text(
            stringResource(R.string.settings_rate_detail),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ActionRow(label = stringResource(R.string.settings_send_feedback), onClick = { sendFeedback() })
        Text(
            stringResource(R.string.settings_send_feedback_detail),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ActionRow(label = stringResource(R.string.settings_recently_deleted), onClick = { subScreen = SettingsSub.TRASH })
        Text(
            stringResource(R.string.settings_recently_deleted_detail),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ListDivider()

        // Reset
        SectionHeader(stringResource(R.string.settings_reset))
        QuietAction(text = stringResource(R.string.settings_reset_button), onClick = { pendingReset = true }, destructive = true)
        Text(
            stringResource(R.string.settings_reset_detail),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 24.dp),
        )
    }
    }

    if (pendingReset) {
        AlertDialog(
            onDismissRequest = { pendingReset = false },
            title = { Text(stringResource(R.string.settings_reset_title)) },
            text = {
                Text(stringResource(R.string.settings_reset_body))
            },
            confirmButton = {
                TextButton(onClick = { pendingReset = false; vm.reset() }) {
                    Text(stringResource(R.string.settings_reset), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingReset = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }

    if (showSetPassword) {
        SetSecretDialog(
            title = stringResource(R.string.settings_set_secret_title),
            allowKindChoice = true,
            initialKind = vm.unlockSecretKind,
            onConfirm = { secret, kind, _ ->
                val switchAfter = biometricOnlyAfterPassword
                biometricOnlyAfterPassword = false
                vm.enrollPassword(secret, kind) {
                    if (switchAfter) vm.applyLockMode(context as FragmentActivity, LockMode.BIOMETRIC_ONLY)
                }
                showSetPassword = false
            },
            onDismiss = { showSetPassword = false; biometricOnlyAfterPassword = false },
        )
    }

    if (showBiometricOnlyDialog) {
        val fingerprintOnly = remember { BiometricGate.fingerprintOnlyHardware(context) }
        AlertDialog(
            onDismissRequest = { showBiometricOnlyDialog = false },
            title = {
                Text(
                    stringResource(
                        if (fingerprintOnly) R.string.settings_lock_fingerprint_only else R.string.settings_lock_biometric_only
                    )
                )
            },
            text = {
                Column {
                    Text(stringResource(R.string.settings_biometric_only_dialog_body))
                    if (!vm.passwordEnrolled) {
                        Text(
                            stringResource(R.string.settings_biometric_only_dialog_needs_secret),
                            modifier = Modifier.padding(top = 8.dp),
                        )
                    }
                }
            },
            confirmButton = {
                if (vm.passwordEnrolled) {
                    // From password-only No lock this adds a way in, so the app password first
                    // (iOS H-1). From another mode it narrows the lock, and the biometric prompt
                    // that makes the key is the check.
                    TextButton(onClick = {
                        showBiometricOnlyDialog = false
                        val apply = { vm.applyLockMode(context as FragmentActivity, LockMode.BIOMETRIC_ONLY) }
                        if (vault.passwordIsOnlyUnlock()) confirmWithPassword(confirmChangeLockTitle) { apply() } else apply()
                    }) { Text(stringResource(R.string.settings_biometric_only_turn_on)) }
                } else {
                    TextButton(onClick = {
                        showBiometricOnlyDialog = false
                        // The first password needs the owner (iOS H-1), then the mode switches once it is saved.
                        confirmIdentity(confirmSetSecretTitle) {
                            biometricOnlyAfterPassword = true
                            showSetPassword = true
                        }
                    }) { Text(stringResource(R.string.settings_biometric_only_set_secret)) }
                }
            },
            dismissButton = {
                TextButton(onClick = { showBiometricOnlyDialog = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }

    if (showSetDuress) {
        SetSecretDialog(
            title = stringResource(
                if (isPin) R.string.settings_set_duress_title_pin else R.string.settings_set_duress_title_password
            ),
            allowKindChoice = false,
            // The duress secret is typed into the same lock screen field, so same keyboard.
            initialKind = vm.unlockSecretKind,
            confirmLabel = stringResource(R.string.settings_set_duress_confirm),
            body = stringResource(
                if (isPin) R.string.settings_set_duress_body_pin else R.string.settings_set_duress_body_password
            ),
            currentLabel = stringResource(
                if (isPin) R.string.settings_current_pin else R.string.settings_current_password
            ),
            onConfirm = { secret, _, current ->
                vm.setDuressSecret(secret, current)
                showSetDuress = false
            },
            onDismiss = { showSetDuress = false },
        )
    }

    if (confirmRemovePassword) {
        AlertDialog(
            onDismissRequest = { confirmRemovePassword = false },
            title = {
                Text(
                    stringResource(
                        if (isPin) R.string.settings_remove_title_pin else R.string.settings_remove_title_password
                    )
                )
            },
            text = {
                Text(
                    if (vm.duressEnrolled) {
                        stringResource(
                            if (isPin) R.string.settings_remove_body_duress_pin else R.string.settings_remove_body_duress_password
                        )
                    } else {
                        stringResource(R.string.settings_remove_body)
                    }
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmRemovePassword = false
                    confirmIdentity(confirmRemoveSecretTitle) { vm.removePassword() }
                }) {
                    Text(stringResource(R.string.settings_action_remove), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmRemovePassword = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }

    passwordOnlyNotice?.let { notice ->
        AlertDialog(
            onDismissRequest = { passwordOnlyNotice = null },
            title = { Text(stringResource(R.string.settings_cant_remove_title)) },
            text = { Text(notice) },
            confirmButton = { TextButton(onClick = { passwordOnlyNotice = null }) { Text(stringResource(R.string.settings_ok)) } },
        )
    }
}

/**
 * New-secret entry with a confirm field. [initialKind] preselects "password" or "pin".
 * With [currentLabel] set, a field for the current secret comes first and must be filled;
 * it is passed to [onConfirm] as the third argument (null otherwise). New secrets must
 * meet the minimum length (audit M-1).
 */
@Composable
private fun SetSecretDialog(
    title: String,
    allowKindChoice: Boolean,
    initialKind: String = "password",
    confirmLabel: String = stringResource(R.string.settings_save),
    body: String? = null,
    currentLabel: String? = null,
    onConfirm: (CharArray, String, CharArray?) -> Unit,
    onDismiss: () -> Unit,
) {
    var kind by remember { mutableStateOf(if (initialKind == "pin") "pin" else "password") }
    var current by remember { mutableStateOf("") }
    var value by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    val isPin = kind == "pin"
    val mismatch = again.isNotEmpty() && value != again
    val policyError = if (value.isEmpty()) null else PasswordVault.secretPolicyError(LocalContext.current, value, kind)
    val valid = value.isNotEmpty() && policyError == null && value == again &&
        (currentLabel == null || current.isNotEmpty())

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                if (body != null) {
                    Text(body, style = MaterialTheme.typography.bodyMedium)
                }
                if (allowKindChoice) {
                    // A menu, not two text buttons posing as segments (5.1.0, U4).
                    ChoiceField(
                        label = stringResource(R.string.settings_secret_type),
                        selected = kind,
                        options = listOf("password", "pin"),
                        optionLabel = {
                            stringResource(if (it == "pin") R.string.settings_kind_pin else R.string.settings_kind_password)
                        },
                        onSelect = { kind = it },
                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                    )
                }
                val kb = KeyboardOptions(keyboardType = if (isPin) KeyboardType.NumberPassword else KeyboardType.Password)
                if (currentLabel != null) {
                    OutlinedTextField(
                        value = current,
                        onValueChange = { current = it },
                        singleLine = true,
                        label = { Text(currentLabel) },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = kb,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    singleLine = true,
                    label = { Text(stringResource(if (isPin) R.string.settings_kind_pin else R.string.settings_kind_password)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = kb,
                    isError = policyError != null,
                    supportingText = {
                        Text(
                            policyError ?: if (isPin) {
                                stringResource(R.string.settings_pin_min, PasswordVault.MIN_PIN_LENGTH)
                            } else {
                                stringResource(R.string.settings_password_min, PasswordVault.MIN_PASSWORD_LENGTH)
                            }
                        )
                    },
                    modifier = Modifier.padding(top = 8.dp),
                )
                OutlinedTextField(
                    value = again,
                    onValueChange = { again = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.settings_confirm_field)) },
                    isError = mismatch,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = kb,
                    modifier = Modifier.padding(top = 8.dp),
                )
                if (mismatch) {
                    Text(stringResource(R.string.settings_mismatch), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onConfirm(value.toCharArray(), kind, if (currentLabel != null) current.toCharArray() else null)
                },
                enabled = valid,
            ) {
                Text(confirmLabel)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}

@Composable
private fun autoLockLabel(seconds: Int): String = when {
    seconds == 0 -> stringResource(R.string.settings_autolock_immediately)
    seconds % 60 == 0 -> pluralStringResource(R.plurals.settings_autolock_minutes, seconds / 60, seconds / 60)
    else -> pluralStringResource(R.plurals.settings_autolock_seconds, seconds, seconds)
}

/** Settings switch row: the whole row toggles (shared SwitchRow). */
@Composable
private fun SettingRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    SwitchRow(
        title = title,
        subtitle = subtitle,
        checked = checked,
        enabled = enabled,
        onCheckedChange = onCheckedChange,
    )
}

/** One choice of a radio group: the whole row selects (shared RadioRow). */
@Composable
private fun LockModeRow(
    selected: Boolean,
    title: String,
    subtitle: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    RadioRow(
        title = title,
        subtitle = subtitle,
        selected = selected,
        enabled = enabled,
        onClick = onClick,
    )
}

@Composable
private fun AboutRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** A link that leaves the app (website, source). Link text in the accent color, 48dp target. */
@Composable
private fun LinkRow(label: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onClick)
            .heightIn(min = 48.dp)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary)
    }
}

/** A sibling app: name in the accent color (it is a link), one plain line under it. */
@Composable
private fun MoreRow(title: String, subtitle: String, onClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onClick)
            .heightIn(min = 48.dp)
            .padding(vertical = 8.dp),
    ) {
        Text(title, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary)
        Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/**
 * A row that opens something (a sub-screen, the store, an email). The whole row is the target,
 * 48dp tall; a chevron marks it, or a short [trailing] action word when the row acts in place.
 */
@Composable
private fun ActionRow(label: String, onClick: () -> Unit, trailing: String? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .heightIn(min = 48.dp)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        if (trailing != null) {
            Text(trailing, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
        } else {
            Icon(
                Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
