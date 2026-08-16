package com.agepony.app.ui.settings

import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
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
import com.agepony.app.vault.FileEncryptor
import com.agepony.app.vault.LockMode
import com.agepony.app.vault.VaultViewModel

//
// Settings tab (expanded in Phase 2d-3a). Android counterpart of iOS's
// SettingsView: security lock mode, encryption default, active identity,
// about, and a guarded reset. The lock-mode selector picks the Keystore/OS gate
// (Off / device credential / biometric) via VaultViewModel.applyLockMode.
//
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
    var identityMenuOpen by remember { mutableStateOf(false) }
    var pendingReset by remember { mutableStateOf(false) }
    var showSetPassword by remember { mutableStateOf(false) }
    var showSetDuress by remember { mutableStateOf(false) }

    fun openUrl(url: String) {
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }

    val versionName = remember {
        runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull() ?: "1.0"
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

    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)

        // Security
        SectionLabel("Security")
        val activity = context as FragmentActivity
        val hasBiometric = remember(vm.isBusy) { BiometricGate.hasBiometric(context) }
        val deviceSecure = remember(vm.isBusy) { BiometricGate.isDeviceSecure(context) }
        val legacy = Build.VERSION.SDK_INT < Build.VERSION_CODES.R
        Text(
            "How AgePony's vault is locked. This is separate from any password you set below, " +
                "which is its own lock whichever mode you pick.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp),
        )
        LockModeRow(
            selected = vm.lockMode == LockMode.BIOMETRIC,
            title = "Biometric",
            subtitle = if (hasBiometric) {
                "Your fingerprint or face unlocks the vault, with your device credential as a fallback."
            } else {
                "Needs a fingerprint or face enrolled on this device."
            },
            enabled = !vm.isBusy && hasBiometric,
            onClick = { vm.applyLockMode(activity, LockMode.BIOMETRIC) },
        )
        LockModeRow(
            selected = vm.lockMode == LockMode.DEVICE_CREDENTIAL,
            title = "Device PIN, pattern, or password",
            subtitle = when {
                !deviceSecure -> "Set a screen lock in Android settings to use this."
                legacy -> "Required at every unlock. On this Android version it gates access but " +
                    "does not add hardware-backed encryption; a vault password below does."
                else -> "Your device PIN, pattern, or password is required at every unlock, " +
                    "checked against the key in hardware."
            },
            enabled = !vm.isBusy && deviceSecure,
            onClick = { vm.applyLockMode(activity, LockMode.DEVICE_CREDENTIAL) },
        )
        LockModeRow(
            selected = vm.lockMode == LockMode.OFF,
            title = "No lock",
            subtitle = "The vault opens with nothing to confirm. If you set a password below it " +
                "becomes the gate; with neither, anyone who opens the app is in.",
            enabled = !vm.isBusy,
            onClick = { vm.applyLockMode(activity, LockMode.OFF) },
        )

        // App-owned password / PIN unlock (4.0.0). Coexists with biometric; also the
        // home of the duress password.
        if (!vm.passwordEnrolled) {
            OutlinedButton(
                onClick = { showSetPassword = true },
                enabled = vm.vault.isUnlocked && !vm.isBusy,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            ) { Text("Set a password or PIN…") }
            Text(
                "A password you can use to unlock even with no biometric enrolled, and the " +
                    "basis for a duress password.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            val noun = if (vm.unlockSecretKind == "pin") "PIN" else "password"
            Text(
                "Unlock $noun is set.",
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(top = 8.dp),
            )
            Row {
                TextButton(onClick = { showSetPassword = true }, enabled = vm.vault.isUnlocked && !vm.isBusy) {
                    Text("Change")
                }
                TextButton(onClick = { vm.removePassword() }, enabled = !vm.isBusy) {
                    Text("Remove", color = MaterialTheme.colorScheme.error)
                }
            }

            if (!vm.duressEnrolled) {
                OutlinedButton(
                    onClick = { showSetDuress = true },
                    enabled = !vm.isBusy,
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                ) { Text("Set a duress password…") }
                Text(
                    "A second, different password that silently wipes the vault instead of " +
                        "opening it. Entered under coercion, it leaves an empty app with nothing " +
                        "to reveal. There is no confirmation and no undo.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Text(
                    "Duress password is set — entering it wipes the vault.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp),
                )
                Row {
                    TextButton(onClick = { showSetDuress = true }, enabled = !vm.isBusy) { Text("Change") }
                    TextButton(onClick = { vm.removeDuress() }, enabled = !vm.isBusy) {
                        Text("Remove", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }

        if (vm.error != null) {
            Text(
                vm.error!!,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(top = 4.dp),
            )
        }

        HorizontalDivider()

        // Encryption
        SectionLabel("Encryption")
        SettingRow(
            title = "Encrypt to self by default",
            subtitle = "Pre-select your active identity when choosing recipients, so you can always decrypt your own files.",
            checked = encryptToSelf,
            enabled = true,
            onCheckedChange = { encryptToSelf = it; vault.encryptToSelfDefault = it },
        )

        SettingRow(
            title = "Armor as text by default",
            subtitle = "Start the encrypt screen with ASCII armor on. Armored output pastes into a " +
                "message; raw binary is about a third smaller. Changing the switch while encrypting " +
                "updates this too.",
            checked = vault.armorDefault,
            enabled = true,
            onCheckedChange = { vault.armorDefault = it },
        )

        SettingRow(
            title = "Passphrase-only by default",
            subtitle = "Open the recipient picker in passphrase (scrypt) mode instead of key " +
                "selection, for when you mostly encrypt with a passphrase.",
            checked = vault.passphraseModeDefault,
            enabled = true,
            onCheckedChange = { vault.passphraseModeDefault = it },
        )

        if (vault.sessionPassphrase != null) {
            ActionRow(
                label = "Forget the remembered passphrase",
                trailing = "Forget",
                onClick = { vault.forgetSessionPassphrase() },
            )
            Text(
                "A passphrase is being held in memory so a run of files is only asked for it once. " +
                    "It is never written to disk and is dropped whenever the vault locks.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        var workFactor by remember { mutableStateOf(vault.scryptWorkFactor) }
        Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Passphrase work factor", style = MaterialTheme.typography.bodyLarge)
                Text(
                    "2^" + workFactor + " — scrypt holds about " +
                        (FileEncryptor.scryptMemoryBytes(workFactor) shr 20) +
                        " MB while it derives the key, whatever the file size. " +
                        (if (workFactor == FileEncryptor.DEFAULT_SCRYPT_WORK_FACTOR) {
                            "This is age's default."
                        } else {
                            "age's default is 2^" + FileEncryptor.DEFAULT_SCRYPT_WORK_FACTOR + "."
                        }) +
                        " The value is stored in the file, so any age tool can still open it.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            TextButton(
                onClick = { workFactor -= 1; vault.scryptWorkFactor = workFactor },
                enabled = workFactor > FileEncryptor.MIN_SCRYPT_WORK_FACTOR,
            ) { Text("Less") }
            TextButton(
                onClick = { workFactor += 1; vault.scryptWorkFactor = workFactor },
                enabled = workFactor < FileEncryptor.MAX_SCRYPT_WORK_FACTOR,
            ) { Text("More") }
        }

        HorizontalDivider()

        // Active identity
        SectionLabel("Active identity")
        if (vault.identities.isEmpty()) {
            Text(
                "No identities yet. Add one from the Identities tab.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            val activeName = vault.identities.firstOrNull { it.id == activeId }?.name
                ?: vault.identities.first().name
            Box {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { identityMenuOpen = true }
                        .padding(vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(activeName, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                    Text("Change", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                }
                DropdownMenu(expanded = identityMenuOpen, onDismissRequest = { identityMenuOpen = false }) {
                    vault.identities.forEach { identity ->
                        DropdownMenuItem(
                            text = { Text(identity.name) },
                            onClick = {
                                activeId = identity.id
                                vault.activeIdentityId = identity.id
                                identityMenuOpen = false
                            },
                        )
                    }
                }
            }
            Text(
                "The active identity is the default \"encrypt to self\" recipient and the first tried when decrypting.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        HorizontalDivider()

        OutlinedButton(onClick = { vm.lock() }, modifier = Modifier.fillMaxWidth()) { Text("Lock vault now") }

        if (vm.error != null) {
            Text(vm.error!!, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }

        HorizontalDivider()

        // About
        SectionLabel("About")
        AboutRow("Version", versionName)
        LinkRow("Website") { openUrl("https://agepony.com") }
        LinkRow("Source code") { openUrl("https://github.com/norsehorse-dev/AgePonyAndroid") }
        LinkRow("age spec") { openUrl("https://age-encryption.org/v1") }
        AboutRow("Made by", "NorseHorse")

        HorizontalDivider()

        // More from NorseHorse — the sibling apps, each linking to its product
        // site. AgePony itself is omitted since this is it. Mirrors PGPony's
        // section; kept to product sites only (no store links) so it's identical
        // in the foss and play flavors.
        SectionLabel("More from NorseHorse")
        MoreRow("All Pony apps", "The whole family at pony.norsehor.se") { openUrl("https://pony.norsehor.se") }
        MoreRow("QuorumPony", "Split a secret into cards. Any few rebuild it.") { openUrl("https://quorumpony.com") }
        MoreRow("CarrierPony", "Private messaging and file transfer, sealed end to end") { openUrl("https://carrierpony.com") }
        MoreRow("BurnPony", "Send a secret. Encrypted on your phone, burned after reading") { openUrl("https://burnpony.app") }
        MoreRow("VaultPony", "VeraCrypt-compatible encrypted vaults, entirely on your device") { openUrl("https://vaultpony.app") }
        MoreRow("PassPony", "Your pass and passage store, in your pocket") { openUrl("https://passpony.app") }
        MoreRow("RelayPony", "Encrypted file transfer, phone to phone") { openUrl("https://relaypony.app") }

        HorizontalDivider()

        // Help & feedback
        SectionLabel("Help & feedback")
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onReplayOnboarding() }
                .padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "Replay the intro",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            Text(
                "Show ↗",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        Text(
            "Walk through what AgePony does and how your keys stay private on this device.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ActionRow(label = "Rate AgePony", trailing = "Open ↗", onClick = { ReviewPrompt.openRating(context) })
        Text(
            "If AgePony has been useful, a rating helps other people find it.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ActionRow(label = "Send feedback", trailing = "Email ↗", onClick = { sendFeedback() })
        Text(
            "Found a bug or have an idea? This opens an email to NorseHorse with your app and device details filled in.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        HorizontalDivider()

        // Danger zone
        SectionLabel("Danger zone")
        TextButton(onClick = { pendingReset = true }) {
            Text("Reset AgePony", color = MaterialTheme.colorScheme.error)
        }
        Text(
            "Erases all stored identities, recipients, and notes. Files you've already saved outside AgePony are untouched. This cannot be undone.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 24.dp),
        )
    }

    if (pendingReset) {
        AlertDialog(
            onDismissRequest = { pendingReset = false },
            title = { Text("Reset AgePony?") },
            text = {
                Text(
                    "This deletes every identity, recipient, and encrypted note in the vault. " +
                        "Files already saved outside AgePony are unaffected. This cannot be undone."
                )
            },
            confirmButton = {
                TextButton(onClick = { pendingReset = false; vm.reset() }) {
                    Text("Reset", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingReset = false }) { Text("Cancel") }
            },
        )
    }

    if (showSetPassword) {
        SetSecretDialog(
            title = "Set a password or PIN",
            allowKindChoice = true,
            onConfirm = { secret, kind ->
                vm.enrollPassword(secret, kind)
                showSetPassword = false
            },
            onDismiss = { showSetPassword = false },
        )
    }

    if (showSetDuress) {
        SetSecretDialog(
            title = "Set a duress password",
            allowKindChoice = false,
            confirmLabel = "Set duress",
            body = "Enter a second password, different from your real one. Entering it at " +
                "unlock wipes the vault silently. Choose something you can recall under " +
                "pressure but would not use by habit.",
            onConfirm = { secret, _ ->
                vm.setDuressSecret(secret)
                showSetDuress = false
            },
            onDismiss = { showSetDuress = false },
        )
    }
}

@Composable
private fun SetSecretDialog(
    title: String,
    allowKindChoice: Boolean,
    confirmLabel: String = "Save",
    body: String? = null,
    onConfirm: (CharArray, String) -> Unit,
    onDismiss: () -> Unit,
) {
    var kind by remember { mutableStateOf("password") }
    var value by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    val isPin = kind == "pin"
    val mismatch = again.isNotEmpty() && value != again
    val valid = value.isNotEmpty() && value == again

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                if (body != null) {
                    Text(body, style = MaterialTheme.typography.bodyMedium)
                }
                if (allowKindChoice) {
                    Row(modifier = Modifier.padding(top = 8.dp)) {
                        TextButton(onClick = { kind = "password" }) {
                            Text("Password", color = if (!isPin) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        TextButton(onClick = { kind = "pin" }) {
                            Text("PIN", color = if (isPin) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
                val kb = KeyboardOptions(keyboardType = if (isPin) KeyboardType.NumberPassword else KeyboardType.Password)
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    singleLine = true,
                    label = { Text(if (isPin) "PIN" else "Password") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = kb,
                    modifier = Modifier.padding(top = 8.dp),
                )
                OutlinedTextField(
                    value = again,
                    onValueChange = { again = it },
                    singleLine = true,
                    label = { Text("Confirm") },
                    isError = mismatch,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = kb,
                    modifier = Modifier.padding(top = 8.dp),
                )
                if (mismatch) {
                    Text("They don't match.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(value.toCharArray(), kind) }, enabled = valid) {
                Text(confirmLabel)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 4.dp),
    )
}

@Composable
private fun SettingRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange, enabled = enabled)
    }
}

@Composable
private fun LockModeRow(
    selected: Boolean,
    title: String,
    subtitle: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick, enabled = enabled)
        Column(Modifier.weight(1f).padding(start = 4.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun AboutRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun LinkRow(label: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text("Open ↗", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
    }
}

@Composable
private fun MoreRow(title: String, subtitle: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text("Open ↗", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
    }
}

@Composable
private fun ActionRow(label: String, trailing: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text(trailing, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
    }
}
