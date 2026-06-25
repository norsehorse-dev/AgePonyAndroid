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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.unit.dp
import com.agepony.app.vault.VaultViewModel

//
// Settings tab (expanded in Phase 2d-3a). Android counterpart of iOS's
// SettingsView: security (biometric), encryption default, active identity,
// about, and a guarded reset. The biometric toggle re-wraps the vault key under
// a non-auth keystore key when turned off (see VaultViewModel.applyBiometric).
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

    fun openUrl(url: String) {
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }

    val versionName = remember {
        runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull() ?: "1.0"
    }

    // Explicit "Rate" action: open the Play Store listing directly (Google's
    // guidance is to reserve the in-app review API for programmatic nudges, not
    // buttons). Try the Play app first, fall back to the web listing.
    fun openPlayStore() {
        val id = context.packageName
        val market = Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$id"))
        if (runCatching { context.startActivity(market) }.isFailure) {
            runCatching {
                context.startActivity(
                    Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=$id"))
                )
            }
        }
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
        SettingRow(
            title = "Require biometric to unlock",
            subtitle = if (vm.biometricEnabled) {
                "On — your vault locks on background and needs your fingerprint or device credential."
            } else {
                "Off — the vault unlocks automatically. Convenient for testing; less private."
            },
            checked = vm.biometricEnabled,
            enabled = !vm.isBusy,
            onCheckedChange = { vm.applyBiometric(it) },
        )

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
        LinkRow("age spec") { openUrl("https://age-encryption.org/v1") }
        AboutRow("Made by", "NorseHorse")

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

        ActionRow(label = "Rate AgePony", trailing = "Open ↗", onClick = { openPlayStore() })
        Text(
            "If AgePony has been useful, a rating on the Play Store helps other people find it.",
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
private fun ActionRow(label: String, trailing: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text(trailing, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
    }
}
