package com.agepony.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.agepony.app.review.ReviewPrompt
import com.agepony.app.ui.files.FilesScreen
import com.agepony.app.ui.identities.IdentitiesScreen
import com.agepony.app.ui.notes.NotesScreen
import com.agepony.app.ui.onboarding.OnboardingScreen
import com.agepony.app.ui.text.TextScreen
import com.agepony.app.ui.settings.SettingsScreen
import com.agepony.app.vault.Vault
import com.agepony.app.vault.VaultViewModel

// Fresh launches required before the in-app review nudge may fire (Phase 2f).
private const val REVIEW_PROMPT_MIN_LAUNCHES = 3

/**
 * Root composable: a Scaffold with a bottom NavigationBar over the five tabs.
 * Selected tab survives configuration changes via rememberSaveable (AgeTab is
 * an enum, so the default Bundle-backed saver handles it).
 *
 * Phase 2c wires the Identities and Files tabs to their real screens; the other
 * tabs remain placeholders until their phases land.
 */
@Composable
fun AgePonyApp(vm: VaultViewModel) {
    val vault: Vault = vm.vault
    var selectedTab by rememberSaveable { mutableStateOf(AgeTab.FILES) }

    // First-run walkthrough (Phase 2e). Shown once after the vault is created,
    // tracked by the previously-unused Vault.hasCompletedOnboarding pref, and
    // re-openable from Settings. Replaying only flips this transient state, not
    // the pref, so it won't re-trigger on the next cold launch.
    var showOnboarding by rememberSaveable { mutableStateOf(!vault.hasCompletedOnboarding) }
    if (showOnboarding) {
        OnboardingScreen(
            onFinish = {
                vault.hasCompletedOnboarding = true
                showOnboarding = false
            }
        )
        return
    }

    // In-app review nudge (Phase 2f): fire Play's review flow at most once, after
    // the user has come back a few times, and only past onboarding. Best-effort —
    // Play may show nothing. The explicit Settings "Rate AgePony" button is the
    // reliable path; this is the contextual "nudge" the testers asked for.
    val activity = LocalContext.current as FragmentActivity
    LaunchedEffect(Unit) {
        if (!vault.reviewPromptShown && vault.launchCount >= REVIEW_PROMPT_MIN_LAUNCHES) {
            vault.reviewPromptShown = true
            ReviewPrompt.request(activity)
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            NavigationBar {
                AgeTab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = selectedTab == tab,
                        onClick = { selectedTab = tab },
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label) },
                    )
                }
            }
        },
    ) { innerPadding ->
        when (selectedTab) {
            AgeTab.IDENTITIES -> IdentitiesScreen(
                vault = vault,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            )

            AgeTab.FILES -> FilesScreen(
                vault = vault,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            )

            AgeTab.NOTES -> NotesScreen(
                vault = vault,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            )

            AgeTab.TEXT -> TextScreen(
                vault = vault,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            )

            AgeTab.SETTINGS -> SettingsScreen(
                vm = vm,
                onReplayOnboarding = { showOnboarding = true },
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            )

            else -> PlaceholderTabContent(
                tab = selectedTab,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            )
        }
    }
}

@Composable
private fun PlaceholderTabContent(tab: AgeTab, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = tab.label,
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.primary,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = placeholderBlurb(tab),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

private fun placeholderBlurb(tab: AgeTab): String = when (tab) {
    AgeTab.FILES -> "Encrypt and decrypt files. Lands in Phase 2c."
    AgeTab.NOTES -> "Encrypted notes with per-note passphrases. Lands in Phase 2d."
    AgeTab.TEXT -> "Encrypt and decrypt text, armor always on. Lands in Phase 2d."
    AgeTab.IDENTITIES -> "Manage identities and saved recipients. Lands in Phase 2c."
    AgeTab.SETTINGS -> "App settings. Lands in Phase 2d."
}
