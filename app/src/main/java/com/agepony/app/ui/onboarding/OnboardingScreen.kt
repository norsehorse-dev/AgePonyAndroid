package com.agepony.app.ui.onboarding

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.annotation.StringRes
import androidx.compose.ui.res.stringResource
import com.agepony.app.R
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import com.agepony.app.ui.settings.LanguageOptions
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.pluralStringResource
import com.agepony.app.ui.components.QuietAction
import com.agepony.app.ui.components.SecondaryAction
import com.agepony.app.ui.identities.AddIdentityFlow
import com.agepony.app.ui.identities.AddIdentityStage
import com.agepony.app.ui.portability.PaperRestoreScreen
import com.agepony.app.ui.portability.ReceiveKeysScreen
import com.agepony.app.vault.Vault

//
// First-run dynamic walkthrough (Phase 2e). Shown once after the vault is first
// created/unlocked, and re-openable from Settings ("Replay the intro"). This is
// the Android answer to the testers' "User Onboarding Dynamic Walkthrough" item,
// and also carries the "Educational Content" and "Enhanced Security Messaging"
// recommendations in the slide copy (what age is, where keys live, no servers).
//
// A horizontal pager of slides with swipe, page dots, a per-page Next button,
// and a Skip affordance on every page except the last (where the primary button
// finishes). Completion is recorded by the caller via Vault.hasCompletedOnboarding,
// so this composable stays free of persistence concerns. There is no iOS share
// intent equivalent to mirror here; the iOS counterpart is the SwiftUI
// OnboardingView paged TabView.
//

// No hero icon on the slides (5.1.0, U4): the title and text carry the page, as on iOS.
private data class OnboardingPage(
    @param:StringRes val title: Int,
    @param:StringRes val body: Int,
    /** 5.2.0: the first page picks the app language, so the rest of the tour reads in it. */
    val languagePicker: Boolean = false,
    /** 5.2.0: the identity page offers to generate, import, receive or restore a key. */
    val identityActions: Boolean = false,
)

/** Where an identity-page action leads: a full-screen flow over the tour, which resumes after. */
private enum class OnboardingAction { GENERATE, IMPORT, RECEIVE, PAPER }

private fun onboardingPages(): List<OnboardingPage> = listOf(
    OnboardingPage(
        title = R.string.settings_language,
        body = R.string.settings_language_footer,
        languagePicker = true,
    ),
    OnboardingPage(
        title = R.string.app_welcome_title,
        body = R.string.app_onboarding_welcome_body,
    ),
    OnboardingPage(
        title = R.string.app_onboarding_identity_title,
        body = R.string.app_onboarding_identity_body,
        identityActions = true,
    ),
    OnboardingPage(
        title = R.string.app_onboarding_recipients_title,
        body = R.string.app_onboarding_recipients_body,
    ),
    OnboardingPage(
        title = R.string.app_onboarding_files_title,
        body = R.string.app_onboarding_files_body,
    ),
    OnboardingPage(
        title = R.string.app_onboarding_private_title,
        body = R.string.app_onboarding_private_body,
    ),
)

@Composable
fun OnboardingScreen(vault: Vault, onFinish: () -> Unit) {
    val pages = remember { onboardingPages() }
    val pagerState = rememberPagerState(pageCount = { pages.size })
    val scope = rememberCoroutineScope()
    val onLastPage = pagerState.currentPage == pages.lastIndex

    // An identity-page action covers the tour until it finishes or is backed out of. When the
    // vault holds an identity afterwards, the tour moves on to the next page, as PGPony's does.
    var action by rememberSaveable { mutableStateOf<OnboardingAction?>(null) }
    var advanceAfterAction by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(action, advanceAfterAction) {
        if (action == null && advanceAfterAction) {
            advanceAfterAction = false
            if (vault.identities.isNotEmpty() && pagerState.currentPage < pages.lastIndex) {
                pagerState.animateScrollToPage(pagerState.currentPage + 1)
            }
        }
    }
    fun closeAction() {
        action = null
        advanceAfterAction = true
    }
    when (action) {
        OnboardingAction.GENERATE, OnboardingAction.IMPORT -> {
            AddIdentityFlow(
                vault = vault,
                modifier = Modifier.fillMaxSize(),
                onDone = { closeAction() },
                onCancel = { action = null },
                initialStage = if (action == OnboardingAction.GENERATE) AddIdentityStage.GENERATE else AddIdentityStage.IMPORT,
            )
            return
        }
        OnboardingAction.RECEIVE -> { ReceiveKeysScreen(vault = vault, onBack = { closeAction() }); return }
        OnboardingAction.PAPER -> { PaperRestoreScreen(vault = vault, onBack = { closeAction() }); return }
        null -> {}
    }
    // System back leaves the walkthrough (same as Skip) instead of closing the app.
    BackHandler(onBack = onFinish)

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .systemBarsPadding()
                .padding(horizontal = 24.dp, vertical = 16.dp),
        ) {
            // Skip is available on every page except the last, where the primary
            // button reads "Done" and finishes. Keep the row height stable
            // so slides don't shift when Skip hides.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (!onLastPage) {
                    TextButton(onClick = onFinish) { Text(stringResource(R.string.app_onboarding_skip)) }
                }
            }

            HorizontalPager(
                state = pagerState,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            ) { page ->
                PageContent(pages[page], vault = vault, onAction = { action = it })
            }

            PageIndicator(
                count = pages.size,
                selected = pagerState.currentPage,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 24.dp),
            )

            Button(
                onClick = {
                    if (onLastPage) {
                        onFinish()
                    } else {
                        scope.launch {
                            pagerState.animateScrollToPage(pagerState.currentPage + 1)
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(if (onLastPage) R.string.app_done else R.string.app_onboarding_next))
            }
        }
    }
}

@Composable
private fun PageContent(page: OnboardingPage, vault: Vault, onAction: (OnboardingAction) -> Unit) {
    if (page.identityActions) {
        IdentityPage(page, vault, onAction)
        return
    }
    if (page.languagePicker) {
        // Taller than the other pages, so it scrolls instead of centring.
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 8.dp, vertical = 16.dp),
        ) {
            Text(
                text = stringResource(page.title),
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = stringResource(page.body),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(16.dp))
            LanguageOptions()
        }
        return
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 8.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(page.title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(page.body),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun PageIndicator(count: Int, selected: Int, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        repeat(count) { index ->
            val active = index == selected
            Box(
                modifier = Modifier
                    .padding(horizontal = 4.dp)
                    .size(width = if (active) 24.dp else 8.dp, height = 8.dp)
                    .clip(CircleShape)
                    .background(
                        if (active) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f)
                        }
                    ),
            )
        }
    }
}

/**
 * The identity page: what an identity is, then the ways to get one (5.2.0, after PGPony's key
 * slide). Generate covers every kind the Identities tab can make (age, quantum-safe, hardware
 * decryption, SSH, hardware signing, security key); import takes an age, OpenSSH or YubiKey
 * identity; receive and paper restore bring keys from another phone or a backup. On a replay with
 * identities already in the vault, the page says how many instead of pushing more.
 */
@Composable
private fun IdentityPage(page: OnboardingPage, vault: Vault, onAction: (OnboardingAction) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 8.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(page.title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(page.body),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        val count = vault.identities.size
        if (count > 0) {
            Text(
                text = pluralStringResource(R.plurals.onboarding_identity_count, count, count),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
                textAlign = TextAlign.Center,
            )
        } else {
            SecondaryAction(
                text = stringResource(R.string.identities_generate_new),
                onClick = { onAction(OnboardingAction.GENERATE) },
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(4.dp))
            QuietAction(
                text = stringResource(R.string.identities_import_existing),
                onClick = { onAction(OnboardingAction.IMPORT) },
                modifier = Modifier.fillMaxWidth(),
            )
            QuietAction(
                text = stringResource(R.string.settings_receive_keys),
                onClick = { onAction(OnboardingAction.RECEIVE) },
                modifier = Modifier.fillMaxWidth(),
            )
            QuietAction(
                text = stringResource(R.string.settings_paper_restore),
                onClick = { onAction(OnboardingAction.PAPER) },
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
