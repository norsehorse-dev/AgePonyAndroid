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
    @StringRes val title: Int,
    @StringRes val body: Int,
)

private fun onboardingPages(): List<OnboardingPage> = listOf(
    OnboardingPage(
        title = R.string.app_welcome_title,
        body = R.string.app_onboarding_welcome_body,
    ),
    OnboardingPage(
        title = R.string.app_onboarding_identity_title,
        body = R.string.app_onboarding_identity_body,
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
fun OnboardingScreen(onFinish: () -> Unit) {
    val pages = remember { onboardingPages() }
    val pagerState = rememberPagerState(pageCount = { pages.size })
    val scope = rememberCoroutineScope()
    val onLastPage = pagerState.currentPage == pages.lastIndex
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
                PageContent(pages[page])
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
private fun PageContent(page: OnboardingPage) {
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
