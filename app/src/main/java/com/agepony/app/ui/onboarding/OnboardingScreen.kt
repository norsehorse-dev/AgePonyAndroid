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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Create
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

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

private data class OnboardingPage(
    val icon: ImageVector,
    val title: String,
    val body: String,
)

private fun onboardingPages(): List<OnboardingPage> = listOf(
    OnboardingPage(
        icon = Icons.Filled.Lock,
        title = "Welcome to AgePony",
        body = "AgePony encrypts files, text, and notes with the modern age " +
            "encryption standard. Everything happens right here on your device.",
    ),
    OnboardingPage(
        icon = Icons.Filled.Person,
        title = "Your identity, your keys",
        body = "An identity is your personal keypair. The private key is sealed " +
            "in your vault and never leaves this device. Create one on the " +
            "Identities tab to start encrypting.",
    ),
    OnboardingPage(
        icon = Icons.Filled.Send,
        title = "Encrypt for anyone",
        body = "Add recipients by their public key or GitHub username. Encrypt " +
            "to one person or many at once, and to yourself so you can always " +
            "open your own files.",
    ),
    OnboardingPage(
        icon = Icons.Filled.Create,
        title = "Files, Text, and Notes",
        body = "Encrypt and decrypt files from the Files tab, scramble short " +
            "messages on the Text tab, and keep private notes locked behind " +
            "your vault.",
    ),
    OnboardingPage(
        icon = Icons.Filled.Info,
        title = "Private by design",
        body = "No accounts. No servers. No tracking. Your vault is sealed on " +
            "this device and opened only by your biometric or device passcode. " +
            "Your keys and your data stay with you.",
    ),
)

@Composable
fun OnboardingScreen(onFinish: () -> Unit) {
    val pages = remember { onboardingPages() }
    val pagerState = rememberPagerState(pageCount = { pages.size })
    val scope = rememberCoroutineScope()
    val onLastPage = pagerState.currentPage == pages.lastIndex

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
        ) {
            // Skip is available on every page except the last, where the primary
            // button reads "Get started" and finishes. Keep the row height stable
            // so slides don't shift when Skip hides.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (!onLastPage) {
                    TextButton(onClick = onFinish) { Text("Skip") }
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
                Text(if (onLastPage) "Get started" else "Next")
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
        Box(
            modifier = Modifier
                .size(96.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primary),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = page.icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onPrimary,
                modifier = Modifier.size(48.dp),
            )
        }
        Spacer(Modifier.height(32.dp))
        Text(
            text = page.title,
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.primary,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = page.body,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onBackground,
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
