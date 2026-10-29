// HelpScreen.kt
// AgePony Android 4.2.0
//
// In-app FAQ. Plain-language answers to the questions testers actually ask,
// so the app can answer them without an email round-trip. Reached from
// Settings, Help & feedback.

package com.agepony.app.ui.settings

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.agepony.app.R
import com.agepony.app.ui.components.AgeScreen

private data class Qa(@StringRes val q: Int, @StringRes val a: Int)

private val FAQ = listOf(
    Qa(R.string.settings_help_what_q, R.string.settings_help_what_a),
    Qa(R.string.settings_help_recipient_q, R.string.settings_help_recipient_a),
    Qa(R.string.settings_help_choice_q, R.string.settings_help_choice_a),
    Qa(R.string.settings_help_armor_q, R.string.settings_help_armor_a),
    Qa(R.string.settings_help_archive_q, R.string.settings_help_archive_a),
    Qa(R.string.settings_help_compat_q, R.string.settings_help_compat_a),
    Qa(R.string.settings_help_lose_q, R.string.settings_help_lose_a),
    Qa(R.string.settings_help_pq_q, R.string.settings_help_pq_a),
    Qa(R.string.settings_help_sign_q, R.string.settings_help_sign_a),
)

@Composable
fun HelpScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    AgeScreen(title = stringResource(R.string.settings_help), modifier = modifier, onBack = onBack) { padding ->
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Text(
            stringResource(R.string.settings_help_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 16.dp),
        )
        FAQ.forEach { item ->
            Text(stringResource(item.q), style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
            Text(stringResource(item.a), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(
            stringResource(R.string.settings_help_footer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 24.dp, bottom = 24.dp),
        )
    }
    }
}
