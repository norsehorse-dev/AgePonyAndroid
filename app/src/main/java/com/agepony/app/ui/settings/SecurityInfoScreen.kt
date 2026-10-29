// SecurityInfoScreen.kt
// AgePony Android 4.2.0
//
// A plain, consolidated account of how AgePony protects your files, and what
// it does not do. The knowledge was scattered across inline hints; this is the
// single trust page. Reached from Settings, Help & feedback.

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

private data class Block(@StringRes val title: Int, @StringRes val body: Int)

private val PROTECTS = listOf(
    Block(R.string.settings_security_device_title, R.string.settings_security_device_body),
    Block(R.string.settings_security_format_title, R.string.settings_security_format_body),
    Block(R.string.settings_security_vault_title, R.string.settings_security_vault_body),
    Block(R.string.settings_security_passphrase_title, R.string.settings_security_passphrase_body),
    Block(R.string.settings_security_duress_title, R.string.settings_security_duress_body),
)

private val NOT_DOING = listOf(
    R.string.settings_security_no_cloud,
    R.string.settings_security_no_recovery,
    R.string.settings_security_no_telemetry,
    R.string.settings_security_no_outside,
)

@Composable
fun SecurityInfoScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    AgeScreen(title = stringResource(R.string.settings_security_info), modifier = modifier, onBack = onBack) { padding ->
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Text(
            stringResource(R.string.settings_security_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 16.dp),
        )
        PROTECTS.forEach { b ->
            Text(stringResource(b.title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
            Text(stringResource(b.body), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(stringResource(R.string.settings_security_not_doing_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 24.dp, bottom = 4.dp))
        NOT_DOING.forEach { line ->
            Text(stringResource(line), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
        }
        Text(
            stringResource(R.string.settings_security_footer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 24.dp, bottom = 24.dp),
        )
    }
    }
}
