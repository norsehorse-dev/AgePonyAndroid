// LicensesScreen.kt
// AgePony Android 4.2.0
//
// Open-source and third-party notices. AgePony's own age implementation lives
// in agepony-core; the libraries below are what the app builds on. Reached
// from Settings, About. Kept in sync by hand with app/build.gradle.kts.

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

// License names stay literal: they are the licenses' own titles, not app copy.
private data class Dep(@StringRes val name: Int, val license: String)

private val DEPS = listOf(
    Dep(R.string.settings_dep_jetpack, "Apache License 2.0"),
    Dep(R.string.settings_dep_compose, "Apache License 2.0"),
    Dep(R.string.settings_dep_camerax, "Apache License 2.0"),
    Dep(R.string.settings_dep_kotlin, "Apache License 2.0"),
    Dep(R.string.settings_dep_serialization, "Apache License 2.0"),
    Dep(R.string.settings_dep_zxing, "Apache License 2.0"),
    Dep(R.string.settings_dep_desugar, "GNU GPL v2 with the Classpath Exception"),
    Dep(R.string.settings_dep_play_review, "Google Play Core Software Development Kit Terms of Service"),
)

@Composable
fun LicensesScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    AgeScreen(title = stringResource(R.string.settings_licenses), modifier = modifier, onBack = onBack) { padding ->
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Text(
            stringResource(R.string.settings_licenses_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 16.dp),
        )
        DEPS.forEach { d ->
            Text(stringResource(d.name), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(top = 12.dp))
            Text(d.license, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(
            stringResource(R.string.settings_licenses_footer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 24.dp, bottom = 24.dp),
        )
    }
    }
}
