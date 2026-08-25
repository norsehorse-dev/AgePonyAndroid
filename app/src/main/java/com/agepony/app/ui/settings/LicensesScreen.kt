// LicensesScreen.kt
// AgePony Android 4.3.0
//
// Open-source and third-party notices. AgePony's own age implementation lives
// in agepony-core; the libraries below are what the app builds on. Reached
// from Settings, About. Kept in sync by hand with app/build.gradle.kts.

package com.agepony.app.ui.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

private data class Dep(val name: String, val license: String)

private val DEPS = listOf(
    Dep("Android Jetpack (Core, Lifecycle, Activity, Fragment, Biometric)", "Apache License 2.0"),
    Dep("Jetpack Compose (UI, Foundation, Material 3, Material Icons)", "Apache License 2.0"),
    Dep("CameraX", "Apache License 2.0"),
    Dep("Kotlin standard library", "Apache License 2.0"),
    Dep("kotlinx.serialization", "Apache License 2.0"),
    Dep("ZXing core (QR encoding and decoding)", "Apache License 2.0"),
    Dep("Android core library desugaring (desugar_jdk_libs)", "GNU GPL v2 with the Classpath Exception"),
    Dep("Google Play In-App Review (Play build only, not in the F-Droid build)", "Google Play Core Software Development Kit Terms of Service"),
)

@Composable
fun LicensesScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp),
    ) {
        TextButton(onClick = onBack, modifier = Modifier.padding(top = 8.dp)) { Text("‹ Back") }
        Text("Open-source licenses", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(bottom = 4.dp))
        Text(
            "AgePony is open source, and stands on these projects. Each remains under its own license, and full license texts are available from every project.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 16.dp),
        )
        DEPS.forEach { d ->
            Text(d.name, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 12.dp))
            Text(d.license, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(
            "The age file format and AgePony's own encryption code (agepony-core) are AgePony's, released with the app. See the source link in Settings under About.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 24.dp, bottom = 24.dp),
        )
    }
}
