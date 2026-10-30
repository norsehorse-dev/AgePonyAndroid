package com.agepony.app.ui.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.agepony.app.R
import com.agepony.app.i18n.AppLanguage
import com.agepony.app.i18n.AppLanguageOption
import com.agepony.app.ui.components.AgeScreen
import com.agepony.app.ui.components.ListDivider
import com.agepony.app.ui.components.RadioRow
import com.agepony.app.ui.components.SectionFooter

/**
 * Settings, Language. Each language is listed by its own name. Picking one switches the app
 * in place (see [AppLanguage]); this screen stays open and redraws in the new language.
 */
@Composable
fun LanguageScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    AgeScreen(title = stringResource(R.string.settings_language), modifier = modifier, onBack = onBack) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
        ) {
            LanguageOptions()
            SectionFooter(stringResource(R.string.settings_language_footer))
        }
    }
}

/** The language rows: "System default", then each language by its own name. Shared with onboarding. */
@Composable
fun LanguageOptions(modifier: Modifier = Modifier) {
    val chosen by AppLanguage.chosen
    Column(modifier) {
        RadioRow(
            title = stringResource(R.string.settings_language_system),
            selected = chosen == null,
            onClick = { AppLanguage.set(null) },
        )
        ListDivider()
        AppLanguageOption.entries.forEach { option ->
            RadioRow(
                title = option.nativeName,
                selected = chosen == option.tag,
                onClick = { AppLanguage.set(option) },
            )
        }
    }
}

