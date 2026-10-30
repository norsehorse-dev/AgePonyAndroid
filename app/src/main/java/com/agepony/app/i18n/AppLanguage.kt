package com.agepony.app.i18n

import android.app.LocaleManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.runtime.mutableStateOf
import androidx.core.os.LocaleListCompat

/**
 * The languages AgePony ships, by BCP-47 tag, with the name each one has in its own language
 * (shown as is in the picker, never translated). Keep in step with res/xml/locales_config.xml
 * and the values-* folders.
 */
enum class AppLanguageOption(val tag: String, val nativeName: String) {
    EN("en", "English"),
    DE("de", "Deutsch"),
    ES("es", "Español"),
    FR("fr", "Français"),
    PT_BR("pt-BR", "Português (Brasil)"),
    RU("ru", "Русский"),
    ZH_HANS("zh-Hans", "简体中文");

    companion object {
        /** The option for a stored or system tag, snapping regions ("de-AT", "pt-PT") to ours. */
        fun resolve(tag: String?): AppLanguageOption? {
            if (tag.isNullOrBlank()) return null
            val t = tag.replace('_', '-')
            entries.firstOrNull { it.tag.equals(t, ignoreCase = true) }?.let { return it }
            val parts = t.split('-').map { it.lowercase() }
            return when (parts.first()) {
                "en" -> EN
                "de" -> DE
                "es" -> ES
                "fr" -> FR
                "pt" -> PT_BR
                "ru" -> RU
                // Simplified only: Traditional script or regions keep the English fallback.
                "zh" -> if ("hant" in parts || ("hans" !in parts && parts.any { it == "tw" || it == "hk" || it == "mo" })) null else ZH_HANS
                else -> null
            }
        }
    }
}

/**
 * In-app language choice (Settings, Language). Same approach as PGPony: AppCompat is the only
 * store. On Android 13 and later it writes the system's per-app language (also editable in
 * Android's own app language settings); on 8 to 12 it keeps it in AppLocalesMetadataHolderService.
 *
 * Switching is live. Both activities declare configChanges="locale|layoutDirection", so on
 * Android 13 and later the new language arrives as an in-place configuration change and Compose
 * redraws every stringResource without recreating the activity: no black frame, and the screen
 * the user is on stays open. On 8 to 12 AppCompat recreates the activity; screen state that
 * matters is rememberSaveable so the picker stays open across it.
 */
object AppLanguage {

    /** The chosen tag, or null for "follow the system". Read by the picker for its checkmark. */
    val chosen = mutableStateOf<String?>(null)

    /**
     * Seed [chosen] from the stored choice. Called from Application.onCreate and again from
     * MainActivity.onCreate: AppCompat answers getApplicationLocales() only once an AppCompat
     * activity exists, so on Android 13 and later the system's LocaleManager is read directly.
     */
    fun init(context: Context) {
        val tag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.getSystemService(LocaleManager::class.java)?.applicationLocales?.get(0)?.toLanguageTag()
        } else {
            AppCompatDelegate.getApplicationLocales().get(0)?.toLanguageTag()
        }
        chosen.value = AppLanguageOption.resolve(tag)?.tag
    }

    /** Apply [option], or follow the system when null. */
    fun set(option: AppLanguageOption?) {
        chosen.value = option?.tag
        AppCompatDelegate.setApplicationLocales(
            if (option == null) LocaleListCompat.getEmptyLocaleList()
            else LocaleListCompat.forLanguageTags(option.tag)
        )
    }

    /** The option currently in effect for [context]: the chosen one, else the system's. */
    fun current(context: Context): AppLanguageOption? =
        AppLanguageOption.resolve(chosen.value)
            ?: AppLanguageOption.resolve(context.resources.configuration.locales.get(0)?.toLanguageTag())

    /**
     * [context] in the chosen language, for strings built outside a composable from the
     * application context (view models, the vault). Android 13 and later already give the
     * application context the per-app language; on 8 to 12 AppCompat only localizes activities,
     * so the locale is applied here.
     */
    fun localized(context: Context): Context {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) return context
        val tags = AppCompatDelegate.getApplicationLocales().toLanguageTags()
        if (tags.isEmpty()) return context
        val config = Configuration(context.resources.configuration)
        config.setLocales(LocaleList.forLanguageTags(tags))
        return context.createConfigurationContext(config)
    }
}
