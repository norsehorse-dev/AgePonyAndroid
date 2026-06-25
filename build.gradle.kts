// AgePonyAndroid root build script.
// Repositories are centralized in settings.gradle.kts.
//
// Both modules use the Android Gradle Plugin with AGP 9.2's built-in Kotlin:
//   - :app          -> com.android.application
//   - :agepony-core -> com.android.library
// There is deliberately NO standalone kotlin("jvm") plugin anywhere. Under AGP 9
// a separate kotlin("jvm") module on the shared build classpath forces KGP to
// create a KotlinAndroidTarget that references com.android.build.gradle.api.
// BaseVariant, an API AGP 9.0 removed with no opt-back-in. Keeping every module
// on AGP built-in Kotlin avoids that entirely. Everything is Kotlin 2.2.10
// (the version AGP 9.2.0 bundles).
//
// The Compose and kotlinx.serialization compiler plugins are applied at the
// Kotlin version; both are first-party Kotlin compiler plugins (NOT KSP), which
// is why they cooperate with AGP built-in Kotlin where KSP currently does not.

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}
