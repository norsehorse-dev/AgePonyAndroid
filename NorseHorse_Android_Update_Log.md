# NorseHorse Android Update Log — AgePony

Running log of shipped Android updates for the AgePony port. One section per shipped
update. Format per entry: **user-visible** / **Android impl** / **iOS port notes** /
**files touched + iOS counterparts**.

---

## Phase 2a — App module + build graph + theme + 5-tab nav shell
**Shipped:** 2026-05-30 · Status: green build, 200 core tests passing, APK runs in emulator

### User-visible
- The app now launches to a five-tab bottom navigation bar: **Files · Notes · Text ·
  Identities · Settings**. Each tab shows a placeholder screen describing what will live
  there. Selected tab survives rotation.
- Cyan-teal brand look applied app-wide (cyan-light `#38CFE8`, teal-core `#14B8B0`,
  teal-deep `#0E7D7A`, teal-ink `#0A4F4D`), edge-to-edge with transparent system bars,
  light + dark color schemes. Dynamic (Material You) color is deliberately off so the
  brand palette is consistent across devices.

### Android impl
- New `:app` module wired on top of the previously shipped `:agepony-core` crypto module
  (Bouncy Castle stack, 200 JUnit 5 tests). `app` depends on `core` via
  `implementation(project(":agepony-core"))`.
- UI is Jetpack Compose + Material3: `Scaffold` + `NavigationBar`, tabs modeled by an
  `AgeTab` enum (label + `ImageVector`), selected index held in `rememberSaveable`.
- **Build toolchain — the load-bearing decisions (do not regress):**
  - Whole project is on **AGP 9.2.0** with **Gradle wrapper 9.4.1** and **Kotlin 2.2.10**
    (the Kotlin version AGP 9.2.0 bundles — verified from its POM). Compose BOM
    **2026.01.00** pairs with Kotlin 2.2.x.
  - **AGP built-in Kotlin is used everywhere.** Do NOT apply the classic
    `org.jetbrains.kotlin.android` plugin — its `KotlinAndroidTarget` references
    `com.android.build.gradle.api.BaseVariant`, which AGP 9.0 removed with no opt-back-in
    (`android.enableLegacyVariantApi` is gone and hard-errors).
  - **`:agepony-core` is a `com.android.library` module, NOT `kotlin("jvm")`.** A
    standalone `kotlin("jvm")` module on the same build classpath forces KGP to create a
    `KotlinAndroidTarget` (the `BaseVariant` crash) the moment any Android plugin applies.
    Making core an Android library keeps the entire build on AGP built-in Kotlin with no
    standalone Kotlin plugin anywhere. Crypto source, BC dependency, and tests are
    unchanged — only the module type changed. Core unit tests now run via
    `:agepony-core:testDebugUnitTest` (JUnit Platform enabled through
    `testOptions { unitTests.all { it.useJUnitPlatform() } }`).
  - Compose still applies `org.jetbrains.kotlin.plugin.compose` at the Kotlin version; the
    Compose compiler plugin handles Compose↔Kotlin compatibility automatically.
  - **Material Icons are a separate artifact.** material3 does not pull
    `androidx.compose.material:material-icons-core` transitively anymore — it is added
    explicitly (BOM-managed version). `Icons.AutoMirrored.Filled.List` is the correct
    post-migration form for the auto-mirroring list icon.
  - `gradle.properties` carries no legacy flags (built-in Kotlin + new DSL are the
    defaults). New Android DSL is used throughout (`compileSdk { version = release(36)
    { minorApiLevel = 1 } }`). Min SDK 26, target/compile SDK 36, JVM target 17.
- **Runtime note for later (not relevant to build/tests):** Android ships its own older
  Bouncy Castle. Once crypto actually runs on a device, the app must register the bundled
  BC 1.78.1 provider at startup (remove the platform `BC` provider, add the bundled one).
  Unit tests run on the JVM and use the dependency BC directly, so this does not affect
  Phase 2a.

### iOS port notes
- Parity target: iOS Phase 1c (the tab scaffold + design-system colors). The five tabs and
  their order mirror the iOS `TabView`. The Android "share extension" is not a separate
  target — it will be `ACTION_SEND` / `ACTION_VIEW` intent filters on `MainActivity`
  (handled in a later phase).
- Palette mirrors the iOS `AgePonyColors` cyan-teal values; a full diff of
  `AgePonyColors.swift` against `Color.kt` is queued for Phase 2b.

### Files touched + iOS counterparts
- `app/src/main/java/com/agepony/app/MainActivity.kt` — edge-to-edge host, sets
  `AgePonyTheme { AgePonyApp() }`. iOS: app entry / `@main` App + root `TabView`.
- `app/src/main/java/com/agepony/app/ui/AgePonyApp.kt` — `Scaffold` + `NavigationBar`,
  placeholder content. iOS: root `TabView` container.
- `app/src/main/java/com/agepony/app/ui/AgeTab.kt` — tab enum (label + icon). iOS: tab
  enum / `TabView` item definitions.
- `app/src/main/java/com/agepony/app/ui/theme/Color.kt` — brand cyan-teal values. iOS:
  `DesignSystem/AgePonyColors.swift`.
- `app/src/main/java/com/agepony/app/ui/theme/Theme.kt` — light/dark color schemes,
  dynamic color off. iOS: color scheme / appearance setup.
- `app/src/main/res/values/colors.xml`, `themes.xml` — `teal_ink` window background,
  transparent system bars.
- Build config: root `build.gradle.kts`, `settings.gradle.kts`, `gradle.properties`,
  `gradle/libs.versions.toml`, `app/build.gradle.kts`,
  `agepony-core/build.gradle.kts` (converted to `com.android.library`).

---

## Phase 2e — First-run onboarding walkthrough + in-app education
**Shipped:** 2026-06-09 · Status: additive, build graph unchanged except one BOM-managed dep

### User-visible
- On the very first launch after creating the vault, AgePony now shows a five-slide
  **walkthrough**: Welcome (what age encryption is) · Identities (your keypair lives only
  on this device) · Recipients (encrypt by public key or GitHub username, and to yourself) ·
  Files/Text/Notes (what each tab does) · Private by design (no accounts, no servers, no
  tracking; vault sealed by biometric/passcode). Swipe or tap **Next**; **Skip** is on every
  slide except the last; page dots show progress.
- The walkthrough is re-openable anytime from **Settings → Help → Replay the intro**, so it
  doubles as in-app educational content. Resolves the testers' "User Onboarding Dynamic
  Walkthrough" item and folds in the "Educational Content" and "Enhanced Security Messaging"
  recommendations via the slide copy.

### Android impl
- New `OnboardingScreen.kt` under `ui/onboarding`: a `HorizontalPager` (foundation) of
  `OnboardingPage` slides (icon + title + body), with `rememberPagerState(pageCount = { … })`,
  `animateScrollToPage` on Next, a dot `PageIndicator`, and a height-stable Skip row so slides
  don't jump when Skip hides on the last page. Icons are all material-icons-core
  (`Lock`, `Person`, `Send`, `Create`, `Info`) — no extended icon dependency added.
- `AgePonyApp.kt` gates the walkthrough in front of the tab `Scaffold`: `showOnboarding` is a
  `rememberSaveable` initialized from the previously-unused `Vault.hasCompletedOnboarding`
  pref. On finish/skip it sets the pref `true` and drops the overlay. Settings can re-open it
  via a new `onReplayOnboarding` callback (replay flips only the transient state, never the
  pref, so it does not re-trigger on the next cold launch).
- `SettingsScreen.kt` gains an optional `onReplayOnboarding: () -> Unit = {}` param (default
  keeps any other call sites valid) and a new **Help** section with the "Replay the intro"
  action row.
- Build graph: added `androidx.compose.foundation:foundation` (BOM-managed, no version pin) to
  the catalog and `:app` deps — it is the same artifact material3 already pulls transitively,
  added explicitly so the pager API is self-documented. No Kotlin-plugin or module-type
  changes; the AGP-built-in-Kotlin setup from Phase 2a is untouched.
- Build fix folded in: enabled `isCoreLibraryDesugaringEnabled = true` in `:app` and added
  `coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")` (same version `:agepony-core`
  uses). `:agepony-core` enables desugaring with `minSdk 21`, so its AAR metadata requires every
  consumer to enable it too; `:app` had not, which failed `checkReleaseAarMetadata` on the first
  release/AAB build. Pre-existing gap, not introduced by 2e.

### iOS port notes
- iOS counterpart is a paged `TabView` `OnboardingView` gated on a `hasCompletedOnboarding`
  `@AppStorage`/UserDefaults flag, presented after the launch gate and re-openable from
  `SettingsView`. The five slides and their copy mirror this Android set verbatim. There is
  no share-intent surface involved, so nothing maps to the iOS share extension here.

### Files touched + iOS counterparts
- `app/src/main/java/com/agepony/app/ui/onboarding/OnboardingScreen.kt` (new) — iOS:
  `Onboarding/OnboardingView.swift`.
- `app/src/main/java/com/agepony/app/ui/AgePonyApp.kt` — onboarding gate + replay wiring. iOS:
  root view that presents `OnboardingView` over the `TabView`.
- `app/src/main/java/com/agepony/app/ui/settings/SettingsScreen.kt` — Help section + replay
  callback. iOS: `SettingsView` "Replay the intro" row.
- `gradle/libs.versions.toml`, `app/build.gradle.kts` — explicit foundation dep. iOS: n/a.
- Pref hook reused: `Vault.hasCompletedOnboarding` (already present since the vault was first
  built; previously unwired). iOS: `hasCompletedOnboarding` UserDefaults flag.

---

## Phase 2f — Rate AgePony + in-app feedback + UI/UX polish
**Shipped:** 2026-06-09 · Status: additive, layers on Phase 2e · versionCode 3 / versionName 1.0

### User-visible
- **Settings → Help & feedback** now has two new actions alongside Replay the intro:
  **Rate AgePony** (opens the Play Store listing) and **Send feedback** (opens an email to
  NorseHorse pre-filled with app version and device details).
- **In-app review nudge:** after the user has come back to the app a few times, AgePony quietly
  asks Google to show the native in-app review card. It fires at most once and never on a brand
  new user. Together these cover the testers' "Rate Your App" item (in-app prompt, nudge system,
  feedback option) and the "User Feedback Mechanism" recommendation.
- **UI/UX polish:** the color scheme now defines its secondary-surface, outline, and container
  roles explicitly in both light and dark, so subtitle text, dividers, and containers have
  intentional, accessible contrast on the cyan-teal palette instead of Material's derived
  defaults. Addresses the "UI/UX Improvements" (layout, contrast, consistent design language)
  item.

### Android impl
- **Rate (explicit button)** opens the Play Store listing via `market://details?id=…` with a
  web fallback — per Google's guidance the in-app review API is reserved for programmatic
  nudges, not buttons.
- **In-app review nudge** uses `com.google.android.play:review` 2.0.2 through a small
  `review/ReviewPrompt.kt` wrapper on the stable Task flow (`requestReviewFlow` /
  `launchReviewFlow`), fully best-effort and failure-swallowing. Gating lives in `Vault`:
  `launchCount` (bumped once per fresh process start in `MainActivity`, guarded by
  `savedInstanceState == null` so rotations don't count) and a `reviewPromptShown` latch.
  `AgePonyApp` fires it from a `LaunchedEffect`, past the onboarding gate, when
  `launchCount >= 3` and not yet shown.
- **Feedback** is an `ACTION_SENDTO` `mailto:` to the public `NorseHorse@norsehor.se`, subject
  carries the app version, body pre-fills `Build.MANUFACTURER/MODEL` and Android version.
- **Theme** gains explicit `surfaceVariant`/`onSurfaceVariant`/`outline`/`outlineVariant` (both
  schemes) plus `primaryContainer`/`onPrimaryContainer`, backed by new named tokens in
  `Color.kt`. No change to the brand primaries.
- Settings adds a reusable `ActionRow(label, trailing, onClick)` beside the existing `LinkRow`;
  the 2e "Help" section is renamed "Help & feedback". `versionCode` 2 → 3.

### iOS port notes
- Rate button → `SKStoreReviewController` is for nudges, so the iOS Rate button opens the App
  Store via `SKStoreProductViewController`/`https://apps.apple.com/...?action=write-review`.
  The nudge maps to `SKStoreReviewController.requestReview(in:)` gated on the same launch
  counter (`launchCount`/`reviewPromptShown` in `@AppStorage`). Feedback maps to an `MFMailComposeViewController`
  (or `mailto:` fallback) to `NorseHorse@norsehor.se` with the same version/device prefill.
  Color-role additions mirror into `AgePonyColors.swift` secondary/outline/container roles.

### Files touched + iOS counterparts
- `app/src/main/java/com/agepony/app/review/ReviewPrompt.kt` (new) — iOS:
  `Review/ReviewPrompt.swift` (`SKStoreReviewController`).
- `app/src/main/java/com/agepony/app/vault/Vault.kt` — launchCount + reviewPromptShown prefs.
  iOS: `@AppStorage` counters.
- `app/src/main/java/com/agepony/app/MainActivity.kt` — fresh-launch counter bump. iOS: app
  launch hook.
- `app/src/main/java/com/agepony/app/ui/AgePonyApp.kt` — nudge `LaunchedEffect`. iOS: root view
  `.onAppear` nudge.
- `app/src/main/java/com/agepony/app/ui/settings/SettingsScreen.kt` — Rate + feedback rows,
  Play Store and mailto intents, `ActionRow`. iOS: `SettingsView` rows.
- `app/src/main/java/com/agepony/app/ui/theme/Color.kt`, `Theme.kt` — explicit secondary/outline/
  container color roles. iOS: `AgePonyColors.swift`.
- `gradle/libs.versions.toml`, `app/build.gradle.kts` — `com.google.android.play:review` 2.0.2;
  versionCode bump. iOS: n/a.

### Requires
- Phase 2e deployed first (this bundle ships the cumulative `AgePonyApp.kt`/`SettingsScreen.kt`
  but not 2e-only files like `OnboardingScreen.kt`).

---
