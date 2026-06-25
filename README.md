# AgePonyAndroid — Phase 2f: Rate AgePony + in-app feedback + UI/UX polish

Second of two updates implementing the Testers Community feedback. Covers the
**Rate Your App** item (in-app prompt, nudge, feedback), the **User Feedback Mechanism**
recommendation, and the **UI/UX Improvements** item (contrast, consistent design language).

**Requires Phase 2e deployed first** — this bundle ships the cumulative `AgePonyApp.kt` and
`SettingsScreen.kt` but not 2e-only files like `OnboardingScreen.kt`.

## What's in this update

- **Rate AgePony** in Settings then Help & feedback — opens the Play Store listing.
- **Send feedback** in Settings then Help & feedback — opens an email to NorseHorse pre-filled
  with app version and device details.
- **In-app review nudge** — after a few fresh launches, AgePony asks Google to show the native
  review card, at most once, never on a brand-new user.
- **UI/UX polish** — explicit secondary-surface, outline, and container color roles in both
  light and dark for intentional, accessible contrast.

## What changed

- `app/src/main/java/com/agepony/app/review/ReviewPrompt.kt` — new Play In-App Review wrapper.
- `app/src/main/java/com/agepony/app/vault/Vault.kt` — launchCount and reviewPromptShown prefs.
- `app/src/main/java/com/agepony/app/MainActivity.kt` — bumps the launch counter on fresh start.
- `app/src/main/java/com/agepony/app/ui/AgePonyApp.kt` — fires the nudge past onboarding.
- `app/src/main/java/com/agepony/app/ui/settings/SettingsScreen.kt` — Rate and Send feedback rows.
- `app/src/main/java/com/agepony/app/ui/theme/Color.kt`, `Theme.kt` — explicit color roles.
- `gradle/libs.versions.toml`, `app/build.gradle.kts` — `com.google.android.play:review` 2.0.2;
  versionCode 2 then 3.
- `NorseHorse_Android_Update_Log.md` — Phase 2f section appended.

All edits to existing files are additive apart from the section rename and the versionCode bump.
No crypto or build-toolchain changes.

## Deploy

```
cd ~/Downloads && unzip -oq AgePonyAndroid_Phase2f.zip && cp -R ~/Downloads/AgePonyAndroid_Phase2f/. ~/Apps/AgePonyAndroid/ && cd ~/Apps/AgePonyAndroid && ./gradlew bundleRelease
```

## Verify after install

1. Settings then Help & feedback shows Replay the intro, Rate AgePony, and Send feedback.
2. Rate AgePony opens the Play Store listing for com.agepony.app.
3. Send feedback opens an email to NorseHorse with version and device details pre-filled.
4. Cold-launch the app three times; on the third the system review card may appear once.
   It is best-effort, so Play may legitimately show nothing on a debug or sideloaded build.
5. Subtitle text and dividers in Settings read with clean contrast in both light and dark.
