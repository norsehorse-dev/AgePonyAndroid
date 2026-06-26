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

## Phase P1 — SSHSIG detached-signing core (agepony-core)

Kicks off the 2.0 signing-parity track from the AgePony Android 2.0 master plan. This phase
is core-only: pure Kotlin format and crypto, no app UI, no version bump (stays
versionName 1.0 / versionCode 3 until P7 closes).

### iOS-ahead baseline at the start of P1
iOS already ships the full signing stack this track is porting: SSHSIG detached signing and
verification, hardware-backed keys (Secure Enclave plus YubiKey/Token2 over NFC), FIDO
security-key signing with clientPin, and multi-file signing. Android starts P1 from
encryption-only parity (1.x). The phases P1 through P10 close that gap.

### What landed
- New package `com.agepony.core.signing` with three pure-Kotlin files:
  - `SSHSig.kt` — the SSHSIG format layer per OpenSSH PROTOCOL.sshsig. Magic, version, the
    signed-data builder, public-key wire builders and the inner-signature wire builders for
    ed25519, rsa-sha2-512, ecdsa-sha2-nistp256, and both sk variants
    (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`), full blob
    encode/decode, and 76-column ASCII armor. Holds no keys and never signs.
  - `SSHSigner.kt` — software signing for the in-app SSH keys (ed25519 and rsa-sha2-512 off
    an `OpenSSHPrivateKey`) plus a software ecdsa P-256 path, and the assembly entry points
    for signatures produced elsewhere: `assembleEcdsaP256` for the P2 Android Keystore key,
    `assembleSkEd25519` / `assembleSkEcdsaP256` for the P3 FIDO-over-NFC keys. The assemble
    paths self-verify the packaged signature before returning, so a wrong flags/counter or a
    malformed DER from hardware fails loudly at assembly instead of at verify time.
  - `SSHSigVerifier.kt` — verifies every algorithm above. For the sk variants it rebuilds the
    FIDO authenticator model `SHA-256(application) || flags || counter || SHA-256(signed-data)`
    and checks against that. Returns the recovered signer public-key wire so the later
    FileVerifier can decide trusted vs valid-but-unknown.
- Default namespace is `agepony`, default message hash is sha512, matching the iOS side and
  the `ssh-keygen -Y sign` default.

### Tests
- `SSHSigTest.kt` — verifies committed `ssh-keygen -Y sign` fixtures with our verifier,
  round-trips software ed25519/rsa/ecdsa through our own verifier, checks tamper and
  namespace rejection and armor/signed-data plumbing, and (gated on `ssh-keygen` being on
  PATH) cross-checks that our signatures pass `ssh-keygen -Y verify`.
- `SSHSigSkTest.kt` — simulates the FIDO authenticator in software to exercise the sk wire
  format, the authenticator-data model, the assemble self-verify guard, and wrong-application
  rejection for both sk-ed25519 and sk-ecdsa. Real YubiKey/Token2 golden vectors arrive in P3.

### Format validation
Every envelope (ed25519, rsa-sha2-512, ecdsa-p256, sk-ed25519, sk-ecdsa) was byte-checked
against OpenSSH `ssh-keygen 9.6` during bring-up: signatures built with this exact wire
construction are accepted by `ssh-keygen -Y verify` under namespace `agepony`, and
ssh-keygen's own output decodes and verifies back. The sk path uses UP flag 0x01.

### Fixtures
- `generate-fixtures.sh` gains section 6: writes `sshsig_message.txt` and produces
  `sshsig_ed25519_hello.sig` and `sshsig_rsa_hello.sig` via `ssh-keygen -Y sign -n agepony`
  off the existing ed25519/rsa identities. Idempotent like the rest of the script.

### iOS parity note
No iOS change. This phase brings Android up toward the existing iOS signing core; the wire
format, namespace, and hash choice are matched to the iOS implementation so signatures
interoperate in both directions.

### Files added
- `agepony-core/src/main/kotlin/com/agepony/core/signing/SSHSig.kt` (new)
- `agepony-core/src/main/kotlin/com/agepony/core/signing/SSHSigner.kt` (new)
- `agepony-core/src/main/kotlin/com/agepony/core/signing/SSHSigVerifier.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/signing/SSHSigTest.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/signing/SSHSigSkTest.kt` (new)
- `agepony-core/src/test/resources/fixtures/sshsig_message.txt` (new)
- `agepony-core/src/test/resources/fixtures/sshsig_ed25519_hello.sig` (new)
- `agepony-core/src/test/resources/fixtures/sshsig_rsa_hello.sig` (new)

### Files edited
- `generate-fixtures.sh` — added SSHSIG section 6.

### Next
- P2: Android Keystore hardware ecdsa P-256 key, signing through `assembleEcdsaP256`.

## Phase P2 — Hardware-backed signing (Android Keystore)

Second phase of the 2.0 signing-parity track. Adds a non-exportable EC P-256 signing key
in the AndroidKeyStore that produces detached SSHSIG via the P1 core. App-only; no version
bump (stays 1.0 / 3). Auth is optional and decided per key at creation.

### What landed
- `security/keystore/KeystoreEcdsa.kt` (new) — the device-independent half: SEC1
  uncompressed-point encoding from an `ECPublicKey`, the `ecdsa-sha2-nistp256` SSHSIG
  public wire, the signed-data a Keystore `Signature` must cover, and the DER -> armored
  SSHSIG assembly via the P1 `SSHSigner.assembleEcdsaP256` (which self-verifies). No
  AndroidKeyStore or framework types, so it is JVM-unit-testable with a software EC key.
- `security/keystore/HardwareKeyService.kt` (new) — generates a `PURPOSE_SIGN` EC P-256
  key in `AndroidKeyStore`, StrongBox when present and TEE otherwise (same try/fallback
  idiom as `KeystoreMasterKey`). Signs the AgePony signed-data with `SHA256withECDSA` and
  hands the DER to `KeystoreEcdsa`. Auth policy is fixed at generation: `requireAuth=true`
  gates the key behind biometric / device-credential and signs through
  `signAuthenticated` (BiometricPrompt CryptoObject over the `Signature`); `requireAuth=false`
  signs headless through `sign`, which inspects `KeyInfo` and refuses if the key actually
  needs auth. Exposes `publicWire`, `isUserAuthRequired`, `isHardwareBacked`, and a
  `toStoredIdentity` factory. The private key never leaves hardware.
- `security/BiometricGate.kt` (edited) — added `authenticateSignature`, the `Signature`
  counterpart of the existing Cipher-based `authenticate`, returning the authenticated
  `Signature` for the signing path.

### Data model (Section 5)
- `StoredIdentityType` gains `HARDWARE_KEY`. A new `isSigningOnly` extension marks it (and
  the future sk-* types) as not usable for encryption.
- `StoredIdentity` gains an optional `keystoreAlias` (the AndroidKeyStore alias). For
  hardware keys only the public wire is stored; the private key stays in the Keystore. The
  field is nullable with a default, so existing serialized vaults load unchanged.
- Exhaustiveness sweep over every `when (StoredIdentityType)`: `Hydration.kt` (toAgeIdentity
  and toAgeRecipient throw signing-only; publicDisplayString renders an `ecdsa-sha2-nistp256`
  line; privateDisplayString notes the key stays in the keystore), `IdentityDetail.kt` and
  `RecipientPicker.kt` type labels. The recipient picker filters signing-only identities out
  of the encrypt-to-self list so a hardware key can never be chosen as a recipient.

### Tests (both JVM and instrumented, per decision)
- `app/src/test/.../KeystoreEcdsaTest.kt` (JVM, JUnit4) — software EC P-256 key drives the
  exact point-encoding / public-wire / DER -> SSHSIG path the device uses, verified by
  `SSHSigVerifier`; plus tamper rejection and the signing-only flag. `bcprov-jdk18on:1.78.1`
  added as a `testImplementation` so the verifier resolves at unit-test runtime.
- `app/src/androidTest/.../HardwareKeyInstrumentedTest.kt` (instrumented, AndroidJUnit4) —
  real AndroidKeyStore key gen (requireAuth=false), sign, verify with `SSHSigVerifier`,
  tamper rejection, public-wire stability across reload, and the hardware identity proving
  signing-only through Hydration. The biometric-gated path needs a human at the prompt and
  is a manual device check.

### Validation
The SEC1 uncompressed-point encoding was cross-checked against canonical X9.62 across 5000
random P-256 keys (zero mismatches). The ecdsa SSHSIG envelope itself was proven against
`ssh-keygen -Y verify` in P1, and `assembleEcdsaP256` self-verifies on every call.

### Not in this phase
- No manifest change. Biometric needs no app-declared permission (androidx.biometric merges
  its own); NFC permission/feature lands with P3 where it is used.
- No signing UI; the FileSigner flow that calls `HardwareKeyService` is P6.

### Run
- JVM: `./gradlew :app:testDebugUnitTest --tests "com.agepony.app.security.keystore.*"`
- Device: `./gradlew :app:connectedDebugAndroidTest`

### Files added
- `app/src/main/java/com/agepony/app/security/keystore/KeystoreEcdsa.kt` (new)
- `app/src/main/java/com/agepony/app/security/keystore/HardwareKeyService.kt` (new)
- `app/src/test/java/com/agepony/app/security/keystore/KeystoreEcdsaTest.kt` (new)
- `app/src/androidTest/java/com/agepony/app/security/keystore/HardwareKeyInstrumentedTest.kt` (new)

### Files edited
- `app/src/main/java/com/agepony/app/security/BiometricGate.kt` — authenticateSignature.
- `app/src/main/java/com/agepony/app/vault/VaultModels.kt` — HARDWARE_KEY, keystoreAlias, isSigningOnly.
- `app/src/main/java/com/agepony/app/vault/Hydration.kt` — HARDWARE_KEY branches.
- `app/src/main/java/com/agepony/app/ui/identities/IdentityDetail.kt` — type label.
- `app/src/main/java/com/agepony/app/ui/files/RecipientPicker.kt` — type label + signing-only filter.
- `app/build.gradle.kts` — bcprov testImplementation.

### Next
- P3: FIDO security-key stack (sk-ed25519 / sk-ecdsa) over NFC, using the P1 assembleSk* paths.

## Phase P3 — FIDO security-key stack + NFC transport (agepony-core + app)

Adds FIDO security keys (YubiKey 5 NFC, Token2) as SSHSIG signing identities over NFC:
full CTAP2 enroll + sign, user-presence (touch). Builds on the P1 assembleSk* paths, which
self-verify every assertion before it is returned. Version stays 1.0 / 3.

### What this phase does
- CTAP2 enroll (`authenticatorMakeCredential`) creates a resident sk credential; the
  returned COSE public key becomes an sk-ed25519 or sk-ecdsa-sha2-nistp256 SSHSIG identity.
- CTAP2 sign (`authenticatorGetAssertion`) signs `SHA-256(SSHSIG signedData)` as the
  clientDataHash; the assertion's signature, flags, and signCount feed `assembleSkEd25519`
  / `assembleSkEcdsaP256` to produce an armored SSHSIG.
- The FIDO credentialId is stored as the private material; the sk SSHSIG wire (which
  embeds the application) as the public material.

### iOS-ahead baseline
iOS already ships sk-ed25519 / sk-ecdsa signing with clientPin. This phase brings Android
to enroll + sign parity for the touch path; the PIN path follows in P4.

### Design notes
- The CTAP2-canonical CBOR codec sorts map keys shortest-first then bytewise, matching
  python-fido2 / cbor2 canonical output, which the JVM tests assert byte-for-byte.
- pinUvAuthParam / pinUvAuthProtocol map keys are baked in correctly from the start: 8/9
  for makeCredential, 6/7 for getAssertion. (Crossing these was the iOS "enroll works, sign
  says PIN required" bug.) P3 sends no PIN params; the slots are wired so P4 only supplies
  values.
- A PIN-required authenticator returns CTAP 0x36, surfaced as
  `SecurityKeyService.PinRequiredException`. The clientPin handshake and retry, plus the
  detect-and-prompt PIN dialog, are P4 — architected here as a clean seam, deferred by
  decision so the clientPin crypto gets its own golden-vector pass and device checkpoint.
- NFC transport (reader mode + IsoDep) is device-only and not JVM-testable; it is validated
  at the YubiKey 5 NFC bring-up checkpoint. It runs enroll/sign inside a single tap so the
  P4 PIN handshake can share the session.

### Files added
- `agepony-core/src/main/kotlin/com/agepony/core/fido/Cbor.kt` (new)
- `agepony-core/src/main/kotlin/com/agepony/core/fido/CoseKey.kt` (new)
- `agepony-core/src/main/kotlin/com/agepony/core/fido/AuthenticatorData.kt` (new)
- `agepony-core/src/main/kotlin/com/agepony/core/fido/Ctap2.kt` (new)
- `app/src/main/java/com/agepony/app/security/nfc/SecurityKeyTransport.kt` (new)
- `app/src/main/java/com/agepony/app/security/SecurityKeyService.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/fido/CborTest.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/fido/CoseKeyTest.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/fido/AuthenticatorDataTest.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/fido/Ctap2Test.kt` (new)

### Files edited
- `app/src/main/java/com/agepony/app/vault/VaultModels.kt` — SK_ED25519 / SK_ECDSA_P256 enum + isSigningOnly.
- `app/src/main/java/com/agepony/app/vault/Hydration.kt` — sk arms in all four identity whens + skLine.
- `app/src/main/java/com/agepony/app/ui/identities/IdentityDetail.kt` — sk type labels.
- `app/src/main/java/com/agepony/app/ui/files/RecipientPicker.kt` — sk type labels.
- `app/src/main/AndroidManifest.xml` — NFC permission + uses-feature (required=false).

### Validation
CBOR, COSE, authenticatorData, and CTAP2 request/response formats are checked byte-for-byte
against python-fido2 2.2.0 and cbor2 canonical vectors embedded in the JVM tests: canonical
integer/map encoding, the 8/9-vs-6/7 pin keys, COSE ed25519/p256 decode, makeCredential and
getAssertion request builders, and response parsing (credentialId, public key, signature,
flags, signCount). The sk SSHSIG envelopes themselves were proven against `ssh-keygen -Y
verify` in P1, and assembleSk* self-verify on every call.

### Run
- JVM: `./gradlew :agepony-core:testDebugUnitTest --tests "com.agepony.core.fido.*"`
- Device: enroll + sign with a YubiKey 5 NFC, then verify the output with `ssh-keygen -Y verify`.

### Next
- P4: clientPin (PIN-protected keys) + PIN UI — AESCBC, PinProtocolV1 (shared secret =
  SHA-256(ECDH x), pinHashEnc, pinUvAuthParam), clientPin getKeyAgreement/getPinToken in the
  same NFC session, and the detect-and-prompt PIN dialog. clientPin crypto already de-risked
  against python-fido2 PinProtocolV1 during P3.

## Phase P4 — clientPin (PIN-protected security keys) + PIN UI (agepony-core + app)

Adds the FIDO clientPin path so PIN-protected security keys (and keys with always-uv) can
enroll and sign. Touch-only keys are unchanged: the PIN dialog appears only when the
authenticator reports PIN required. Version stays 1.0 / 3. This brings Android to full sk
signing parity with iOS (touch and PIN).

### What this phase does
- PIN/UV auth protocol one: shared secret = SHA-256(ECDH X), AES-256-CBC (zero IV) wrap of
  the PIN hash, HMAC-SHA-256 (truncated to 16) request authentication.
- On CTAP 0x36 (PIN required), `SecurityKeyService` runs getKeyAgreement, derives the shared
  secret, sends getPinToken with the encrypted PIN hash, decrypts the PIN token, and retries
  the original command with a pinUvAuthParam over its clientDataHash, all in the same tap.
- Wrong PIN (0x31) re-prompts; the dialog only collects a PIN, never displays it.

### Design notes
- The pinUvAuthParam on the main command is keyed by the decrypted PIN token, not the shared
  secret; the shared secret only wraps PIN material during the handshake. The makeCredential
  8/9 vs getAssertion 6/7 key placement (baked in during P3) is what makes the retried
  command validate rather than loop on "PIN required".
- The platform key is freshly generated per handshake; the shared secret never leaves the
  session.
- `PinPromptController` implements `SecurityKeyService.PinProvider` and bridges the suspend
  handshake to Compose via a state flow and a rendezvous channel, so the signing screen (P6)
  renders `SecurityKeyPinPrompt` and the handshake parks until the user responds.

### Files added
- `agepony-core/src/main/kotlin/com/agepony/core/crypto/AESCBC.kt` (new)
- `agepony-core/src/main/kotlin/com/agepony/core/fido/PinProtocolV1.kt` (new)
- `app/src/main/java/com/agepony/app/ui/security/SecurityKeyPinDialog.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/crypto/AESCBCTests.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/fido/PinProtocolV1Test.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/fido/ClientPinTest.kt` (new)

### Files edited
- `agepony-core/src/main/kotlin/com/agepony/core/fido/Ctap2.kt` — clientPin getKeyAgreement / getPinToken builders + parsers, subcommand and key constants.
- `app/src/main/java/com/agepony/app/security/SecurityKeyService.kt` — PinProvider, in-session PIN handshake with retry, replaces the P3 PIN-required stub.

### Validation
AES-CBC, the ECDH shared secret, pinHashEnc, pinUvAuthParam, and the getKeyAgreement /
getPinToken request and response CBOR are checked byte-for-byte against python-fido2 2.2.0
PinProtocolV1 and cbor2, with deterministic P-256 keys, in AESCBCTests / PinProtocolV1Test /
ClientPinTest. The NIST CBC-AES256 known-answer vector covers the cipher itself.

### Run
- JVM: `./gradlew :agepony-core:testDebugUnitTest --tests "com.agepony.core.fido.*" --tests "com.agepony.core.crypto.AESCBCTests"`
- Device: with a PIN-set YubiKey 5 NFC (toggle always-uv) and the Token2, enroll + sign and
  confirm the PIN dialog appears only when required; verify output with `ssh-keygen -Y verify`.

### Next
- P5: multi-file tar (core TarArchive + app), then P6 wires the FileSigner / FileVerifier
  signing UI to HardwareKeyService and SecurityKeyService (including SecurityKeyPinPrompt).

## Phase P5 — Multi-file tar (agepony-core + app)

Lets the encrypt flow take more than one file. Two or more files are bundled into a single
compact USTAR archive before encryption, producing one `bundle.tar.age`. A single file is
unchanged. Version stays 1.0 / 3.

### What this phase does
- `TarArchive` builds and extracts compact USTAR: per-file 512-byte header plus padded
  data, then two zero blocks, with no 10240-byte record padding. Headers use fixed fields
  (mode 0644, uid/gid 0, mtime 0, empty uname/gname) so a given set of files always produces
  the same bytes. Checksums are written and verified.
- The encrypt picker now allows multiple selection. With one file the behaviour is exactly as
  before. With several, the files are read and packed via `TarArchive.create`, then handed to
  the existing encrypt path as `bundle.tar`; duplicate basenames are de-duplicated.

### Files added
- `agepony-core/src/main/kotlin/com/agepony/core/archive/TarArchive.kt` (new)
- `agepony-core/src/test/kotlin/com/agepony/core/archive/TarArchiveTest.kt` (new)

### Files edited
- `app/src/main/java/com/agepony/app/ui/files/EncryptFlow.kt` — OpenMultipleDocuments picker, tar bundling, bundle-aware source display, uniqueName de-dup.

### Validation
The compact USTAR layout is cross-checked against python tarfile (USTAR_FORMAT) and GNU tar:
the reference two-file archive hashes to a fixed SHA-256, asserted in `TarArchiveTest`, and
the same archive extracts cleanly with `tar -xf`. Round-trip, empty / unaligned files,
checksum-tamper rejection, and overlong-name rejection are also covered. `TarArchive.extract`
is in place for a future decrypt-side unpack; for now a decrypted `bundle.tar` opens with any
tar tool.

### Run
- JVM: `./gradlew :agepony-core:testDebugUnitTest --tests "com.agepony.core.archive.*"`
- Device: encrypt 2+ files, decrypt the `.tar.age`, and confirm `tar -xf bundle.tar` recovers
  the originals.

### Next
- P6: FileSigner / FileVerifier services (route by identity type to SSH / Keystore /
  security-key signing; detached .sig and verify with trusted / valid-unknown states),
  wiring in SecurityKeyPinPrompt for PIN-protected keys.

## Phase P6 — File sign / verify services (app)

Adds the signing and verification services that the Sign / Verify UI (P7) will drive. No UI
yet; these are the routing and trust layers. Version stays 1.0 / 3.

### What this phase does
- `FileSigner` produces a detached SSHSIG over a file, routing by identity type: software SSH
  Ed25519 in-process, a hardware Keystore key in the TEE/StrongBox (behind a biometric prompt
  when the key requires user auth), or a security key over NFC (prompting for a PIN through
  the P4 PinProvider when required). Output is the armored SSHSIG, saved as `<name>.sig`.
- `FileVerifier` checks a detached SSHSIG with `SSHSigVerifier`, then classifies the signer:
  TRUSTED when the signer's public key matches a known vault identity (with its name),
  VALID_UNKNOWN for a cryptographically valid signature from an unknown key, INVALID with a
  reason otherwise.

### Files added
- `app/src/main/java/com/agepony/app/signing/FileSigner.kt` (new)
- `app/src/main/java/com/agepony/app/signing/FileVerifier.kt` (new)
- `app/src/test/java/com/agepony/app/signing/FileVerifierTest.kt` (new)

### Design notes
- The signer reuses the existing per-type paths (SSHSigner, HardwareKeyService,
  SecurityKeyService), so the detached signatures verify the same way the P1 envelopes do.
- Trust matching compares the verifier's signer public wire to each identity's SSHSIG public
  wire: Ed25519 is rebuilt from the stored raw key, while hardware and security-key
  identities already store the full wire.
- RSA signing is not yet available (consistent with the rest of the app) and reports a clear
  message; age X25519 identities are signing-incapable and are rejected up front.

### Validation
`FileVerifierTest` signs a message with a known Ed25519 pair through `SSHSigner` and asserts
the trusted, valid-unknown, and invalid (tampered-message) outcomes. It runs as a host unit
test with no Android dependencies. The hardware and security-key signing routes are exercised
at the device checkpoint.

### Run
- JVM: `./gradlew :app:testDebugUnitTest --tests "com.agepony.app.signing.FileVerifierTest"`
- Device: sign a file with each identity type and verify the `.sig`; confirm trusted vs
  valid-unknown badges and that `ssh-keygen -Y verify -n agepony` accepts the output.

### Next
- P7: Sign / Verify screens and the identity-generation UI for hardware and security keys,
  wiring in BiometricGate and SecurityKeyPinPrompt.

### P6 fix — host-safe base64 in vault hydration

`b64d` / `b64e` (and the sshEd25519 line helper) used `android.util.Base64`, which is not
available in host JVM unit tests, so `FileVerifierTest` threw at the b64 calls. Switched them
to `java.util.Base64` (basic encoder/decoder). This is byte-identical to `android.util.Base64`
with `NO_WRAP` (standard RFC 4648, padded, no line breaks) and is supported on the app's
minSdk 26, so there is no change to stored data and no migration; the vault layer is now
host-testable. File: `app/src/main/java/com/agepony/app/vault/Hydration.kt`.

## Phase P7a — Identity generation UI for hardware + security keys (app)

Extends the Generate flow on the Identities tab so users can create the new signing
identities, not just age X25519. Version stays 1.0 / 3.

### What this phase does
- The Generate path now opens a key-type chooser: age X25519 (software), Hardware key (this
  device), or Security key (FIDO over NFC).
- Hardware key: name plus a "require biometric / device unlock to sign" toggle, then
  `HardwareKeyService.generate` in StrongBox or TEE and store via `toStoredIdentity`. The auth
  policy is fixed at creation; the biometric prompt happens later at signing time.
- Security key: name plus an Ed25519 / P-256 toggle, then `SecurityKeyService.enroll` over NFC.
  The PIN dialog (`SecurityKeyPinPrompt` + `PinPromptController`) is mounted so PIN-protected
  keys enroll in the same tap. NFC work runs off the main thread.

### Files edited
- `app/src/main/java/com/agepony/app/ui/identities/IdentitiesScreen.kt` — GenerateIdentity is
  now a router (GenerateTypeChooser + GenerateX25519 + GenerateHardwareKey + GenerateSecurityKey);
  added Switch, activity, and service / PIN-prompt imports.

### Validation
UI only, so no JVM test; the compile is the check. Exercised at the device checkpoint:
generate a hardware key (auth on and off) and enroll a security key (Ed25519 and P-256, PIN
and touch-only), then confirm each appears in the list with the right type label.

### Next
- P7b: SignScreen and VerifyScreen (driving FileSigner / FileVerifier), surfaced from the
  Files tab, with the trusted / valid-unknown / invalid result states.
