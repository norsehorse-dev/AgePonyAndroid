# AgePony Android 5.1.0 RC1: UI changes (U2, U3, U6)

Scope: U2 (theme and shared components), U3 (navigation chrome), U6 (bugs) from
`AgePony_5.1.0_UI_Plan.md`. Rule numbers are the human-grade-app-ui rules. Nothing was
compiled here; the whole change set needs a build on the Mac:

    ./gradlew :app:compileFossDebugKotlin :app:testFossDebugUnitTest

(Flavors are `play` (default) and `foss`; `:app:compilePlayDebugKotlin` covers the other one.)

No dependency changes. Every icon used is in material-icons-core (already a dependency):
ArrowBack, KeyboardArrowRight (AutoMirrored), CheckCircle, Warning, Info, Lock, Add,
MoreVert, ArrowDropDown. BackHandler comes from activity-compose 1.8.0 (already a dependency).
Nothing is committed.

## Theme and resources (U2)

- `ui/theme/Color.kt`: rewritten. Neutral grays for every surface in both modes (light
  background #FAFAFA, dark #121314 with a #0D0E0F to #333536 container ladder), replacing
  #06302F and TealInk. Accent: light #0E7D7A with white text, dark #38CFE8 with #00363D text.
  Secondary and tertiary are a quiet gray, not lavender or cyan. Error is a real red
  (#BA1A1A light, #F2675E dark). Status colors for success and warning added. (Rules 12, 13)
- `ui/theme/Theme.kt`: every ColorScheme role pinned in both schemes, including
  surfaceContainerLowest/Low/(default)/High/Highest, surfaceBright, surfaceDim,
  secondaryContainer/on, tertiaryContainer/on, error/onError/errorContainer/onErrorContainer,
  inversePrimary, inverseSurface, inverseOnSurface, scrim, surfaceTint (neutral, so tonal
  elevation stays gray). Dynamic color removed entirely (the `dynamicColor` parameter had no
  callers). Shapes: 12dp for extraSmall/small/medium (fields, menus, boxes); buttons and
  avatars stay fully round, so two radii. New `StatusColors` (success, warning, failure)
  through `LocalStatusColors`, read as `AgeStatus.colors.success` etc. (Rules 11, 12, 13)
- `ui/theme/Type.kt`: template removed. `AgeTypography` is the Material type scale on the
  platform sans with titleMedium set to SemiBold for section headings; rows use bodyLarge
  (16sp regular). Two extensions: `Typography.mono` (bodyMedium in monospace, for keys, file
  names, digests) and `Typography.code` (headlineSmall in monospace, for transfer and
  confirmation codes). (Rules 1, 2, 3, 26)
- `res/values/colors.xml`: purple_200/500/700, teal_200, teal_700 and teal_ink deleted
  (nothing in res, manifest or Kotlin referenced them except themes.xml). Added
  `window_background` (#FAFAFA), with a `res/values-night/colors.xml` override (#121314).
- `res/values/themes.xml`: windowBackground is now `@color/window_background`, so the light
  splash is light. New `res/values-night/themes.xml` with a `Theme.Material.NoActionBar` parent
  for dark mode. (U6 dark splash)
- `res/values/strings.xml`: new strings for the shared components, the Files rows, the
  decrypt verdict titles, delete confirmations, app bar titles that were new, and 9 plurals
  (see "Strings" below).

## Shared components (U2)

- New `ui/components/Instrument.kt` (HashPony pattern):
  `AgeTopBar`, `AgeScreen` (Scaffold + TopAppBar + back arrow + BackHandler, marks its
  padding as consumed so `imePadding()` in content is exact; `showTopBar = false` for an
  embedded flow), `SectionHeader` (titleMedium semibold, onSurface, heading semantics; not
  accent-tinted, per the plan's "no teal headings"), `ListDivider`, `StatusText`,
  `VerdictPanel`, `PrimaryAction`/`SecondaryAction`/`QuietAction` (QuietAction has a
  `destructive` flag), `ChoiceField`, `EmptyState`, `ErrorText`, `NavRow` (whole-row target
  with chevron, 56dp), `SwitchRow`/`CheckRow`/`RadioRow` (whole row toggles via
  toggleable/selectable with Role, control drawn with a null callback, 48dp min),
  `pluralResource()` and `showOwnCopyConfirmation` (true below API 33). (Rules 6, 9, 15, 26,
  27, 28, 32)
- Per-file copies removed: `SectionLabel` (Settings), private `SectionHeader` and `CheckRow`
  (RecipientPicker), `ErrorLine` (Decrypt, Notes, Text), `ErrorText` (Encrypt), `EmptyPane`
  (Identities, also used by Recipients), `ModeRow`/`SignerRow` (Encrypt), `SigningKeyRow`
  (SignFileFlow). `SettingRow` and `LockModeRow` in Settings are now thin wrappers over
  `SwitchRow`/`RadioRow`, so their call sites did not change. `CheckLine` (TransferScreens)
  wraps `CheckRow`.
- `components/KeyBlock.kt`: no tint, border or 13sp; label in bodyMedium, value in
  `typography.mono`. "Copied" shows only below API 33. Labels from resources. (Rules 2, 7, 32)
- `components/PostQuantumBadge.kt`: lock icon plus "Quantum-safe" in onSurfaceVariant through
  `StatusText`, no pill. (Rule 15)
- `components/KeyAvatar.kt`: flat circle, same per-key hue (one HSV value, no Brush gradient),
  initials in labelMedium/titleSmall instead of a computed sp. (Rule 14, Q4)

## Navigation chrome (U3)

- `ui/AgeTab.kt`: SIGN removed, five tabs (Files, Notes, Text, Identities, Settings). A saved
  `lastTab` of "SIGN" falls back to Files through the existing `firstOrNull`.
- `ui/AgePonyApp.kt`: outer Scaffold has empty contentWindowInsets; each tab gets
  `padding(innerPadding).consumeWindowInsets(innerPadding)` and draws its own TopAppBar.
  NavigationBarItem icons have a null contentDescription (the label already says it).
- `ui/files/FilesScreen.kt`: rewritten as a list. TopAppBar "Files", an intro line, then
  "Encryption" rows (Encrypt, Decrypt, Inspect, Upgrade to quantum-safe) and "Signatures" rows
  (Sign a file, Verify a signature, Trusted signers) that open the existing SignFileFlow,
  VerifyFileFlow and SignersScreen unchanged. All strings in resources.
- `ui/sign/SignScreen.kt`: emptied to a package line and a comment. **Please delete this
  file**; deleting is off for this session, so I could not remove it.
- Every screen and flow now sits in `AgeScreen` with a TopAppBar; sub-screens and flows have the
  back arrow, and BackHandler runs the same callback, so system back returns to the parent
  instead of leaving the app: Encrypt, Decrypt, Inspect, Migrate, SignFile, VerifyFile,
  Signers, allowed_signers import review, Text (home, encrypt, decrypt, choose recipients),
  Notes (list, new, detail), Identities (list with Add and a MoreVert "Recently deleted" in
  the bar, add-identity flow with one bar whose back steps form, chooser, choice, list),
  IdentityDetail, RecipientDetail, AddRecipient, QrScanner (its own bar now, the in-content
  Cancel is gone), Settings and its sub-screens (Help, Security info, Licenses, Recently
  deleted, Send keys, Receive keys, Paper backup, Paper restore), PassphraseOnly (bar with back
  to unlock; its embedded DecryptFlow uses `showTopBar = false`), Onboarding (system back
  acts like Skip). (Rules 9, 30)
- While work is running and leaving would cancel it mid-write (Encrypt/Decrypt WORKING and
  PROBING, Inspect, Migrate, SignFile, VerifyFile, Send keys WORKING), the back arrow is hidden
  and an empty BackHandler holds system back.
- The 20 in-content back buttons are gone (all 11 "‹ Back", "‹ Back to unlock", the six
  "Back" buttons in the generate-identity forms, Encrypt MODE "Back", Signers "Back").
  Cancel and Done buttons were kept.
- In-content screen titles removed where the bar now carries them (headlineMedium/
  headlineSmall/titleLarge in primary). Step headings inside flows became `SectionHeader`.
- imePadding added to every scrolling column with fields: Encrypt configure, Decrypt
  passphrase, Migrate, RecipientPicker, Text encrypt/decrypt, Notes new/detail, the six
  generate forms and Import identity, AddRecipient, RecipientDetail, Settings, Transfer send
  and receive, Paper backup and restore, PassphraseOnly text, SignFile. The non-scrolling
  columns with fields from inventory section 6 now scroll (Identities 258/308/350/402/456/
  511/687, Decrypt passphrase, Encrypt MODE). (Rule 29)
- `ui/VaultGate.kt`: Welcome and Locked screens pad for system bars and the keyboard and
  scroll, centred through `BoxWithConstraints` + `heightIn(min = maxHeight)`. The 260dp and
  240dp button widths are now fillMaxWidth. Headings are headlineSmall in onBackground.
- `ui/onboarding/OnboardingScreen.kt`: systemBarsPadding, BackHandler.
- `share/ShareScreen.kt`: Scaffold contentWindowInsets emptied, since the flows inside now
  handle the bars themselves (avoids a doubled status-bar gap).

## Screens touched for U2/U3 rules

- Glyph icons replaced: ✓ and ⚠ in Decrypt, Encrypt, Migrate, Inspect, Transfer, Paper,
  Text, Verify, SignFile are now `VerdictPanel`/`StatusText`/icon rows or plain words; ↗ in
  Settings rows is gone (in-app rows get a chevron, external links are accent-colored link
  text); › and → in Transfer, Paper (on-screen and in the PDF text), Migrate, Encrypt are now
  words; • in SecurityInfo, Paper and the Inspect/Recipient/Identity meta lines is gone.
  (Rule 17)
- Decrypt verdict: `DecryptOutcome.verdict` is now a typed `SignatureVerdict(kind, text)` with
  `VerdictKind { TRUSTED, UNKNOWN_SIGNER, NOT_TRUSTED, FAILED }`. Color and icon come from the
  kind, never from a "⚠" prefix. Titles are in strings.xml. VerifyFileFlow uses the same
  VerdictPanel shape.
- "ACTIVE" pill is "Active" in onSurfaceVariant; recipient source pills (PASTE, QR, GITHUB,
  SELF) are "Pasted", "Scanned", "GitHub", "Your identity" in onSurfaceVariant, no background.
  (Rules 4, 15)
- HardwareDecrypt warning (errorContainer box) is a VerdictPanel with a warning icon.
  (Rules 12, 16)
- Whole rows toggle: all 10 thumb-only switches (SettingRow x5 via SwitchRow, Identities x4,
  Notes x2, Encrypt armor, RecipientPicker passphrase-only, AddRecipient candidate include),
  checkbox rows (RecipientPicker, Transfer CheckLine and PreviewRow, Signers import review),
  radio rows (Settings lock mode, proxy mode, SOCKS/HTTP, Encrypt output mode and signer,
  Migrate target, SignFile key, Paper protect/plain). (Rule 28)
- Settings: ActionRow, LinkRow, MoreRow, AboutRow are 48dp with the whole row as target; text in
  bodyLarge. Auto-lock and Active identity are `ChoiceField`s. "Danger zone" is "Reset".
  Sibling-app slogans reworded (QuorumPony, BurnPony, PassPony, ScrubPony). (Rules 10, 19, 20, 27)
- Transfer codes use one style (`typography.code`) instead of 24/26/24/20sp. (Rule 3)
- Mono on prose fixed where touched: decrypted text in TextScreen and PassphraseOnly is
  bodyLarge; Inspect and Verify file names are `typography.mono` body size, not a titleLarge
  heading. (Rule 2)
- Title Case fixed in place: "My identities", "Hardware key (P-256)", "Security key (...)"
  (IdentityDetail and RecipientPicker), "Files, text and notes".
- Em dashes removed in every Kotlin string I touched or found: Encrypt (armor help, OOM),
  Decrypt OOM, Text intro and OOM, Migrate skip, Identities hybrid copy, Recipients footer,
  Notes unsaved, VaultGate create dialog, Settings work factor, `vault/Hydration.kt` (3).
  "Get started" is "Done"; the onboarding slogan is a sentence. (Rules 20, 21)
- Spacing: no 2/6/10/14/18/20/28dp left under ui/ except a 20dp icon size and a 2dp progress
  stroke. Screen padding is 16dp in rewritten screens, 24dp kept in flows that had it.
  (Rule 11)

## Bugs (U6)

- System back exiting the app: BackHandler everywhere above.
- Keyboard covering fields: imePadding and scrolling above.
- Dark splash in light mode: windowBackground fix above.
- "1 identities" (TransferScreens) and the hand-built plurals in files I touched: Migrate
  (files chosen, upgrade button), Signers (exported, imported, unreadable lines), Recipients
  ("Found N recipients"), Transfer (identities, recipients, signers), Paper restore. All are
  `<plurals>` in strings.xml.
- Duplicate "Copied" on API 33+: KeyBlock and TextScreen show their own feedback only below
  33; PassphraseOnly's Copy, which had none, now does the same.
- Version fallback "1.0": now `.orEmpty()` from PackageManager versionName.
- Delete confirmations: RecipientDetail ("It moves to Recently deleted") and NoteDetail ("can't
  be undone"), both AlertDialogs with the delete in the error color.

## Spots to check first when it builds

1. `TopAppBar` is called under `@OptIn(ExperimentalMaterial3Api::class)` in Instrument.kt only.
   If BOM 2026.01's material3 has it stable, the OptIn is harmless.
2. `Role.DropdownList` in `ChoiceField` (Compose UI 1.5+). If it is missing, use `Role.Button`.
3. `pluralResource()` reads `LocalConfiguration.current` as a bare statement to recompose on a
   locale change; at worst an "unused expression" warning.
4. `onBack = if (stage == SendStage.WORKING) null else ({ back() })` in TransferScreens and the
   `fun() { ... }` anonymous functions in EncryptFlow's back mapping: written to avoid the
   lambda/block ambiguity, but they are the least common syntax in the change.
5. `BoxWithConstraints` in VaultGate uses `maxHeight` inside `heightIn(min = ...)`; Compose lint
   may flag it, the code is valid.
6. `AgeScreen` wraps content in `Box(Modifier.fillMaxSize().consumeWindowInsets(padding))`; the
   screens then apply `padding(padding)` themselves. If any screen looks doubly padded at the
   top, that pairing is where to look.
7. `IdentitiesScreen` lost `onAdd`/`onRecentlyDeleted` on `IdentityList` and `RecipientList`
   (those actions moved to the app bar). Grep found no other callers.

## Skipped, and why

- `SetSecretDialog` (Settings) and `CreateSecretDialog` (VaultGate) fake Password/PIN segmented
  buttons: U4 (ChoiceField conversion) in RC2.
- RecipientPicker's four-button Diceware row and other truncation risks from inventory section
  7: U4.
- Onboarding 96dp icon in a primary circle: U4 (hero icons).
- Raw `e.message` errors: U5. Only lines rewritten for chrome changed, and they still show the
  same message.
- `replaceFirstChar { uppercase }` on "password"/"PIN" (SensitiveConfirm, IdentityDetail,
  VaultGate): U1, it goes away when those labels become resources.
- `SafIo.humanSize` returning an em dash for an unknown size: U1 (locale-aware formatting, and "0 B"
  versus "unknown" needs a decision).
- "UNPROTECTED:" in the paper backup PDF text: PDF content, left for U4.
- Inspect stanza details still in monospace (they mix key tags with prose): U4.
- `Button` call sites were not converted to `PrimaryAction`/`SecondaryAction`; they already use
  the platform shapes, so the radius rule holds. Converting them is churn for RC2 or U1.
- Transfer "Copy the key as text" has no feedback at any API level; unchanged.

## Left for U1 (string extraction)

`Text("...")` literals, then `title/label/subtitle/body/text/detail = "..."` literals, per file
after RC1 (approximate, from grep):

| File | Text("...") | named literals |
|---|---|---|
| ui/settings/SettingsScreen.kt | 32 | 37 |
| ui/portability/TransferScreens.kt | 23 | 7 |
| ui/identities/IdentitiesScreen.kt | 22 | 9 |
| ui/sign/SignersScreen.kt | 20 | 2 |
| ui/VaultGate.kt | 18 | 0 |
| ui/text/TextScreen.kt | 17 | 6 |
| ui/identities/IdentityDetail.kt | 17 | 11 |
| ui/identities/RecipientsScreen.kt | 16 | 6 |
| ui/files/RecipientPicker.kt | 16 | 1 |
| ui/portability/PaperScreens.kt | 15 | 5 |
| ui/notes/NotesScreen.kt | 12 | 7 |
| ui/files/EncryptFlow.kt | 11 | 9 |
| ui/sign/VerifyFileFlow.kt | 10 | 8 |
| ui/settings/RecentlyDeletedScreen.kt | 9 | 2 |
| ui/passphrase/PassphraseOnlyScreen.kt | 8 | 1 |
| ui/files/DecryptFlow.kt | 7 | 2 |
| ui/security/YubiKeyPromptHost.kt | 7 | 0 |
| ui/files/MigrateFlow.kt | 6 | 2 |
| ui/sign/SignFileFlow.kt | 5 | 2 |
| ui/security/SensitiveConfirm.kt | 5 | 0 |
| ui/files/InspectFlow.kt | 4 | 23 |
| ui/security/SecurityKeyPinDialog.kt | 4 | 0 |
| ui/onboarding/OnboardingScreen.kt | 1 | 10 |
| ui/settings/SecurityInfoScreen.kt | 1 | 1 |
| ui/scan/QrScanner.kt | 1 | 1 |
| ui/settings/LicensesScreen.kt | 0 | 1 |
| ui/settings/HelpScreen.kt | 0 | 1 |

Also for U1: `AgeTab` labels, AgeScreen titles passed as literals, the data lists in Help,
SecurityInfo, Licenses and Onboarding, VerdictPanel/StatusText titles added in RC1 as literals
when they replaced existing text ("Encrypted", "Decrypted", "Signed", "Sent", "Imported",
"PDF saved", "Upgrade complete", "Active", the recipient source words), the remaining hand
plurals (`DecryptFlow` extract count, `RecentlyDeletedScreen.relativeAge`, `InspectFlow`
"Encrypted to N recipients", `EncryptFlow`/`TextScreen` `recipientSummary`), and the
`.lowercase()` on a sentence in EncryptFlow DONE. Already in resources: everything on
FilesScreen, KeyBlock, PostQuantumBadge, the app bar back label, decrypt verdict titles, delete
confirmations, the new app bar titles, and the plurals listed under U6.

## Left for RC2

U4 (segmented Password/PIN to ChoiceField, truncation rows, hero icon circle, mono on prose in
Inspect, PDF caps, Button to Primary/Secondary actions where it helps), U5 (raw error mapping,
"found none" for the GitHub fetch), plus deleting `ui/sign/SignScreen.kt`.
