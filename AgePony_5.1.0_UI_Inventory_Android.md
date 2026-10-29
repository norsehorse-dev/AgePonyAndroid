# AgePony Android UI inventory (5.1.0, Oct 26 2026)

Step 1 of the human-grade-app-ui process: every tell found before anything changes. Read-only
pass over the app module. Paths are relative to `app/src/main/java/com/agepony/app/` unless they
start with `res/` (`app/src/main/res/`). The plan that works from this is
`AgePony_5.1.0_UI_Plan.md` in the iOS repo.

## Theme

- `ui/theme/Color.kt`: brand CyanLight #38CFE8, TealCore #14B8B0, TealDeep #0E7D7A, TealInk
  #0A4F4D; light neutrals (Surface #FFFFFF, Background #F7FAFA, SurfaceVariant #DDECEB,
  OnSurfaceVariant #3C5957, Outline #AEC6C4, OutlineVariant #C9DEDC, PrimaryContainer #CDEFF4);
  dark neutrals (Surface = TealInk, Background #06302F, On #E6FBFA, SurfaceVariant #143F3D,
  OnSurfaceVariant #BAD7D5, Outline #386260, OutlineVariant #274F4D). No #6750A4, no template
  names here.
- `ui/theme/Theme.kt`: dynamic color off. 16 roles pinned. Not pinned, so on M3 baseline
  lavender/pink: secondaryContainer and on, tertiaryContainer and on, error, onError,
  errorContainer and on, inversePrimary, inverseSurface, inverseOnSurface, scrim, surfaceBright,
  surfaceDim, surfaceContainerLowest/Low/(default)/High/Highest. Shows through on the
  NavigationBar indicator (secondaryContainer), dialogs (surfaceContainerHigh), menus, unchecked
  Switch tracks, the warning box at `IdentitiesScreen.kt:591` (errorContainer).
- `ui/theme/Type.kt`: untouched Android Studio template; only bodyLarge set, to the default.
- `res/values/colors.xml`: template purple_200, purple_500 (#6200EE), purple_700, teal_200,
  teal_700 left over. `res/values/themes.xml`: `windowBackground` teal_ink, so light-mode users
  see a dark teal window before the first frame.
- Locales: `res/values/strings.xml` only, 2 strings (app_name, share_label), 0 plurals.
- `ui/components/`: KeyAvatar, KeyBlock, PostQuantumBadge, QrCode. No shared row, header or
  empty-state file; SectionLabel/SectionHeader, ErrorLine/ErrorText (3 files), typeLabel (4),
  recipientSummary (2), EmptyPane (`IdentitiesScreen.kt:874`) are copied per file.

## 1. Mono on prose (9)
Decrypted plaintext `text/TextScreen.kt:429`, `passphrase/PassphraseOnlyScreen.kt:122`; prose
placeholders through KeyBlock `vault/Hydration.kt:128,132,134,136` (`IdentityDetail.kt:181-186`);
stanza prose `files/InspectFlow.kt:206`; `portability/TransferScreens.kt:745`;
`files/RecipientPicker.kt:396` (can be "SSH Ed25519 (one-time)", :592); SSH comment
`identities/RecipientsScreen.kt:515`; file name as titleLarge heading `files/InspectFlow.kt:155`,
`sign/VerifyFileFlow.kt:167`.

## 2. Type scale
Styles per file: RecipientsScreen 7; Settings, Notes, Identities, RecipientPicker, InspectFlow
6; Text, SignFile, RecentlyDeleted, Paper, Encrypt 5; TransferScreens 5 plus 20/24/26sp (8).
Custom sp: `components/KeyBlock.kt:68` 13sp; `TransferScreens.kt:296,336,593,715` (24/26/24/20,
three sizes for one transfer code); `KeyAvatar.kt:50`. Medium title `TransferScreens.kt:741`.
About 60 `Text()` with no style.

## 3. Case
"ACTIVE" `identities/IdentitiesScreen.kt:225`; "PASTE"/"QR"/"GITHUB"/"SELF"
`identities/RecipientsScreen.kt:584-588` (pill :129, detail :223); "UNPROTECTED:"
`portability/PaperScreens.kt:265` (PDF). `replaceFirstChar{uppercase}` on "password"/"PIN"
`SensitiveConfirm.kt:68`, `IdentityDetail.kt:388`, `VaultGate.kt:285` (breaks under
localization). Title Case "My Identities" `IdentitiesScreen.kt:79`; "Hardware Key (P-256)",
"Security Key (...)" `IdentityDetail.kt:359-361`, `RecipientPicker.kt:617-619`; "Files, Text,
and Notes" `OnboardingScreen.kt:84`.

## 4-5. Lists, cards, headers
0 Cards; lists are rows with 57 HorizontalDividers, 0 ListItem. KeyBlock tint plus border plus
r12 `components/KeyBlock.kt:72-81`. Section headers in primary titleSmall
`settings/SettingsScreen.kt:973`, `files/RecipientPicker.kt:528`. "Danger zone"
`SettingsScreen.kt:757`.

## 6. Chrome, back, insets, IME
0 TopAppBar; screen titles are in-content Text (headlineMedium `FilesScreen.kt:43`,
`SignScreen.kt:43`, `TextScreen.kt:77`, `SettingsScreen.kt:140`; headlineSmall
`NotesScreen.kt:106`; titleLarge in flows; none on Identities). NavigationBar with 6 items
(`AgeTab.kt:21-28`, M3 max is 5). **0 BackHandler: system back exits the app from every
sub-screen.** In-content "‹ Back" (11): `SecurityInfoScreen.kt:62`, `RecentlyDeletedScreen.kt:54`,
`HelpScreen.kt:71`, `LicensesScreen.kt:43`, `NotesScreen.kt:274`, `TransferScreens.kt:263,548`,
`PaperScreens.kt:115,338`, `RecipientsScreen.kt:171`, `IdentityDetail.kt:102`; "‹ Back to
unlock" `PassphraseOnlyScreen.kt:69`; "Back" buttons `IdentitiesScreen.kt:391,445,498,559,671,762`,
`EncryptFlow.kt:377`, `SignersScreen.kt:218`. 0 imePadding, no windowSoftInputMode, edge-to-edge
on. No insets: `ui/VaultGate.kt:115,225`, `onboarding/OnboardingScreen.kt:105`. Non-scrolling
columns with fields: `IdentitiesScreen.kt:350,402,456,511,687` (and 258, 308), `VaultGate.kt:226`,
`DecryptFlow.kt:273,366`, `EncryptFlow.kt:317,348`.

## 7. Truncation risk
Fake segmented Password/PIN `VaultGate.kt:420-433`, `SettingsScreen.kt:896-903`; four buttons
`RecipientPicker.kt:298-320`; `SettingsScreen.kt:407-414,243-262,288-299`;
`EncryptFlow.kt:400-406,422-439`; `RecentlyDeletedScreen.kt:166-167`; `KeyBlock.kt:94,99`;
headers `IdentitiesScreen.kt:177-178`, `RecipientsScreen.kt:84-85`; tab labels; 6-slot bar.
Fixed widths `VaultGate.kt:146,159,166` (260dp), `:256,274` (240dp).

## 8. Grid and radii
dp counts: 8 x71, 12 x65, 24 x58, 4 x32, 16 x32, 20 x26, 14 x11, 10 x11, 6 x10, 32 x7, 2 x5,
28 x3, 260 x3, 1 x3, 48 x2, 240 x2, 96/40/320/220/18/0 x1. Off grid: 6dp `KeyBlock.kt:61`,
`PostQuantumBadge.kt:28`, `RecipientPicker.kt:549`, `IdentitiesScreen.kt:228,878`,
`RecipientsScreen.kt:122,132`, `NotesScreen.kt:116`, `SettingsScreen.kt:390,1030`; 10dp
`FilesScreen.kt:56,60,64`, `SignScreen.kt:58,62`, `TextScreen.kt:88`, `EncryptFlow.kt:561`,
`InspectFlow.kt:149`, `MigrateFlow.kt:215`, `RecentlyDeletedScreen.kt:152`,
`SettingsScreen.kt:615`; 14dp `KeyBlock.kt:81`, `DecryptFlow.kt:275`, `EncryptFlow.kt:350,382`,
`MigrateFlow.kt:99`, `IdentitiesScreen.kt:207,262,310,782`, `RecipientsScreen.kt:110`,
`NotesScreen.kt:132`; 2dp `PostQuantumBadge.kt:28`, `EncryptFlow.kt:807`, `MigrateFlow.kt:122`,
`IdentitiesScreen.kt:228`, `RecipientsScreen.kt:132`; 18dp `RecipientsScreen.kt:435`; 28dp
`FilesScreen.kt:49`, `SignScreen.kt:51`, `TextScreen.kt:83`. Screen padding mixes 20 and 24.
Radii: extraSmall, 8, 12, Circle.

## 9-12. Color, pills, icons, motion
Gradient avatars `components/KeyAvatar.kt:43`. Status as background: errorContainer
`IdentitiesScreen.kt:590-601`, ACTIVE pill `:219-230`. Failures in primary `SignersScreen.kt:150`,
`DecryptFlow.kt:436`; verdict color from a "⚠" prefix `DecryptFlow.kt:398`. Pills:
`components/PostQuantumBadge.kt:19-30` (at `IdentitiesScreen.kt:216`, `RecipientsScreen.kt:122,230`,
`IdentityDetail.kt:141`; inline text instead at `InspectFlow.kt:195-198`), ACTIVE, source pill
`RecipientsScreen.kt:124-134`. 96dp icon in a primary circle `OnboardingScreen.kt:173-186`.
Glyphs as icons (about 35): ✓ `DecryptFlow.kt:371,496`, `EncryptFlow.kt:564,582,592`,
`MigrateFlow.kt:142,228`, `InspectFlow.kt:170`, `TransferScreens.kt:458,653,680`,
`PaperScreens.kt:120,394`, `TextScreen.kt:437`, `VerifyFileFlow.kt:176`, `SignFileFlow.kt:218`;
⚠ `DecryptFlow.kt:398,500,505,520`, `EncryptFlow.kt:592`, `MigrateFlow.kt:228`,
`InspectFlow.kt:172`, `VerifyFileFlow.kt:185,210`; ↗ on in-app rows
`SettingsScreen.kt:707,708,722,733,740,747,1042,1056`; › and → `TransferScreens.kt:270`,
`PaperScreens.kt:283`, `MigrateFlow.kt:114`, `EncryptFlow.kt:389-390`; • `SecurityInfoScreen.kt:76`,
`PaperScreens.kt:385`. Only 2 Material Icon() calls. No decorative animation.

## 13. Raw exception text (55 UI sites, 16 ViewModel sites)
`security/SensitiveConfirm.kt:87,126`; `security/YubiKeyPromptHost.kt:54`;
`passphrase/PassphraseOnlyScreen.kt:179,181,185`; `notes/NotesScreen.kt:235,326,384`;
`files/MigrateFlow.kt:284,287,294,301`; `files/RecipientPicker.kt:450,475,501`;
`files/DecryptFlow.kt:147,153,187,219,326`; `files/EncryptFlow.kt:150,206,212,263,269,768`;
`files/InspectFlow.kt:99`; `portability/TransferScreens.kt:178,224 (class name),521,534,631,636`;
`portability/PaperScreens.kt:103,214,374`; `identities/IdentitiesScreen.kt:552,664,754,857,860`;
`identities/RecipientsScreen.kt:309,399,427`; `identities/IdentityDetail.kt:203,326`;
`text/TextScreen.kt:204,350,355,403`; `sign/VerifyFileFlow.kt:90`; `sign/SignersScreen.kt:91,108`;
`sign/SignFileFlow.kt:109`. `vault/VaultViewModel.kt` sets `vm.error` from `e.message` at
115, 117, 154, 186, 249, 254, 308, 334, 442, 571, 629, 690, 720, 747, 893, 895 (shown at
`VaultGate.kt:174,377`, `SettingsScreen.kt:337,666`). Core wrappers: `vault/FileEncryptor.kt`
173, 205, 234, 251, 265, 292, 310, 346, 358, 378, 395, 433; `signing/FileVerifier.kt:92,94`;
`vault/RecipientImport.kt:49,66,84,100,205,213,272`; `vault/IdentityImport.kt:80,113,148`;
developer strings `security/keystore/HardwareTagKeyService.kt:160`,
`security/nfc/SecurityKeyTransport.kt:49,94`.

## 14. Hard-coded English
405 `Text("...")` literals plus 6 `text = "..."`, 0 `stringResource`. Per file: Settings 40,
Identities 40, Transfer 35, Text 23, Signers 23, Paper 23, Encrypt 21, Notes 20, Recipients 20,
IdentityDetail 19, VaultGate 18, RecipientPicker 16, RecentlyDeleted 14, Migrate 13, Verify 11,
PassphraseOnly 10, Decrypt 10, SignFile 8, YubiKeyPrompt 7, SensitiveConfirm 5, Inspect 5,
Files 5, Sign 4, SecurityInfo 4, SecurityKeyPin 4, Licenses 2, Help 2, QrScanner 2,
Onboarding 1; Help/SecurityInfo/Licenses/Onboarding copy in Kotlin lists; tab labels in
`AgeTab.kt:22-27`. Hand plurals: `MigrateFlow.kt:135,196`, `DecryptFlow.kt:661`,
`RecipientsScreen.kt:461`, `SignersScreen.kt:106,124,316`, `RecentlyDeletedScreen.kt:181`,
`InspectFlow.kt:183`, `TransferScreens.kt:460` ("1 identities"), `PaperScreens.kt:394`;
`EncryptFlow.kt:612` lowercases a sentence. `SafIo.humanSize` has no locale and returns "—".
Em/en dashes (18): `SettingsScreen.kt:394`, `NotesScreen.kt:402`, `MigrateFlow.kt:282`,
`SafIo.kt:159`, `DecryptFlow.kt:679`, `EncryptFlow.kt:486,487,784`, `IdentitiesScreen.kt:408`,
`RecipientsScreen.kt:260`, `TextScreen.kt:79,352`, `VaultGate.kt:417`, `VerifyFileFlow.kt:197`,
`vault/Hydration.kt:128,132,134`. Tropes: "Get started" `OnboardingScreen.kt:158`; "No accounts.
No servers. No tracking." `:92`; "a friendly age client" `HelpScreen.kt:27`; taglines
`SettingsScreen.kt:695,699,701`; "Danger zone" `:757`.

## 15-17. Behavior and states
Thumb-only switches (10): `SettingsScreen.kt:998` (SettingRow, used 5 times),
`IdentitiesScreen.kt:530,612,623,706`, `NotesScreen.kt:299,434`, `EncryptFlow.kt:482`,
`RecipientPicker.kt:241`, `RecipientsScreen.kt:497`. Control-only checkbox
`TransferScreens.kt:703,739`, `SignersScreen.kt:323`; radio `PaperScreens.kt:130,134`,
`SettingsScreen.kt:532,539`. Small targets `SettingsScreen.kt:1063,1039,710-713` (about 36dp),
`:611-615` (44dp). Squashed spinner `RecipientsScreen.kt:435`. Version fallback "1.0"
`SettingsScreen.kt:101`. Duplicate copy confirmation on API 33+ `KeyBlock.kt:94`,
`TextScreen.kt:437`; none at `PassphraseOnlyScreen.kt:127`, `TransferScreens.kt:305`. Deletes
without confirmation `RecipientsScreen.kt:253`, `NotesScreen.kt:333`. Headings smaller than
rows: titleSmall over bodyLarge at `SettingsScreen.kt:976`, `RecipientPicker.kt:531`,
`EncryptFlow.kt:386,413,464`, `TextScreen.kt:175`, `MigrateFlow.kt:111,133,140,149`,
`TransferScreens.kt:331,352,377,399`, `PaperScreens.kt:117,384`, `SignFileFlow.kt:152`; four
different screen-title styles. Empty states exist on all five main lists; error states are
mostly raw text; GitHub fetch has no "found none" message.

## Bugs found
System back exits the app from every sub-screen; keyboard covers bottom fields; light-mode
splash is dark teal; deletes without confirmation on Recipients and Notes; "1 identities".
