# AgePony 5.1.0 plan (Rev 1)

versionCode 18, versionName 5.1.0. Joint release with iOS 5.1.0, same number on both stores as
with 5.0.1. The iOS side is `AgePony_iOS_5.1.0_Plan.md` in the iOS repo. As before, the Kotlin
here is the reference implementation for anything both platforms share.

Starting point: Android 5.0.1 (tag `v5.0.1`). iOS 5.0.1 is built and its store metadata is
committed, but the iOS repo has no `5.0.1` tag yet (last tag `4.0.1`).

Last updated: 2026-10-16 (Rev 1, drafted). Nothing below is decided except where it says so.

---

## Status

| Item | State |
| --- | --- |
| 1. YubiKey PIN before the tap | Done in RC2 (unit tests; device pass waits on a working YubiKey). |
| 2. YubiKey PIV over USB-C | Moved to 5.2.0, blocked on hardware (see 2.4). |
| 3. Picker rows show key material | Done in RC2, including the Sign and encrypt-signer pickers. |
| 4. GitHub issue housekeeping | To do, no build needed. |
| 5. Carryovers | Listed, not triaged. |
| U1 to U9 | UI restyle (no generated look), see `AgePony_5.1.0_UI_Plan.md` in the iOS repo; inventory in `AgePony_5.1.0_UI_Inventory_Android.md`. |
| E3, E7 (Q4) | From a professional evaluation, see `AgePony_5.1.0_Evaluation_Requests.md` in the iOS repo. E7 proposed for RC1. |

## RC breakdown (Rev 2, Oct 28)

One RC at a time. RC2 is not started until RC1 is built and tested.

- **RC1 (built, device pass green):** UI foundations (U2, U3, U6), Sign folded into Files,
  every string in resources (U1, six `strings_*.xml` files), Files tab with Encrypt/Decrypt
  buttons and the tool list, E7 CCTV vectors and the all-zero X25519 check in `agepony-core`.
- **RC2 (built, device pass green Oct 29):** screens and errors (U4, U5); item 1 (PIN before the tap, `pinPolicy` in
  `agepony.json` matching iOS); item 3 (picker rows); a strong-biometric-only lock to match iOS
  Face ID only (Q4, now in scope); and the iOS 5.1.1 follow-ups below.
- **Item 2 (USB-C) moves to 5.2.0** (Q1): there is no working USB-C YubiKey to build it against.

### iOS 5.1.1 follow-ups (from the internal 5.1.0 review, Oct 28)

Check each on Android and fix in RC2 where it applies:

- First app password: can it be set without a biometric/device-credential check, and do the
  owner re-checks then trust it (iOS H-1)?
- Decrypted temp files: swept at launch and on lock, created with the tightest storage the
  flow allows, and dropped when a screen closes mid-decrypt (iOS M-2)?
- ssh-ed25519 small-order keys: Android already refuses them (`keyExchangeOrNull`); add the
  same three test keys as iOS (`EC FF..FF 7F`, 32 zero bytes, an order-8 point) so both cores
  pin it (iOS M-1).
- A Keystore hardware key that can't decrypt: does it hide the YubiKey tap (iOS M-4)?
- Cap tag-matching stanzas per hardware key at 4 and skip a key after its first error; never
  resend PIV VERIFY or CTAP clientPIN after a lost NFC reply (iOS L-7, L-8).
- Text decrypt verifies signatures; scrypt memory guard on every passphrase decrypt; failed
  signature shown as a failure (iOS L-1, L-2, L-3).

---

## 1. YubiKey: ask for the PIN before the tap

**Source:** user email, Oct 16 2026 (credit as "a user report"). Same request applies to iOS.

### What happens now

`security/piv/YubiKeyBroker.ecdh` sends the first tap with no PIN. When the slot answers
`PinRequiredException`, the broker asks for the PIN and the user taps again. The serial goes into
an in-memory `needsPin` set, so later decrypts in the same process ask first. After the process
dies, the double tap is back.

The reason for trying without a PIN: the 9-byte stub doesn't carry the slot's PIN policy, and a
`Never` key shouldn't be asked for a PIN it doesn't use. The problem: age-plugin-yubikey's
default is `Once`, and every NFC tap is a new PIV session, so a default key needs the PIN on every
tap. Nearly every user gets the failed first tap. PGPony never had this because an OpenPGP card
always wants PW1 for decryption.

iOS is worse: `DecryptIdentities.prepare` clears `yubiKeyPIN` after each decrypt and remembers
nothing, so every YubiKey decrypt on iOS is two taps.

### Change

1. New optional field on a `YUBIKEY_PIV` identity: `pinPolicy`, one of `unknown`, `required`,
   `notRequired`. Missing means `unknown`. `Vault` already decodes with `ignoreUnknownKeys`, so a
   5.0.1 build reading a 5.1.0 vault drops the field instead of failing.
2. Where the policy comes from, in order:
   - **Import from an identity file:** age-plugin-yubikey writes `#    PIN policy: Never|Once|Always`
     in the comment block. `Never` gives `notRequired`, the other two give `required`. Parse it in
     the same pass that reads the `# Recipient:` line.
   - **Import tap:** when the import already taps the key to read the public key, also send PIV
     GET METADATA (INS `F7`, P2 = slot) on firmware 5.3+. Tag `02` byte 0 is the PIN policy
     (1 never, 2 once, 3 always, 0 slot default, which counts as `required`). Older firmware
     answers `6D00`; leave the policy `unknown`.
   - **Learned at decrypt:** a tap with no PIN that succeeds sets `notRequired`; a
     `PinRequiredException` sets `required`.
3. Decrypt:
   - `required` or `unknown`: PIN dialog first, then one tap that runs VERIFY and the ECDHs.
   - `notRequired`: one tap, no PIN. If the key answers `PinRequiredException` anyway (policy
     changed on the key), set `required`, ask, tap again. That fallback stays as the safety net.
   - For `unknown` only, the PIN dialog gets a "This key has no PIN" action that taps without
     one (Q2).
4. Drop the in-memory `needsPin` set.
5. The PIN is never stored and never kept past the operation (unchanged).
6. Key transfer: carry `pinPolicy` in `agepony.json` as an optional field. Older readers ignore
   it. Note it in `docs/TRANSFER_FORMAT_v1.md`.

### Acceptance

- A key made with age-plugin-yubikey defaults (`Once`) decrypts with the PIN dialog first and
  exactly one tap, on the first decrypt after import and after the app is killed.
- A `Never` key imported from its identity file decrypts with one tap and no PIN dialog.
- A 5.0.1 vault's existing YubiKey identity (no field) gets the PIN dialog first.
- Wrong PIN shows tries left; the blocked-PIN message is unchanged.
- Unit tests: comment parsing for all three values plus a file without the line; GET METADATA
  parsing for each policy byte and for `6D00`.

## 2. YubiKey PIV over USB-C

**Source:** same email (the reporter uses mTLS from the YubiKey's PIV applet over USB-C). Oct 1
decision Q3 was "NFC only, USB-C on both platforms later". This is the "later".

### 2.1 Shape

`Piv.Card` is already a transceive closure, so the PIV logic doesn't change. What's new is a
second transport and a prompt that covers both: "Hold your YubiKey to the phone or plug it in".
Whichever arrives first wins. Same serial check either way.

### 2.2 Android

- USB host CCID transport: find the CCID interface (class `0x0B`), bulk in/out endpoints,
  `PC_to_RDR_IccPowerOn` then `PC_to_RDR_XfrBlock` per APDU, chained responses through the same
  bounded reader as NFC (audit L-11 caps apply).
- Reuse PGPony Android's USB smart-card transport rather than writing one. It has carried a
  Nitrokey 3 USB fix since 4.6.4, so it has seen real hardware.
- `UsbManager.requestPermission` on attach, `device_filter.xml` for Yubico (vendor `0x1050`),
  `android.hardware.usb.host` declared `required="false"` so phones without host mode can still
  install.
- Listen only while a YubiKey prompt is open, the same as reader mode for NFC.
- Update the `YubiKeyBroker` header comment that says USB-C needs a CCID stack AgePony doesn't
  have.

### 2.3 What's out

- FIDO (`sk-` signing keys) over USB HID: possible on Android, not on iOS. Q4.
- Import over USB (reading the public key): include it if it falls out of the shared transport,
  otherwise NFC and the identity file stay the import paths.

### 2.4 Blocker

No working USB-C YubiKey on hand (broken, Oct 2026). RC2 needs either a replacement or the
reporting user testing an RC build. Both platforms get tested on real hardware before release.

## 3. Picker rows show key material

**Source:** user email, Aug 1 2026. Written up on the iOS side as `PLANNED_FEATURES.md` item 1,
which marked Android "not yet surveyed". Surveyed Oct 16:

| Surface | File | Row today |
| --- | --- | --- |
| Active identity | `ui/settings/SettingsScreen.kt:624` (`DropdownMenuItem`) | name only |
| Encrypt to self | `ui/files/RecipientPicker.kt:356` (`CheckRow`) | name + type label |

The transfer preview (`ui/portability/TransferScreens.kt:363`) already gets it right:
`typeLabel · keySummary` under the name. Reuse `KeyPortability.keySummary` rather than adding a
helper.

The active-identity dropdown is the worst one, same as the iOS `Picker` rows: two same-named
identities render as two identical lines.

Same rule as iOS: name, type in words, then the existing short public string. No new truncation
helper. Two identities with the same name and type must be told apart in every picker without
leaving it, with a Compose UI test that asserts the two rows differ.

## 4. GitHub issue housekeeping

Still open on GitHub although the work shipped. Pull each thread and its comments before drafting
any reply, then close with a short note of the version that fixed it.

| Issue | Shipped in |
| --- | --- |
| #10 age-plugin-yubikey identities | 5.0.0 |
| #11 sign+encrypt not age compatible | 5.0.0 (sig stanza), v2 in 5.0.1 |
| #12 scrypt OOM / silent crash | 5.0.0 |
| #13 PIN required for passphrase work | 5.0.0 (passphrase mode from the lock screen) |
| #14 share support | 5.0.0 |
| #15 can't verify, no fingerprint | 5.0.1 (README "Verifying your download") |
| #3 blank screen after switching apps | Possibly 5.0.1 (process-wide auto-lock, H-3). Reproduce on 5.0.1 first. |

## 5. Carryovers (to triage)

- **Evaluation requests** (`AgePony_5.1.0_Evaluation_Requests.md` in the iOS repo): E7 adds the
  C2SP CCTV age vectors to `agepony-core` tests (decided, told the user). E3: the `v5.0.1`
  GitHub release text calls the review a "full security audit"; reword it to "internal security
  review" and link `SECURITY_REVIEW_2026-09-23.md`. Q4: a strong-biometric-only lock to match
  iOS E6, not promised.

- RelayPony still pins agepony-core below 5.0.1 (`AgePony_5.0.1_Plan.md` section 7). Bump and
  test there, not here.
- Clipboard auto-clear: Android has `ClipboardGuard`. iOS `PLANNED_FEATURES.md` item 3 wants a
  regression test for every clipboard write; consider the same on Android.
- iOS-only carryovers are in the iOS plan.

## 6. Build and test

```
./gradlew clean :agepony-core:test :app:testFossDebugUnitTest :app:compilePlayReleaseKotlin :app:assembleFossRelease :app:bundlePlayRelease
```

Device pass for RC1: item 1 acceptance with an NFC YubiKey (default key, `Never` key, a 5.0.1
vault upgraded in place, wrong PIN, kill and reopen between decrypts); item 3 with two
same-named identities; one full R8 smoke pass (unlock, encrypt/decrypt, YubiKey, FIDO, share).

## 7. Decisions and open questions

- **Q1. USB-C timing:** in 5.1.0 as RC2, or its own 5.2.0? Hinges on getting a USB-C YubiKey.
- **Q2. Unknown policy (decided Oct 26):** ask for the PIN first, with a "This key has no PIN"
  action. Applies to both platforms.
- **Q3. GET METADATA on the import tap (decided Oct 26):** yes, on both platforms.
- **Q4. FIDO over USB on Android:** in scope for RC2, or PIV only?

## 8. Credit

User reports by email (Aug 1 and Oct 16 2026) and GitHub issues by number. No personal names in
anything shipped or committed.
