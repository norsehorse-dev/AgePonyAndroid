# AgePony 5.2.0 plan (Rev 2)

Started Oct 29 2026. Rev 2 (Oct 31): 5.1.1 is folded in and never ships on its own. Everything
built for it (six languages, the language picker, fastlane, the onboarding identity step) ships as
5.2.0, versionCode 19. One RC at a time: the next RC's work doesn't start until the current one is
built and tested on device.

## Status

| Item | State |
| --- | --- |
| 0a. Six languages, live language picker, fastlane and screenshot tooling | Done, RC1 (`4ea469f`, built and device-tested as 5.1.1 RC1). |
| 0b. Onboarding identity step (generate any kind, import, receive, paper restore) | Written, RC2. Needs its build and device pass. |
| 1. YubiKey PIV over USB-C | Planned. Moved from 5.1.0 item 2. Blocked on hardware. |
| 2. FIDO security keys over USB-C | Planned. Android only. |
| 3. Security keys when signing while encrypting | Planned. iOS `PLANNED_FEATURES.md` item 5. |
| 4. Sign text | Planned. iOS `PLANNED_FEATURES.md` item 5. |
| 5. More than one "Also encrypt to" key | Planned. iOS `PLANNED_FEATURES.md` item 4; Android has no "Also encrypt to" setting yet. |
| 6. Hide file name | Planned. iOS `PLANNED_FEATURES.md` item 6 (iOS 5.2.0 in progress). Same bytes on both. |

## RC breakdown

- **RC1 (done):** languages, picker, fastlane, demo seeding, screenshot script.
- **RC2:** the onboarding identity step. Build, device pass, commit.
- **RC3:** items 6, 5, 4 and 3 (encrypt-side features shared with iOS 5.2.0). Strings for the RC
  translated into all six languages with several agents, then the checker.
- **RC4:** item 2 (FIDO over USB-C), and item 1 if a working USB-C YubiKey turns up.
- **Release prep:** What's new `19.txt` in seven languages grows with each RC; screenshots with
  `bundle exec fastlane screenshots` on an Android 13+ emulator; listing and screenshots with
  `fastlane metadata`; the translated 5.1.0 What's new (`18.txt`) can go up any time with
  `fastlane whats_new version_code:18`; GitHub release notes; signed APK and Play bundle.

---

## 1. YubiKey PIV over USB-C

Moved from 5.1.0 (see `AgePony_5.1.0_Plan.md` section 2 for the full write-up): a USB CCID
transport next to NFC behind the existing `Piv.Card` transceive closure, one prompt for both
("Hold your YubiKey to the phone or plug it in"), reusing PGPony Android's `UsbCcidCardTransport`
and `UsbCardConnection`.

**Blocker:** no working USB-C YubiKey on hand. It ships only after a real-hardware test, either on
a replacement key or by a user testing an RC build.

## 2. FIDO security keys over USB-C

**Source:** our own planning, Oct 29 2026. 5.1.0 left this as open question Q4.

Today the `sk-ssh-ed25519` and `sk-ecdsa-sha2-nistp256` identities (enrol, sign) only talk to a
key over NFC (`security/nfc/SecurityKeyTransport.kt`, CTAP2 over ISO-DEP). A key plugged into
the USB-C port should work the same way.

### 2.1 Shape

CTAP2 itself doesn't change: `Ctap2`, `Cbor`, `CoseKey` and `PinProtocolV1` in `agepony-core`
already build and parse every message. What's new is a second transport that carries the same
CBOR request and response bytes, and a prompt that offers both: "Hold your security key to the
phone or plug it in". Whichever arrives first wins.

### 2.2 Android

- **CTAPHID transport** (FIDO CTAP 2.1, section 11.2). New `security/usb/CtapHidTransport.kt`:
  64-byte HID reports over the interrupt IN and OUT endpoints; `CTAPHID_INIT` on the broadcast
  channel `0xFFFFFFFF` with an 8-byte nonce to get a channel ID; `CTAPHID_CBOR` (0x10) carrying
  the CTAP2 command; init packet plus continuation packets (sequence 0 to 127) both ways;
  `CTAPHID_KEEPALIVE` (0x3B) handled while the user is asked to touch the key; `CTAPHID_CANCEL`
  when the prompt is dismissed; `CTAPHID_ERROR` mapped into the existing `UserMessage` errors.
- **Finding the key:** match HID interfaces (class `0x03`) and confirm the FIDO usage page
  `0xF1D0` from the report descriptor, rather than a vendor list, so any FIDO2 key works (YubiKey,
  Token2, Nitrokey, SoloKeys). `device_filter.xml` for attach intents, `UsbManager.requestPermission`
  on attach, `android.hardware.usb.host` declared `required="false"`.
- **Same safety rules as NFC:** the response reader is bounded the same way (5.1.0 L-11 caps), a
  lost reply is never answered by resending clientPIN or getAssertion (`NfcResendPolicy` becomes a
  transport-neutral resend policy), and USB is listened for only while a security-key prompt is
  open.
- **Prompt:** `SecurityKeyService` takes a transport chooser instead of opening NFC directly. The
  PIN step (CTAP 0x36 and the clientPin handshake) is unchanged and runs over whichever transport
  answered.
- **Touch:** over USB the key needs a touch for user presence (over NFC the tap is the presence).
  The prompt says so while keepalives report `UPNEEDED`.
- **Share both transports with item 1** where they overlap: one USB attach listener and one
  permission flow serve PIV (CCID) and FIDO (HID).

### 2.3 iOS

Not possible: iOS gives apps no raw USB HID access to a security key (only the system WebAuthn
APIs, which don't produce SSHSIG). iOS stays NFC for FIDO. Say so in the iOS plan so the two
apps' notes stay honest.

### 2.4 Acceptance

- Enrol a new `sk-ssh-ed25519` identity with a key plugged into USB-C, with and without a FIDO2
  PIN set on the key.
- Sign a file with it over USB-C; the signature verifies with `ssh-keygen -Y verify -n agepony`
  and in the app.
- The same identity signs over NFC and over USB-C interchangeably.
- Unplugging mid-request gives a whole-sentence error, nothing hangs, and the prompt can be
  retried.
- Wrong PIN shows tries left; a blocked PIN gives the existing message.
- Unit tests: CTAPHID packet split and reassembly (including a response that needs continuation
  packets), INIT nonce check, keepalive handling, error frames, and the report-descriptor usage
  page check.
- Tested on real hardware: the Token2 on hand if it has a USB connector, plus any second FIDO2
  key available.

## 3. Security keys when signing while encrypting

See iOS `PLANNED_FEATURES.md` item 5. On Android `FileSigner.ENCRYPT_SIGNING_TYPES` leaves out
`sk-*`; the tap (or, with item 2, the touch over USB) goes between the hashing pass and the encrypt
pass. Needs a hashed entry point on `SecurityKeyService`.

## 4. Sign text

See iOS `PLANNED_FEATURES.md` item 5: a Sign mode on the Text screen producing an armored SSHSIG,
the matching text verify, and "Sign as" on Text encrypt. Android and iOS together.

## 5. More than one "Also encrypt to" key

See iOS `PLANNED_FEATURES.md` item 4. Android has no "Also encrypt to" setting yet, so it lands
here in the multi-key shape from the start: a list of recipient IDs applied by Files encrypt, Text
encrypt and the share sheet.

## 6. Hide file name

See iOS `PLANNED_FEATURES.md` item 6 for the decisions and the format (`agepony.com/name v1`
stanza for public-key recipients, a small tar wrapper for unsigned passphrase files, random hex
outer name or a typed one, numbered for one-file-each batches). Android mirrors it byte for byte:
`agepony-core` gets `naming/NameStanza.kt` (the iOS file already names it as its mirror) and the
named bundle, both pinned by the same test vector as iOS. A file iOS encrypts with a hidden name
must open under its real name on Android and the other way round; that is the RC3 acceptance test.

## Credit

User reports by email and GitHub issues by number. No personal names in anything shipped or
committed.
