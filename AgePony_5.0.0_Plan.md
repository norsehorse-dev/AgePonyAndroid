# AgePony 5.0.0 plan

Working document for the 5.0.0 release, Android first with iOS parity tracked per
feature. Target `versionCode 16`, `versionName 5.0.0` (4.3.0 never shipped, so 5.0.0
takes its code). Current shipped: `versionCode 15`, `versionName 4.2.0`.
Last updated: 2026-09-22.

This plan absorbs everything in `AgePony_4.3.0_Plan.md`. That file stays in the repo
as the detailed reference for the signature-stanza format (its sections 3 to 9) and the
scrypt memory fix (section 10). Nothing here contradicts it.

Headline: keys you can hold in hardware, move between devices, and put on paper, plus
AgePony in the share sheet.

---

## Build status (2026-09-22, first pass)

Written and compiling; not yet run on a device. Core tests: 379, all green (in a JVM mirror
of agepony-core), including live round trips against the age 1.3.0 CLI and its tagtest plugin.
The app was compiled (foss flavor) against the Gradle cache, but has not been built by Gradle
or run on a device yet.

| Item | State |
| --- | --- |
| A. Signature stanza | Plain `age` 1.3 decrypts an AgePony signed file to the bare bytes (`AgeCliInteropTest`) |
| B. #12 | Done earlier |
| C. #13 | Lock screen has "Continue without unlocking": passphrase text encrypt/decrypt and passphrase file decrypt, vault stays locked (also offered when a share arrives at a locked app) |
| D. Share | `share/` package + `ShareActivity`: SEND, SEND_MULTIPLE, PROCESS_TEXT (replace selection with ciphertext). Plaintext share-out is behind a warning dialog |
| E. Tag recipients | Core `crypto/HpkeP256.kt`, `recipients/Tag.kt`; reproduces age's tagtest recipients byte for byte; interop both ways with age 1.3 |
| E. Keystore keys | `HardwareTagKeyService`, classic and hybrid, API 31+, optional auth (off by default, 30 s window, not invalidated by biometric re-enrollment) |
| E. YubiKey decrypt | Import `AGE-PLUGIN-YUBIKEY-1…` (one tap reads the slot's key), decrypt `piv-p256` and `p256tag` over NFC, PIN asked when the slot wants it. Core `piv/Piv.kt`, `recipients/YubiKey.kt`, tested against a simulated PIV card. USB-C not yet |
| F. Transfer | Core `portability/KeyTransfer.kt` + Settings › Send / Receive keys |
| G. Paper backup | Core `portability/PaperBackup.kt`; PDF from Identity detail; Settings › Restore from a paper backup. X25519 and PQ only (SSH left out, decision 5) |
| Version | versionCode 16, versionName 5.0.0 |

Other changes made along the way:

- The vault is now one instance per process (`SharedVault`), so the share activity and the main
  activity can't overwrite each other's saves.
- Wiping the vault (reset and duress) now deletes AgePony's Keystore keys too. Purging an identity
  from Recently deleted deletes its Keystore key. Before this, hardware signing keys were never
  removed from the Keystore.
- Decrypt tries software identities first and tag identities last. A cancelled or invalidated
  hardware key no longer blocks a file that another key in the vault can open.
- Pasting `age1yubikey1` as a one-time recipient in the recipient picker used to fail (it went
  to the X25519 parser). Fixed alongside the tag prefixes.
- New vault enum values (`hardwareTag`, `hardwareTagPQ`, recipient `tag`, `tagPQ`) mean a
  vault that holds one can't be opened by a pre-5.0 build. That's the same as when the sk-* types
  were added.

Decisions settled 2026-09-22: #13 gets the passphrase-only mode; YubiKey decrypt is in 5.0.0;
hardware keys default to quantum-safe with unlock-per-use off; SSH keys stay out of paper
backups; plaintext share-out stays, behind the warning.

## 0. Scope at a glance

| # | Item | Origin | State (Sep 22) |
| --- | --- | --- | --- |
| A | Signature stanza `agepony.com/sig v1` | 4.3.0, issue #11 | Core + flows implemented in the working tree, uncommitted. Cross-impl fixture and iOS mirror left |
| B | Scrypt decrypt memory guard | 4.3.0, issue #12 | Done, unit tests green |
| C | PIN prompt on passphrase ops | 4.3.0, issue #13 | Not started, confirm behavior in code first |
| D | Share sheet support | 4.3.0, issue #14 | Headline feature, section 1 |
| E | Hardware-bound identities (age `p256tag` / `mlkem768p256tag`) + YubiKey decrypt | New | Section 2 |
| F | Identity transfer between devices | Jul 2026 user request | Section 3 |
| G | Paper backup | New | Section 4 |

## 1. Share support (issue #14)

The reasoning in 4.3.0 section 12 stands. Summary of what ships:

- Intent filters for `ACTION_SEND` and `ACTION_SEND_MULTIPLE` (text and files), plus
  `ACTION_PROCESS_TEXT` so "AgePony" shows in the text-selection menu for armored
  blocks. Everything handled in memory, nothing written to app storage.
- Incoming ciphertext: detect age binary or armor, open the decrypt sheet directly.
- Incoming plaintext: open the encrypt sheet with the recipient picker.
- Outgoing ciphertext: share out via `ACTION_SEND`, armored for text, binary for files.
- Outgoing plaintext: the one direction to gate. Options: allow with a one-time warning,
  allow for text only, or leave out and offer copy (with clipboard auto-clear) instead.

Safety rules for the receive path:

- Treat every incoming payload as hostile. The #12 pre-flight guard already sits on all
  passphrase decrypt paths, so a shared file with a huge scrypt work factor gets a clean
  refusal. Add a size cap for in-memory handling and route anything larger to the
  streaming path.
- Vault lock applies: a share into a locked app shows the lock screen first, then resumes
  the share.
- Signed files arriving by share get the same verify-on-decrypt verdict as the Files tab.

iOS: the project already has a share-extension target (its deployment target was
lowered in 4.0.1). Confirm what it does today and whether it was stubbed out when share
was cut, and recover the original reason share was cut before building on it. Mirror
PGPony iOS's share extension where it makes sense.

## 2. Hardware-bound identities

### 2.1 What the spec gives us

age v1.3.0 added two recipient types meant for hardware keys (C2SP `age.md`):

| Type | Recipient | Stanza | Encoding |
| --- | --- | --- | --- |
| Classic | `age1tag1...` | `p256tag`, args: 4-byte tag, 65-byte HPKE enc | compressed P-256 point, 33 bytes |
| Hybrid PQ | `age1tagpq1...` | `mlkem768p256tag`, args: 4-byte tag, 1153-byte enc | ML-KEM-768 encaps key + uncompressed P-256 point, 1249 bytes |

- HPKE: DHKEM(P-256, HKDF-SHA256) or MLKEM768-P256, HKDF-SHA256, ChaCha20-Poly1305.
  Info labels `age-encryption.org/p256tag` and `age-encryption.org/mlkem768p256tag`.
- The tag is a truncated HKDF-Extract over `enc || SHA-256(recipient)[:4]` (hybrid hashes
  only the P-256 part). It lets an identity find its stanza without a trial ECDH, which
  matters when each ECDH is a hardware call behind a user-auth prompt.
- Identities are plugin-defined. The spec says nothing about identity encoding, so how
  AgePony stores a hardware identity is ours to decide.
- The spec says not to mix hybrid and non-PQ recipients in one file. AgePony already
  deals with this for `mlkem768x25519`; apply the same rule to the tag types.
- Stock age 1.3 can encrypt to both types natively, no plugin needed. So an Android phone
  holding an `age1tag1` key becomes a recipient anyone with upstream age can encrypt to.
  age-plugin-yubikey, age-plugin-se and age-plugin-tpm are adding these types too, so
  AgePony can also encrypt to those devices.

Pin every constant to the spec text before locking fixtures, and generate cross-impl
vectors with `age` 1.3 and `age-plugin-tagtest`.

### 2.2 Android implementation

- Recipient side (encrypt to `age1tag1` / `age1tagpq1`): pure software in
  `agepony-core`, next to `P256.kt` and `HpkeMlkem768X25519.kt`. Needs HPKE with the
  P-256 DHKEM and the MLKEM768-P256 combiner. Works on every supported API level.
- Identity side, classic: Android Keystore EC P-256 key with `PURPOSE_AGREE_KEY`
  (API 31+). StrongBox when `FEATURE_STRONGBOX_KEYSTORE` is present, TEE otherwise, and
  the key detail screen says which. Decrypt = Keystore `KeyAgreement("ECDH")` for the raw
  shared secret, then HPKE key schedule in software. Key never leaves the chip.
- Identity side, hybrid: Keystore has no ML-KEM as far as I know (check API 37). The
  ML-KEM seed would live in the vault, encrypted like other identities, with the P-256
  half in hardware. Decryption needs both. Decide whether that is worth shipping or
  whether 5.0.0 does classic hardware identities only (see open decisions).
- User auth: per-use biometric/device credential via
  `setUserAuthenticationParameters`, or a timeout, as a per-key option.
- minSdk stays 26. Hardware identity creation is hidden below API 31; encrypting to tag
  recipients works everywhere.
- Stored identity record: Keystore alias, recipient string (needed for the tag), label,
  created date, StrongBox/TEE flag, auth policy.

### 2.3 YubiKey decrypt

Today `P256.kt` encrypts to `age1yubikey1` (`piv-p256`) but cannot decrypt. With the
hardware-identity plumbing in place, add PIV decrypt over NFC and USB-C:

- Import the `AGE-PLUGIN-YUBIKEY-1...` identity stub (serial, slot, tag), which is only a
  reference, not a secret.
- PIV APDUs: SELECT PIV, VERIFY PIN, GENERAL AUTHENTICATE (ECDH) on the stub's slot. The
  existing NFC transport from the CTAP2 stack should carry it.
- Support both `piv-p256` and the new `p256tag` stanzas, since age-plugin-yubikey is
  moving to the latter.
- Check iOS 4.0.0 first: its device-test list included a YubiKey real-device decrypt, so
  iOS may already have PIV code to port from.
- Only YubiKey and Token2 hardware has been tested so far. Say so in release notes.

Decision: YubiKey decrypt in 5.0.0 or next minor. It is additive and self-contained.

### 2.4 Loss warning

A hardware key cannot be backed up or moved (sections 3 and 4 exclude it by design).
Creating one shows a clear warning: lose the phone, lose anything encrypted only to that
key. Offer "also encrypt to a backup recipient" as a saved default in the encrypt sheet,
respecting the no-mixing rule (a hybrid tag key pairs with a PQ backup key).

### 2.5 iOS

iOS already has Secure Enclave P-256 keys. Find out what recipient format they use
today. If it is custom, 5.0.0 moves them to `age1tag1` so they interop with Android,
upstream age and age-plugin-se, with a migration path for existing SE keys (the existing
re-encrypt migration flow is the model). Check whether iOS 26 CryptoKit's Secure Enclave
support for ML-KEM can hold the hybrid half, which would make iOS fully hardware-backed
where Android is not.

Also fold in the reported iOS lag where Copy and QR on a Secure Enclave key's public-key
screen do not respond for a while. Same shape as PGPony #36: move the work off the main
thread and show immediate feedback.

## 3. Identity transfer between devices

From a Jul 2026 user request: move identities to another device by encrypting them to a
key the receiving device holds, not by copying secrets around in the clear.

### 3.1 Flow

1. Receiving device (phone, iPhone or AgePony Desktop): "Receive keys". It makes a
   one-time transfer key (hybrid PQ, `age1pq1...`) kept only in memory, and shows it as
   a QR plus a short fingerprint phrase.
2. Sending device: "Send keys", pick which identities (and optionally recipients,
   trusted signers, labels), re-authenticate, scan the QR, compare the phrase.
3. Sender writes a normal age file encrypted to the transfer key and sends it straight to
   the receiver over the local network (RelayPony framing; the QR carries address, port
   and a one-time token; the receiver opens it before acknowledging). Share sheet, file,
   AirDrop or USB remain as the fallback when the phones share no network.
4. Receiver opens it, shows what is inside, imports on confirm, and forgets the transfer
   key. The transfer key expires on a timer if nothing arrives.

The fingerprint phrase guards against a swapped QR. Reuse the diceware wordlist for it.

### 3.2 Bundle format (`agepony.com/transfer v1`)

A tar inside the age file (tar support already exists):

- `identities.txt`: a standard age identity file (`AGE-SECRET-KEY-1...`,
  `AGE-SECRET-KEY-PQ-1...`, with `# created` / `# public key` comments). Plain
  `age -d` on the bundle gives a file that works with `age -i`, so the transfer is useful
  even without AgePony on the other end.
- `ssh/`: SSH private keys in OpenSSH format, if selected.
- `agepony.json`: versioned metadata. Labels, recipients, trusted signers, YubiKey stubs.

This is a wire format shared across Android, iOS and Desktop, so spec it once in this
repo and mirror it, the same way as the signature stanza.

### 3.3 What never moves

Keystore and Secure Enclave identities (they cannot). YubiKey stubs can move, since they
are only references. The vault password, duress password and app settings stay per
device.

### 3.4 Later

Direct device-to-device delivery over PonyDirect on the LAN, skipping the file hop.
Not in 5.0.0.

## 4. Paper backup

A printable page per identity, restorable by scanning.

- Default mode: passphrase-protected. The identity file is encrypted with scrypt
  (work factor 18) and armored, then shown as a QR plus the armored text. Restore with
  AgePony or with plain `age -d`, so the paper outlives the app. Offer the diceware
  generator for the passphrase, with a reminder that the passphrase must be stored
  somewhere other than the paper.
- Plain mode: the raw `AGE-SECRET-KEY` string, behind a strong warning that the paper is
  the key. Some people want this for a safe or safe-deposit box.
- Sizes are fine for a single QR. X25519 and PQ identities are both 32-byte seeds, and
  the scrypt-armored version stays small. SSH RSA private keys are the large case; decide
  whether they are in scope or X25519/PQ only.
- Page content: label, public key (so the owner can check which key it is), created
  date, mode, restore instructions, QR, and the text in chunked groups for manual typing
  (Bech32 checksum catches typos).
- Output: render with `PdfDocument` in memory. The Android print path spools through the
  print service and can reach cloud printers, so warn about it and prefer "save as PDF"
  to a user-chosen location or a direct local printer. Passphrase mode makes this much
  less risky, which is another reason it is the default.
- Restore: "Restore from paper" scans the QR (existing scanner), asks for the passphrase
  and imports. Manual text entry as a fallback.
- Hardware identities show "cannot be backed up, it lives in this device's chip" in
  place of the backup option. YubiKey stubs can be printed as a plain reference.

## 5. How E, F and G fit together

| Identity kind | Transfer (F) | Paper backup (G) |
| --- | --- | --- |
| Software X25519 / PQ | yes | yes |
| SSH key | yes | decide |
| Keystore / Secure Enclave | no, by design | no, by design |
| YubiKey stub | yes (reference only) | reference only |

The honest message across all three: software keys are portable and recoverable,
hardware keys are not, and the app says so where it counts.

## 6. Items carried from 4.3.0

- **A. Signature stanza.** Implemented in the working tree. Left: add the real
  `age`/`rage` round-trip to `generate-fixtures.sh`, the signer-privacy and tamper tests
  from 4.3.0 section 7 if not all present, commit, then the iOS mirror. The stanza type
  string in code is `agepony.com/sig v1`; treat that as locked once fixtures are
  committed.
- **B. #12.** Done. Add the device-level check from 4.3.0 section 10 (clean refusal on
  `aesop.age` under a constrained profile) to the release device tests.
- **C. #13.** Confirm in code whether a passphrase op prompts for the app PIN on top of
  the passphrase while the vault is already unlocked. If yes, skip the second prompt for
  passphrase-only operations in an unlocked session. Global lock unchanged.
- **D. #14.** Section 1.

## 7. Docs and housekeeping

- README "Not implemented on purpose" says there is no share sheet. Rewrite it.
- README calls `mlkem768x25519` "an AgePony extension" that stock age will not read. age
  1.3 ships the same stanza, and AgePony's `age1pq1` / `AGE-SECRET-KEY-PQ-1` encodings
  match. Confirm with a round-trip against `age` 1.3 (`age-keygen -pq`) and fix the line.
  This is also good release-note material.
- In-app Help and Security screens: sections for hardware keys, transfer, paper backup.
- Play and F-Droid descriptions: new features; the share sheet does not add network
  access.
- iOS files sit at the Android repo root (`AgePonyShareExtension-Info.plist` and
  `PrivacyInfo.xcprivacy` are tracked; `AgePonyShareExtension/` and the iOS test folders
  are empty). Remove or move them.

## 8. Tests

Hold the cross-implementation bar:

- Tag recipients: vectors from `age` 1.3 encrypting to an AgePony `age1tag1` key,
  decrypted on device; AgePony encrypting to `age-plugin-tagtest` recipients, decrypted
  by the reference tool. Tag computation unit-tested against spec vectors.
- Hardware: StrongBox and TEE devices, per-use auth and timeout, key invalidation after
  biometric enrollment changes (Keystore behavior, make sure the error is clear).
- YubiKey decrypt: `piv-p256` and `p256tag` over NFC and USB-C, wrong PIN, PIN lockout.
- Transfer: Android to Android, Android to iOS, Android to Desktop and back; plain
  `age -d` on a bundle gives a working identity file; expired transfer key refuses.
- Paper: restore from printed page (scan and typed); plain `age -d` on the armored block.
- Share: every direction, locked vault, oversized payload, hostile scrypt work factor.

## 9. Open decisions

1. Release split. 5.0.0 now carries three large features on top of 4.3.0, while the #12
   crash fix and the signature stanza are nearly done and uncommitted. Option: ship them
   as 4.3.0 now and keep 5.0.0 for D, E, F, G. Lean: split, since #12 is a crash users
   can hit today.
2. Plaintext share-out: allow with warning, text only, or leave out.
3. Hybrid hardware identities on Android (vault-held ML-KEM half) in 5.0.0, or classic
   `age1tag1` only.
4. YubiKey decrypt in 5.0.0 or next minor.
5. SSH private keys in paper backup.
6. iOS SE key migration to `age1tag1` if the current format is custom.
7. Carried from 4.3.0: passphrase plus signing (lean: keep the wrapper), and whether that
   fallback gets a distinct extension.

## 10. Suggested order

1. Commit A with its fixtures; B is done; C. (Ship as 4.3.0 if decision 1 says split.)
2. Tag recipients in core (encrypt side), with vectors. Small and unblocks everything.
3. Share support (D), since the receive path benefits from B being in.
4. Keystore hardware identities (E), then YubiKey decrypt if in scope.
5. Transfer (F): spec first, then Android, then Desktop and iOS receivers.
6. Paper backup (G), reusing F's identity-file writer.
7. iOS parity pass, docs, release notes.

## 11. Credit

Signature stanza direction from issue #11, surfaced by testing on #10. Passphrase crash,
PIN item and share request from issues #12, #13 and #14. Identity transfer from a user
email request, Jul 2026.
