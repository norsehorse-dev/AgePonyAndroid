# AgePony internal security review, 2026-09-23

**What this is.** An internal review of both AgePony codebases, done with Claude (Anthropic's AI model) on 23 September 2026. It is not a professional third-party audit. It read the code; nothing was run on a device. The 5.0.1 release notes called it a "security audit", and that wording will change in the next store update.

It is published as written, with a few changes, each marked *[edited for publication]*: the commit and file hashes that point at the leaked Android keystore are removed, a personal name is removed, a wrong statement about F-Droid signing is corrected, and one sentence that read as if a person had checked the findings is reworded. What was fixed, and what wasn't, is in **Status after 5.0.1** at the end.

---


**Scope**

| Repo | Version / state | Files |
|---|---|---|
| AgePonyAndroid | `main` at `e99afeb`, 5.0.0 | ~50k lines Kotlin |
| AgePony (iOS) | working tree, 4.0.1 | ~36k lines Swift, local-only repo |

Both repos were read in full across five areas:

- Android core protocol
- Android core SSH, signing and transfer
- Android app
- iOS core
- iOS app and share extension

The git history and tracked files were also checked for secrets.

Every Critical, High and Medium finding was checked against the source a second time, in a separate pass of the same review. *[edited for publication: the original said "checked by hand"]* Nothing was run on a device. Items marked *(confirm on device)* were found by reading code only.

**Overall:** the age protocol code is in good shape on both platforms. That covers the header MAC, STREAM, X25519, the ML-KEM hybrid, P-256 tags, SSHSIG, and the hand-rolled Swift ML-KEM, Keccak and scrypt, which all match the specs. The serious problems are in two places:

1. One repo-hygiene leak (C-1).
2. The app-lock layer: the password and duress design, auto-lock, backups and leftover plaintext.

## Summary

| ID | Sev | Platform | Title |
|---|---|---|---|
| C-1 | **Critical** | Android | Release signing keystore and its passwords are in public git history |
| H-1 | High | Both | Duress password (and the app password) is skipped by hardware/device-passcode unlock |
| H-2 | High | iOS | Vault file and the password-wrapped key go into iCloud/Finder backups, so the PIN can be brute-forced offline |
| H-3 | High | Android | Vault stays unlocked forever after a share-sheet session finishes |
| H-4 | High | Android | "No lock" plus a password auto-opens the vault; the password and duress PIN are ignored |
| M-1 | Medium | Both | No attempt limit or backoff on the app PIN/password; 1–4 digit PINs are allowed |
| M-2 | Medium | Android | Password blob is software-only scrypt 2^15, so it can be brute-forced offline after a file-system extraction |
| M-3 | Medium | iOS | "No lock" plus a password keeps an unprotected copy of the master key in the Keychain |
| M-4 | Medium | Both | Auto-lock gaps: iOS uses the wall clock; Android's file-picker exemption never expires |
| M-5 | Medium | Both | Plaintext visible in app-switcher snapshots (Android has no FLAG_SECURE; the iOS cover misses sheets) |
| M-6 | Medium | Both | Key-transfer receiver can't authenticate the sender, so a forged transfer can plant keys and trusted signers |
| M-7 | Medium | iOS | Leftover plaintext: share-extension payloads never cleaned up; decrypted tmp files remain after swipe-dismiss |
| M-8 | Medium | Both | Duress wipe leaves residue and tells |
| M-9 | Medium | iOS | Any saved *recipient* key counts as a *trusted signer* |
| L-* | Low | Both | 25 lower-severity items (see below) |

---

## Critical

### C-1: Signing keystore and passwords in public git history (Android)

**Where**

- The repository's first commit (2026-06-24) added `agepony-upload.jks` and `keystore.properties`.
- The second commit deleted them from the tree.
- Both commits are ancestors of `origin/main` on github.com/norsehorse-dev/AgePonyAndroid. *[edited for publication: commit hashes removed]*

**Evidence**

- The `agepony-upload.jks` in that commit is byte-identical to the one on disk today.
- `keystore.properties` in history is also identical to the current file. It holds `storePassword` and `keyPassword`. *[edited for publication: blob hashes removed]*
- `.gitignore` now covers both files, but that doesn't remove history.

**Impact**

Anyone who clones the public repo gets your signing key and both passwords.

- **Direct APK users.** A malicious APK signed with this key installs *as an update* over a genuine AgePony and inherits its data directory: `vault.dat` and the key blobs. After the user's next unlock it has every identity.
- **F-Droid users** were not exposed. *[edited for publication: the review said the F-Droid build ships the developer signature. It doesn't. F-Droid builds AgePony and signs it with its own key, so the leaked key was never used there.]*
- **Play.** Play users are shielded by Play App Signing, but this is the Play *upload* key, so it is compromised as well.

**Fix.** Treat the key as burned. Rewriting history doesn't un-leak it.

1. Generate a new keystore with new passwords. Change any other keystores or accounts that reused those passwords.
2. **Play:** Play Console, then App integrity, then request an upload key reset.
3. **Direct and F-Droid:** rotate with APK Signature Scheme v3.1 key rotation:
   - Run `apksigner rotate` to build a lineage from old to new.
   - Remove the old signer's rollback capability so devices that have installed the rotated build reject updates signed only with the old key.
   - Check the current apksigner docs for the exact flags.
   - Rotation only protects API 28+ devices. minSdk is 26, so API 26–27 users can't be protected short of reinstalling.
4. Coordinate the signer change with F-Droid, via an fdroiddata MR updating `AllowedAPKSigningKeys`. Update the certificate fingerprint published in the README and in `tools/verify_repro.sh`.
5. Purge the files from history (`git filter-repo --path agepony-upload.jks --path keystore.properties --invert-paths`) and force-push. Ask GitHub Support to drop cached views of the old commits. Existing clones and forks keep the key regardless, which is why step 3 matters.
6. Check whether any other Pony repo started out the same way.

---

## High

### H-1: Duress password and app password are skipped by biometric/device-passcode unlock (both)

**Where**

- **iOS:**
  - `Vault/KeychainStore.swift:49-53` creates the ACL `[.biometryCurrentSet, .or, .devicePasscode]`.
  - `Features/Home/RootView.swift:61,316-320` shows "Use Face ID" next to the password field whenever `lockMode == .biometric`.
  - Setting a password during onboarding leaves lockMode at `.biometric`.
- **Android:** `ui/VaultGate.kt:251-274`. In BIOMETRIC mode the lock screen shows "Unlock", which runs BiometricPrompt with device-credential fallback (API 30+), and "Use your PIN instead" beside it.

**Impact.** The app password is an *alternative* to hardware unlock, not an extra requirement. A coercer who has the phone passcode, which is normally the first thing demanded, taps Face ID/Unlock, then Enter Passcode, and gets the real vault. The duress PIN never gets a chance to fire. That is exactly the scenario the duress feature is advertised for.

**Fix.**

- When a duress password is set, require the app password: hide or disable hardware unlock, or make both required by deriving VK = HKDF(keystore/keychain secret ‖ scrypt(password)).
- At minimum, say plainly in Lock settings that Face ID/passcode also opens the vault, so the duress PIN only helps if the phone passcode isn't given up.

### H-2: iOS vault and password blob are in device backups (offline PIN brute force)

**Where**

- `Vault/Vault.swift:529-544,581-598`: `vault.dat` and `vault.key.pw` are in `Application Support/AgePony/`. `isExcludedFromBackup` appears nowhere in the repo.
- `PasswordKeyBlob.swift:60`: `logN = 15`.
- `LockSettingsView.swift:218`: minimum PIN length is 4.

**Impact.** The Keychain master key is `ThisDeviceOnly` and stays out of backups. `vault.key.pw`, though, is the vault key sealed only under scrypt(PIN, 2^15). Anyone who has an iCloud backup (a taken-over Apple ID, or legal process without Advanced Data Protection) or a Finder/forensic backup can:

1. try every 4–6 digit PIN offline,
2. recover the vault key,
3. open `vault.dat` and get every private key.

Changing the password doesn't rotate the vault key, so old backups stay crackable with the old PIN. This contradicts two in-app claims: "The vault file on disk is useless without the key" (`InfoPages.swift:66`) and "no cloud sync" in the App Store description.

**Fix.**

- Set `isExcludedFromBackup` on the `AgePony` directory.
- Bind the password KEK to a device-only secret: a `ThisDeviceOnly` Keychain salt or a Secure Enclave key.
- Rotate the vault key on password change.

### H-3: Android vault never locks after a share-sheet session

**Where**

- `vault/VaultViewModel.kt:617-626`: the lock is `viewModelScope.launch { delay(grace); vault.lock() }`.
- `share/ShareActivity.kt:80`: `onDone = { finish() }`.
- `SharedVault` is process-wide (`vault/Vault.kt:28`). There is no `onCleared`, no `ProcessLifecycleOwner` and no screen-off hook.

**Impact.** The sequence is: share into AgePony, unlock, encrypt or decrypt, tap Done.

1. ON_STOP schedules the lock job.
2. `finish()` destroys the activity, which clears the ViewModel and cancels the job.
3. The process-wide vault stays unlocked until the process dies, which can be hours.
4. The next person to open AgePony from the launcher lands straight in the vault.

The same thing happens on API ≤30 when Back finishes MainActivity. It only doesn't happen with a grace of 0.

**Fix.** Lock from a process-scoped owner: ProcessLifecycleOwner ON_STOP plus an application-scope timer. Also lock in `onCleared()` when finishing, and on `ACTION_SCREEN_OFF`.

### H-4: Android "No lock" plus a password auto-opens the vault

**Where**

- `ui/VaultGate.kt:101-109`: auto-unlock runs when `lockMode == OFF && plainKeyBlobExists()`. It doesn't check `passwordEnrolled`, even though the comment above it says "Password-enrolled vaults are NOT auto-unlocked".
- `VaultViewModel.kt:516`: `applyLockMode(OFF)` always writes the plain blob.
- `enrollPassword` (`:330-352`) never deletes the plain blob.
- `SettingsScreen.kt:164`: the UI promises "If you set a password below it becomes the gate".

**Impact.** A user who picks No lock plus a PIN, as the UI suggests, has a vault that opens for anyone, and their duress PIN can never fire.

**Fix.**

- When a password is enrolled, OFF must not create or keep a plain blob.
- `enrollPassword` should delete the plain blob and the plain KEK.
- Add `!passwordEnrolled` to the auto-unlock condition.

---

## Medium

**M-1: No attempt limiting; tiny PINs allowed (both).**

- **Where:**
  - Android: `VaultViewModel.kt:296-323`. Also `VaultGate.kt:360` and `SettingsScreen.kt:722`, which accept any non-empty secret.
  - iOS: `RootView.swift:111-121` and `LockSettingsView.swift:218` (4-digit minimum).
- **Impact:** a wrong entry just sets an error, with no counter, delay or wipe-after-N. With H-4 or iOS "No lock", 10^4 PINs can be driven through the UI (adb input or a HID injector) in about an hour.
- **Fix:** add a persisted failure counter with exponential backoff and an optional wipe after N failures. Require at least 6 digits.

**M-2: Android password blob is software-only (`security/PasswordVault.kt:73-77,151-157`).**

- **Impact:** the blob is `scrypt(secret, 2^15)` wrapping the vault key, with no Keystore involvement. It's correctly excluded from backup, but a full-file-system extraction of a phone unlocked since boot yields an offline-crackable blob. Once a PIN is enrolled, the hardware-backed biometric KEK next to it stops mattering.
- **Fix:** wrap the blob again under a non-auth AndroidKeyStore key (StrongBox, `setUnlockedDeviceRequired(true)`), so guesses only work on the device. Raise logN.

**M-3: iOS "No lock" plus a password leaves an unprotected Keychain key.**

- **Where:** `KeychainStore.swift:58-62` and `Vault.swift:422-428`. `setAppPassword` never deletes the `WhenUnlockedThisDeviceOnly` item, which has no access control.
- **Impact:** the password is a screen gate, not encryption. A forensic extraction or a jailbreak reads the master key directly. The UI says the password is "the only thing standing in front of your keys".
- **Fix:** in `.none` mode with a password, delete the Keychain item and use the password-wrapped key only.

**M-4: Auto-lock gaps.**

- **iOS** (`RootView.swift:180-195`):
  - The grace period is measured with `Date()` and checked only on return to the foreground, so setting the clock back makes the elapsed time negative and the vault stays open.
  - Keys stay in RAM for the whole time the app is backgrounded.
  - Fix: lock on `.background`, or use a monotonic clock and treat a negative elapsed time as "lock".
- **Android:**
  - `VaultViewModel.kt:618`: `if (vault.autoLockSuppressed) return`. The flag is set before every SAF picker and cleared only at ON_START, so pressing Home from inside the picker means no lock is ever scheduled.
  - Fix: always schedule a bounded lock (for example 5 minutes) while suppressed.

**M-5: App-switcher snapshots show plaintext.**

- **Android:** FLAG_SECURE is set only on the private-key reveal and the paper screen. Decrypted text, notes, the passphrase-only screen, paper restore and the transfer preview have none, and neither does ShareActivity, which sits in the *sender's* task so its Recents card shows plaintext. Fix: set FLAG_SECURE on both activities by default (a toggle is fine), and call `setRecentsScreenshotEnabled(false)` on API 33+.
- **iOS** *(confirm on device)*: `RootView.swift:73-81` puts the privacy cover on the root view, so modal sheets render above it. That exposes TextDecryptView, the share-incoming sheet, note editing and key import. Fix: put the cover in its own `UIWindow` at `.alert + 1`.

**M-6: Key-transfer receiver doesn't authenticate the sender (both platforms share the design; the Android code was reviewed).**

- **Where:**
  - `core/portability/LanTransfer.kt:96-124`
  - `ui/portability/TransferScreens.kt:165-185,278-296`
  - `vault/KeyPortability.kt:91-150`
  - `Vault.kt:395`: the first imported identity becomes active.
- **Impact:**
  - The receive QR holds a public one-time recipient and a token, so anyone who photographs it and is on the same LAN can send first.
  - The preview shows only identity *names* and signer/recipient *counts*.
  - Imported signers are trusted immediately. `isConsistent` doesn't check SSH or PIV public keys against their private keys.
  - Result: an attacker-known key can become the victim's encrypt-to-self key, and attacker-signed files show "Signed by <any name> ✓".
  - The sender side is solid: the confirmation code plus a biometric check, ciphertext only on the wire, and a sniffer can't get the keys.
- **Fix:**
  - Add a sender-to-receiver check: a short code shown on the sender and typed on the receiver, or a SAS.
  - List every key with its fingerprint in the preview.
  - Import signers as untrusted.
  - Never auto-activate an imported identity.

**M-7: iOS leftover plaintext.**

- **Share payloads:** `HomeView.swift:95-98` never cleans them up. `.sheet(item:onDismiss:)` sets `sharePayload` to nil *before* `onDismiss` runs, so the `if let token` branch is dead. Payloads are also dropped, and left on disk, when the app is locked or cold-starting (`AgePonyApp.swift:57-63`). They're written `.atomic` only, so default protection and backed up (`Services/SharedContainer.swift:127,172`), with shared *text* stored plainly in `manifest.json`. The extension's own `share-<uuid>` copy is never deleted.
- **Decrypted files:** `DecryptFlow.swift:394-396` deletes `resultURL` only on the Cancel/Done buttons. Swipe-dismiss, auto-lock teardown or a crash leaves the plaintext in `tmp/AgePonyShare-*`. `TempFileCleanup` runs only from a Settings button. Output is created under class C protection and upgraded only after success.
- **Fix:**
  - Hold the token in its own state and delete the payload as soon as it's read.
  - Write with `.completeFileProtection` and exclude from backup.
  - Sweep the share directory and `tmp` on launch, on lock and on duress.
  - Clean up in `onDisappear`.

**M-8: Duress wipe residue and tells (both).**

- **iOS** (`Vault.swift:501-527`) doesn't wipe:
  - `tmp` plaintexts and App Group payloads (M-7)
  - `tmp/AgePonySigners-*/allowed_signers`
  - the proxy host/user/password in UserDefaults
  - ReviewPrompter counters ("has done N operations but the vault is empty")
  - `URLCache.shared` and cookies from GitHub fetches, which record contact usernames
  - `Documents/Inbox`

  The duress path also does one extra scrypt, so it isn't constant-time.
- **Android** (`Vault.kt:576-581`, `VaultViewModel.kt:468-484`):
  - `reset()` clears the onboarded flag, so the tour shows right after a "successful" PIN, which is an obvious tell to a watching coercer.
  - The proxy/Orbot prefs survive.
  - `cache/agepony-stage*.tmp` plaintext isn't swept.
  - The lock mode silently changes.
- **Fix:**
  - Wipe every location listed above.
  - Keep the onboarding flag.
  - Reset prefs to what a fresh long-time user would have.
  - Pad the wrong-password path with a dummy scrypt.

**M-9: iOS treats saved recipients as trusted signers.**

- **Where:** `Services/FileVerifier.swift:198-199`: `if let r = recipients.first(where: { keyMatches($0, wire) }) { return .trusted(...) }`.
- **Impact:** "I encrypt to this key" isn't a trust decision. Any SSH key added as a recipient, including one fetched from GitHub, produces "Signed by <name>, trusted". Android correctly trusts only identities and explicit signers, so the platforms also disagree on the same file.
- **Fix:** drop the recipient branch, or show it as VALID_UNKNOWN with the recipient name as a hint.

---

## Low

**Protocol and parsers (both cores)**

- **L-1:** Lenient base64 in headers and stanzas.
  - Padding and non-zero trailing bits are accepted. Android also skips empty lines, and its "body lines must be 64 chars" check is a comment with no code behind it (`Stanza.kt:101-105`). iOS MACs *re-serialized* stanzas (`AgeHeader.swift:172-180`).
  - Result: the MAC line and body lines can be changed without a key and still decrypt, so ciphertexts aren't canonical. Confidentiality is unaffected.
  - Fix: strict decode plus a round-trip check. iOS should MAC the raw header bytes.
- **L-2:** Decrypt doesn't enforce "scrypt must be the only stanza", on either platform.
  - Android: `Age.kt:174-178`. The app's memory guard reads only the *first* scrypt stanza (`FileEncryptor.kt:105,134`), so a second stanza at work factor 22 gets past the #12 fix and OOMs. That's an `Error`, which `catch (e: Exception)` doesn't catch.
  - iOS: max work factor is 22 (4 GiB), with no sole-stanza check, and a 1 MiB header can hold about 13k stanzas.
  - Fix: reject mixed headers before any KDF work, and cap the work factor at what the device can handle (≤20).
- **L-3:** Android streaming header reader has no size cap (`Age.kt:221-248`), so a file with no `---` gets buffered until OOM. iOS caps it at 1 MiB.
- **L-4:** Android: no minimum RSA size for ssh-rsa recipients or signers (`SSHRSA.kt:31`, `SSHSigVerifier.kt`). Age requires 2048 bits, and iOS already enforces that for recipients. Also bound `e`, since BC may not cap it, which allows a CPU DoS through a detached `.sig`.
- **L-5:** Android doesn't check wrapped file-key length for X25519, scrypt, ssh-ed25519 or ssh-rsa (should be 32-byte bodies). No confidentiality impact.
- **L-6:** `allowed_signers` options (`namespaces=`, `valid-before/after`, `cert-authority`) are parsed and ignored on both platforms, and dropped on Android export.
  - Result: an expired or git-only key becomes trusted for AgePony, and a CA key becomes a direct signer.
  - Fix: enforce the options, or refuse lines with options AgePony doesn't understand.
- **L-7:** `sk-*` SSHSIG verification doesn't require the user-presence flag (both platforms). OpenSSH rejects these unless `no-touch-required` is set.
- **L-8:** Signatures cover only H(payload) in all three formats (detached, bundle, sig stanza), all under the one namespace `agepony`.
  - Result: the bundle filename shown as "inside the signed file" can be changed by a recipient who re-encrypts, and a signature can be forwarded to a different recipient.
  - Fix: sign the name plus H(payload), use a separate namespace per format, and label the filename "unsigned" in the UI.
- **L-9:** Android: a sig stanza that is present but unreadable reports "unsigned", and signature errors surface *after* plaintext was written (`SignatureStanza.kt:372-384`, `DecryptFlow.kt:470-501`). Fix: use a three-way result, and verify before writing where the data is already in memory.
- **L-10:** No cap on bcrypt_pbkdf rounds when importing an encrypted OpenSSH key (both), so a crafted key hangs a core indefinitely. Cap it at around 2^16.
- **L-11:** A malicious NFC authenticator or card can crash or hang the app.
  - Android: `Cbor.kt:108,113` (preallocates 2^31 and recurses without limit), plus unbounded `61xx` loops in `Piv.kt:110` and `SecurityKeyTransport.kt:98-125`.
  - iOS: `CBOR.swift:237-253` (`Int()` traps, `reserveCapacity`), and an RSA mpint p≤1 hits a precondition.
- **L-12:** iOS ML-KEM skips the FIPS 203 encapsulation-key modulus check (`MLKEM768.swift:449`). A bad `age1pq1` key gives a file nobody can decrypt; it doesn't hurt confidentiality.
- **L-13:** iOS `Field25519` subtraction is off by 38 when b > a+p (`Field25519.swift:146-166`). That case is hit by a non-canonical Ed25519 `y` in an ssh-ed25519 *public* key. It causes wrong recipients, not a secret leak. Fix: reduce inputs first and reject y ≥ p.
- **L-14:** iOS has no explicit all-zero X25519 check; it relies on CryptoKit throwing. *(Confirm with a unit test on a low-order point.)*

**App layer**

- **L-15:** Security downgrades need no re-auth on either platform: No lock, remove or change password, remove duress. Anyone holding the phone during the grace window can loosen the lock permanently.
- **L-16:** Android "Remove password" on a password-only vault deletes the only wrap of the vault key without asking (`VaultViewModel.kt:389-407`). The vault is gone at the next lock.
- **L-17:** Android `lockMode` survives Reset and backup restore. A new biometric vault then shows no unlock control *(confirm on device)*.
- **L-18:** Android leaves a partial or truncated plaintext file at the SAF destination when decrypt fails (`DecryptFlow.kt:139-142,478-493`). iOS deletes it. Android also extracts a bundle even with an INVALID verdict.
- **L-19:** Android `cache/agepony-stage*.tmp` plaintext is leaked when the copy throws or the process dies (`SafIo.kt:104-108`, `EncryptFlow.kt:645`).
- **L-20:** Android ShareActivity accepts `file://` URIs with no scheme or authority check (`share/Share.kt:60-78`). Another app can make AgePony open its own private files, for example `files/vault/vault.key.pw`, as share input. Reject `file://` and this app's own authority.
- **L-21:** Proxy credentials are stored in plaintext prefs. On Android `agepony_vault_settings` isn't excluded from backup; on iOS it's UserDefaults. Move them into the vault or Keychain.
- **L-22:** Android has no tapjacking protection (`setHideOverlayWindows`, `filterTouchesWhenObscured`).
- **L-23:** Secrets show up in places they shouldn't:
  - Android: `rememberSaveable` holds note bodies and passphrases, and the SSH-key passphrase field is unmasked.
  - iOS: autocorrect and learning are on in note and text editors, and third-party keyboards aren't blocked.
  - Both: long-press or text-selection Copy skips ClipboardGuard/`.localOnly` (iOS `AgePonyKeyBlock.swift:51`, which applies even to sensitive blocks).
- **L-24:** iOS: the App Intent uses an unsanitized `IntentFile.filename` via `appendingPathComponent` and then deletes the parent directory (`AgePonyIntentSupport.swift:42-56`). The `agepony://share?token=` value isn't checked to be a UUID (`SharedContainer.swift:98-104`). Use `sanitizedFilename`, and `UUID(uuidString:)` for the token.
- **L-25:** iOS miscellaneous:
  - Setting the real password equal to the duress value silently disables duress.
  - The Keychain update deletes before adding, so a failed add sends the next launch to onboarding, which overwrites `vault.dat`.
  - The share extension reads whole files into memory and is killed above about 100 MB.
  - The "In-app biometric prompts" toggle silently flips lockMode to `.none`.
  - Notes use scrypt work factor 16 while the UI says 2^18 (`CreateNoteView.swift:96` vs `:158`), and text encryption ignores the user's work-factor setting.
  - The Secure Enclave signing key has no `.userPresence` access control.
  - `SSHKeySource` uses `URLSession.shared` (persistent cache and cookies) for direct GitHub fetches.

## Info

- Secrets aren't zeroized, and passphrases are held as `String` (JVM and Swift). This is expected.
- Android `OpenSSHPrivateKey.RSA` is a `data class`, so `toString()` prints d, p and q.
- Android RSA-OAEP uses unblinded `RSAEngine`; switch to `RSABlindedEngine`.
- The iOS ML-KEM `compress`/`mod` and the implicit-rejection select aren't strictly constant-time. This is disclosed in the file comments and isn't practical against file decryption.
- Both platforms accept an empty final STREAM chunk (non-canonical).
- Per-operation biometric prompts (reveal, export, decrypt) are boolean gates, not tied to a crypto operation. The main *unlock* is correctly bound on both platforms: Android uses a CryptoObject and iOS uses the Keychain ACL.
- The vault key is never rotated on password change or purge (both).
- Android dependencies are outdated but have no known CVEs as used: okhttp 4.12.0, biometric 1.1.0, core-ktx 1.10.1, lifecycle 2.6.1. `isMinifyEnabled=false`.
- Test gaps: there are no C2SP age CCTV testkit vectors on either platform. Those alone would have caught L-1, L-2, L-5 and the empty-chunk case. There are also no negative or fuzz tests for CBOR, tar, SSH keys, allowed_signers options or the sk UP flag.
- iOS repo hygiene:
  - One commit with most files untracked and no `.gitignore`.
  - Dead SwiftData templates (`Item.swift`, `ContentView.swift`) still have Xcode headers with a personal name in them. *[edited for publication: name removed]* Strip them before the repo ever goes public.
  - The App Store description still says "Requires iOS 18.6".
  - The root `PrivacyInfo.xcprivacy` is a stale duplicate.

## Checked and OK (highlights)

**Header MAC (both).** HKDF "header" key with a constant-time compare, checked before any payload work.

**STREAM (both).**
- 64 KiB chunks.
- 11-byte counter plus last flag, with an overflow check.
- Each chunk is authenticated before release.
- Truncation is caught, including at chunk boundaries.
- No trailing data is accepted.

**Recipient types (both).**
- X25519: labels and salt correct.
- ssh-ed25519: tweak and conversion correct.
- ssh-rsa: OAEP label correct.
- mlkem768x25519 hybrid: combiner and RFC 9180 key schedule correct.
- P-256 and tag: points validated, tag compared in constant time.
- piv-p256: matches age-plugin-yubikey.
- Bech32: correct.

**iOS hand-rolled primitives.**
- ML-KEM-768: NTT, sampling, CBD, compression, and implicit rejection J(z‖c) with a constant-time ciphertext compare.
- Keccak/SHA-3.
- scrypt (RFC 7914).
- bcrypt_pbkdf and Blowfish: match OpenBSD.

**SSHSIG (both).**
- Magic and version checked.
- Namespace enforced.
- Only sha256/sha512 hashes allowed.
- Signature type bound to key type (RSA requires `rsa-sha2-512`).
- The trust decision matches the exact key blob only after the signature verifies.
- The sig stanza uses its own HKDF label and a random nonce, and binds to the plaintext.

**Tar.** Checksum verified, and extraction is basename-only (Android through SAF, iOS through `safeFileName`), so no path traversal.

**LAN transfer, sender side.**
- Token compared in constant time.
- Frame caps enforced.
- Ciphertext only on the wire, to a one-time recipient that travels only in the QR.
- 60-bit confirmation code.
- 15-minute expiry.

**Android storage.**
- The Keystore KEK is per-use auth, `invalidatedByBiometricEnrollment`, StrongBox with fallback, and CryptoObject-bound.
- `vault/` is excluded from cloud backup and device transfer.
- PROCESS_TEXT only ever returns ciphertext, never plaintext.
- ClipboardGuard sets EXTRA_IS_SENSITIVE and auto-clears.
- No secrets in logs.
- No custom TrustManager, cleartext is blocked, and SOCKS has no DNS leak.

**iOS storage.**
- Keychain items are `ThisDeviceOnly` and not synchronizable, with no access group, so the extension can't read the key.
- The share extension never touches the vault.
- No ATS exceptions.
- No logging.
- In-app Copy uses `.localOnly` plus an expiry.
- The proxy path uses an ephemeral session with no direct fallback.

**Recipient import (both).** Always an explicit review list; nothing is imported silently.

## Suggested order

1. **C-1.** Rotate the key and purge history.
2. **H-3 and H-4.** Small, contained fixes on Android.
3. **H-1.** A design decision about how duress and the password relate to hardware unlock.
4. **H-2 and M-3.** iOS: backup exclusion plus a device-bound password KEK.
5. **M-1, M-4, M-5, M-7, M-8.** The auto-lock and residue sweep, which both platforms need.
6. **M-6 and M-9.** Trust UX.
7. Low items, plus the CCTV testkit, as a hardening release.

---

## Status after 5.0.1

Android 5.0.1 and iOS 5.0.1 were built to fix these findings.

**C-1 (Android signing key).** The key was replaced, not hidden:

- Direct-download APKs from 5.0.1 on are signed with a new key, with an APK Signature Scheme v3.1 rotation lineage from the old one. The old signer's rollback capability is off, so a phone on Android 9 or later that has installed 5.0.1 refuses an update signed only with the old key. This was tested on a device.
- Phones on Android 8.x (API 26 and 27) can't be protected by rotation and still accept the old key.
- The Google Play upload key was reset. Play users were never exposed, since Google re-signs what they install.
- F-Droid was never affected (see the correction above).
- The history was not rewritten. The key was already public, so purging it wouldn't take it back from existing clones; it is retired instead and used only as the first link of the lineage.

**High and Medium.** H-1 to H-4 and M-1 to M-9 are fixed on every platform they apply to. The main design change is H-1: setting a duress password makes the vault password-only, on both platforms.

**Low.** L-1 to L-25 are fixed on every platform they apply to, with these gaps:

- L-6 on iOS: the core parses and enforces `allowed_signers` options, but the iOS vault has nowhere to store them, so a key transfer skips signers that carry options rather than importing them without their restrictions. Android imports the ones it can enforce.
- The C2SP age CCTV test vectors suggested under Info are not in either test suite yet.

**Info.** These are notes rather than findings. Some were addressed along the way (blinded RSA-OAEP and R8 on Android, the iOS repo hygiene items); the rest are unchanged.
