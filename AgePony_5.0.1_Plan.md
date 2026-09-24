# AgePony 5.0.1: security release

versionCode 17, versionName 5.0.1. Fixes every Android-applicable finding from the September 2026
security audit (report kept outside the repo), plus R8 from `AgePony_Next_Release.md` item 1.

Decisions made for this release:

- Duress (H-1): once a duress PIN is set, the vault is PIN-only. Hardware unlock is turned off
  and its key wraps are deleted.
- Leaked keystore (C-1): rotate the key. Git history is left as is (no rewrite, which also
  keeps the commit RelayPony's submodule pins).
- Formats: both new formats ship in 5.0.1. Signatures v2 (binds recipients and the bundle's
  file name) and the key-transfer code (sender check on the receiving phone).

## 1. Before building: the signing key (C-1)

`agepony-upload.jks` and `keystore.properties` were in the first commit (`9deae43`) and are
still reachable from `origin/main`. The file in history is byte-identical to the current
keystore, passwords included. Anyone with a clone can sign an APK as AgePony, and a
direct-download install accepts it as an update (F-Droid and Play installs are signed by
F-Droid and Google, so they were never exposed). The key has to be replaced. None
of this can be done from code; it's the one part of 5.0.1 that has to happen on the Mac and in
the Play Console.

### 1a. Google Play

Play App Signing re-signs what users get, so Play users are not exposed. The upload key is,
though. Play Console > the app > Test and release > App integrity > App signing > Request
upload key reset, with a new upload key (it can be the same new key as below). Google takes a
day or two to approve.

### 1b. Direct APK: rotate with a signing lineage

APK Signature Scheme v3 key rotation lets phones that have the old-key app accept an update
signed by the new key, and lets you tell them to stop trusting the old key afterwards. It
works on Android 9 (API 28) and later. AgePony's minSdk is 26, so phones on Android 8.x can't
be protected by rotation. They keep accepting the old key.

New key and lineage (run from the repo root; the old alias is whatever `keyAlias` says in
`keystore.properties`):

```
keytool -genkeypair -v -keystore ~/Keys/agepony-release-2026.jks -alias agepony2026 -keyalg RSA -keysize 4096 -validity 36500
apksigner rotate --out ~/Keys/agepony.lineage --old-signer --ks agepony-upload.jks --ks-key-alias OLD_ALIAS --set-rollback false --new-signer --ks ~/Keys/agepony-release-2026.jks --ks-key-alias agepony2026
apksigner lineage --in ~/Keys/agepony.lineage --print-certs
```

Signing 5.0.1: Gradle's signingConfig can't apply a lineage, so build unsigned and sign with
apksigner. Move `keystore.properties` out of the repo root first (the build only signs when it
exists), then:

```
./gradlew clean :app:assembleFossRelease
apksigner sign --ks agepony-upload.jks --ks-key-alias OLD_ALIAS --next-signer --ks ~/Keys/agepony-release-2026.jks --ks-key-alias agepony2026 --lineage ~/Keys/agepony.lineage --rotation-min-sdk-version 28 --out AgePony-5.0.1-foss.apk app/build/outputs/apk/foss/release/app-foss-release-unsigned.apk
apksigner verify -v --print-certs --min-sdk-version 26 AgePony-5.0.1-foss.apk
```

Check the flags against `apksigner help rotate` and `apksigner help sign` for the build-tools
version on the Mac before running. In particular, check that `--set-rollback false` belongs to
the old signer. The point is that once a phone has installed the rotated 5.0.1, an update
signed only with the old key is refused.

Test that before releasing:

1. Install 5.0.0 from GitHub on an Android 9+ test phone.
2. Update to the rotated 5.0.1. It must install over 5.0.0 with data kept.
3. Take any other APK with the same package name, signed only with the old key (for example
   a debug-flavored build you sign with `agepony-upload.jks`), and try `adb install -r`. It
   must fail with a signature error.

### 1c. F-Droid

Nothing to do for the key. The fdroiddata recipe has no `Binaries` or
`AllowedAPKSigningKeys`, so F-Droid builds and signs AgePony with its own key and never used
the leaked one. The recipe uses `AutoUpdateMode: Version` and `UpdateCheckMode: Tags`, so
F-Droid's update bot picks up the `v5.0.1` tag and adds the build on its own. Switching
F-Droid to ship the developer signature later would change the signer for every F-Droid
install (users would have to reinstall), so that's a separate decision.

### 1d. After release

- README "Verifying your download": add the new certificate fingerprints next to the old
  ones. Say that 5.0.1 and later carry the new key with a lineage from the old one, and that
  the old key must not be trusted for anything newer than 5.0.0. Also update the AppVerifier
  block. The README is untouched in this change set because the new fingerprint doesn't
  exist yet.
- Keep the new keystore and the lineage file out of the repo (`.gitignore` covers `*.jks`
  and, as of 5.0.1, `*.lineage`). Keep both in `~/Keys`, not the repo root.
- The old key stays in use only as the first link of the lineage. Don't sign anything else
  with it.

## 2. What changed, by finding

### Critical and High

| ID | Fix |
|---|---|
| C-1 | Key rotation plan above (outside the code). |
| H-1 | A duress PIN makes the vault PIN-only. Setting duress asks for the current PIN, then deletes the auth KEK blob and key and the plain blob and KEK, and sets lock mode OFF. A 5.0.0 vault that had duress plus biometric goes PIN-only on the lock screen at once, and its extra blobs are deleted after the first PIN unlock. Lock-mode rows are disabled in Settings while duress is set. |
| H-3 | New `AgePonyApplication` + `security/AutoLock.kt`. One process-wide lock timer driven by started-activity counts, with an elapsedRealtime deadline checked on the next start. Screen-off makes sure a lock is scheduled on the grace period. Finishing ShareActivity no longer cancels the lock. |
| H-4 | No lock plus a password never auto-opens. `enrollPassword` and `applyLockMode(OFF)` remove the plain blob when a password exists. 5.0.0 vaults in that state lose the plain blob after the first password unlock. Until then the lock screen offers "Forgot it? Open without the PIN", which opens the vault the 5.0.0 way one last time and removes the password. It is never offered with a duress PIN set. |

### Medium

| ID | Fix |
|---|---|
| M-1 | New PINs need 6+ digits and new passwords 8+ characters; existing short ones still work and Settings suggests a change. Persistent attempt counter (`security/UnlockAttempts.kt`, in `files/vault/`, reboot-aware): 30 s wait after 5 wrong tries, doubling to a 1 h cap. Optional "Erase the vault after 10 wrong attempts" (off by default). Real and duress unlocks both reset the counter. |
| M-2 | Password blob v2 is device-bound: KEK = HMAC(AndroidKeyStore key, scrypt(secret, 2^16)). v1 blobs still unlock and are re-wrapped. The new blob is opened once before it replaces the old one or before any other wrap is deleted. Unlock time at 2^16 needs measuring on a slow phone (`PasswordVault.LOG_N`). |
| M-4 | The file-picker exemption is capped at max(grace, 5 min). |
| M-5 | FLAG_SECURE on both activities by default, plus `setRecentsScreenshotEnabled(false)` on API 33+. New Settings toggle "Allow screenshots" (re-auth to turn on). Key reveal and paper screens stay secure regardless. |
| M-6 | Transfer code: both phones show `TransferCode.of(sealed bytes)` (LAN, file and paste). The receiver must confirm it matches before Import is enabled. The preview lists every key with a fingerprint and warns on name clashes. Signers start unticked. Imported identities are never made active. **Both phones need 5.0.1.** |
| M-8 | The duress wipe keeps the onboarding flag (no tour after a decoy PIN), resets other prefs including proxy credentials and counters, and sweeps cache staging files. The decoy vault's new blob reuses the scrypt output already computed, so the response time stays close to a wrong PIN. |

### Low: protocol and parsers (core)

| ID | Fix |
|---|---|
| L-1 | Strict canonical base64 and Go-exact stanza and header grammar. Checked against a Go age 1.1.1 binary in the tests, so AgePony is never stricter than age. |
| L-2 | A mixed scrypt header is refused before any KDF when a passphrase identity is tried. This matches Go, which only refuses inside scrypt unwrap. The app's memory guard takes the largest work factor across stanzas. |
| L-3 | Header cap of 1 MiB on every path. |
| L-4 | Can't encrypt to ssh-rsa keys under 2048 bits (old files still decrypt with them). The picker shows small keys disabled. Adding one warns. The RSA exponent is range-checked. |
| L-5 | 32-byte wrapped-key bodies and 16-byte file keys are required. |
| L-6 | allowed_signers options are parsed and enforced (namespaces, valid-after/before, cert-authority, no-touch-required). The import preview explains each entry. Options round-trip on export. |
| L-7 | Security-key signatures need the user-presence flag unless the signer's entry says no-touch-required. |
| L-8 | Signature v2: the sig stanza binds SHA-512(plaintext) and a digest of the recipient stanzas; bundles bind the manifest including the name. Each format has its own namespace. v1 still verifies and shows a note on what it doesn't cover. Detached signatures are unchanged. Spec: `docs/SIGNATURE_FORMATS_v2.md`. |
| L-9 | A three-way signature result. "Present but unreadable" is shown as a failure. Stanza files are verified before anything is written. |
| L-10 | bcrypt_pbkdf rounds capped at 10,000, plus salt and key-length caps. |
| L-11 | CBOR, PIV and NFC transport parsers are bounded (lengths, depth, chained responses, keepalive time). |
| misc | Empty final STREAM chunk refused. Armor lines are capped at 4 KiB while reading. RSA-OAEP decrypt is blinded. ML-KEM encapsulation-key modulus check. Ed25519 recipient point validation. Low-order X25519 is treated as "not for me". Tar takes regular files only with no size truncation, and an `available()` OOM was fixed. OpenSSH private keys are consistency-checked. RSA key `toString()` is redacted. |

### Low: app

| ID | Fix |
|---|---|
| L-15 | Re-auth before weakening the lock: No lock, remove or change the password, remove duress, a longer grace, allowing screenshots, turning erase-after-10 off. Password-only vaults confirm with the app PIN. |
| L-16 | "Remove password" is refused when it's the only way in, and otherwise asks for confirmation. |
| L-17 | Bootstrap sets the lock mode. Reset clears the lock prefs. The real PIN can't be set equal to the duress PIN. |
| L-18 | A failed decrypt deletes (or truncates) the destination document. An invalid or unreadable signature blocks bundle extraction. |
| L-19 | Staging copies are always deleted. `TempFiles.sweep` runs on start, lock and wipe. |
| L-20 | Share input takes `content://` only, and never this app's own authority. |
| L-21 | The settings prefs file is excluded from cloud backup and device transfer. |
| L-22 | `setHideOverlayWindows(true)` on API 31+ (new normal permission HIDE_OVERLAY_WINDOWS). Window-wide `filterTouchesWhenObscured` was left out on purpose: on Android 8 to 11 it makes the app ignore every tap while a screen dimmer or blue-light filter is running. |
| L-23 | Secrets kept out of `rememberSaveable`. The SSH passphrase field is masked. Plaintext results are non-selectable, so copies go through ClipboardGuard. |
| AS-2/AS-3 | Transfer checks identity consistency (SSH, RSA, PIV, sk). The LAN listener binds to the Wi-Fi address, with per-connection deadlines and 4 concurrent slots. |
| other | GitHub key fetch capped at 256 KiB, ASCII usernames only. Paper backup warns on weak passphrases. A picker recipient that fails to load is an error, not a silent drop. The picker only preselects the identity the user made active. |

### R8

`isMinifyEnabled` and `isShrinkResources` are on for both flavors, with documented rules in
`app/proguard-rules.pro` (kotlinx.serialization models, enums restored by name, the
`VaultViewModel` constructor, `-dontwarn` for BC and OkHttp optionals). No reflection was
found in app or core. Keep `mapping.txt` from each signed build.

## 3. Build and test on the Mac

```
./gradlew clean :agepony-core:testDebugUnitTest :app:testFossDebugUnitTest :app:compilePlayReleaseKotlin :app:assembleFossRelease :app:bundlePlayRelease
tools/verify_repro.sh rebuild v5.0.1-rc1
```

What was checked here: the core module compiled and ran under kotlinc 2.2.10 with BC 1.78.1
(480 tests pass; the 3 hybrid/tag vector tests that fail do so only because the harness maps
ML-KEM onto BC 1.78's Kyber). The non-UI app files and the new app tests were compiled against
stubs and pass. The Compose screens were only reviewed by hand, so expect the first Gradle
build to surface a few compile errors.

Also check `app/build/outputs/mapping/playRelease/missing_rules.txt` (and the foss one) for
"Missing class" warnings from BC 1.79.

## 4. Device test pass

Lock and vault:

1. Share into a locked AgePony, unlock, tap Done, wait past the grace period, open from the
   launcher: locked. Back out of MainActivity on API 30 or lower: same.
2. Screen off with the app in front: locks after the grace period. Home from inside the SAF
   picker: locks after 5 minutes.
3. Grace 0: rotate while unlocked (stays open), unlock via device credential (stays open).
4. 5.0.0 vault with No lock plus a PIN: asks for the PIN, "Forgot it?" appears, it opens and
   removes the PIN. Repeat, but enter the PIN: "Forgot it?" is gone afterwards and
   `vault.key.plain` is deleted.
5. Set duress on a biometric vault: current PIN is asked, the lock screen shows only the PIN,
   mode rows are disabled, `vault.key` and `vault.key.plain` are gone. Remove duress, pick
   Biometric again. Also upgrade a 5.0.0 vault that had duress plus biometric.
6. Duress entry: empty vault, no tour, proxy and counters cleared, no `cache/agepony-*`.
   Compare response time for real, duress and wrong PINs on a StrongBox phone and on one
   without StrongBox.
7. Five wrong PINs give a 30 s countdown that survives kill and reboot. Erase-after-10 erases
   on the 10th.
8. 5.0.0 password vault: unlocks, `vault.key.pw` byte 0 becomes 2. Time the unlock at 2^16.
9. Each L-15 re-auth prompt appears. Remove password is refused where it's the only way in.
10. `adb shell bmgr backupnow com.agepony.app`: settings file and `vault/` not included.

Files, share, signing:

11. Recents and screenshots are blank in both activities (including a share from another
    app). "Allow screenshots" applies at once. Revealed key and paper screens stay secure.
12. `file://` share and a share of `content://com.agepony.app...` just close.
13. Failed decrypts (wrong key, truncated file, cancelled destination) leave nothing behind,
    on Downloads, Drive and an SD card. A tampered signed bundle refuses extraction.
14. v2 sign-and-encrypt with Ed25519, RSA and a FIDO key, to a recipient and with a
    passphrase; verifies. 5.0.0 signed files still verify and show the v1 note. Plain
    `age -d` still returns the bare file for stanza-signed files.
15. allowed_signers import with a mixed file (expired, git-only, cert-authority, unknown
    option): the preview explains each entry. An imported git-only signer verifies as "valid,
    not trusted".
16. A security key signing with touch verifies. The NFC keepalive cap (120 s) is fine with a
    key waiting for a touch.

Transfer:

17. LAN transfer with mobile data on, over a hotspot, and with a VPN: codes match on both
    phones, Import stays disabled until confirmed, signers unticked, nothing made active.
18. File and paste routes show the same code. Cancel ends the session.
19. Paper restore works and doesn't make the restored key active.

R8 (both flavors):

20. Unlock an existing 5.0.0 vault; notes; ML-KEM hybrid and tag encrypt/decrypt; SSH
    signing; YubiKey PIV; FIDO over NFC; QR scan; GitHub fetch through the proxy; biometric
    unlock; Play review prompt (play flavor); tab restore after process death.
21. Two clean foss builds are byte-identical (`tools/verify_repro.sh`).

## 5. Behavior changes to mention

- A small ssh-rsa recipient (under 2048 bits) can no longer be encrypted to.
- Tars with directory, symlink or pax entries no longer extract in-app (AgePony's own bundles
  never contain them).
- Headers over 1 MiB are refused.
- GitHub usernames with underscores (enterprise-managed) are refused.
- Transferred and paper-restored keys aren't made the active identity. Pick one in Settings.
- Signers imported by 5.0.0 from lines with options lost those options back then. Re-import
  them to get the restrictions enforced.
- A 5.0.1 phone sending a signer to a 5.0.0 phone: 5.0.0 drops the options field.

## 6. iOS parity (for the next iOS release)

- Signature v2 read and write: `docs/SIGNATURE_FORMATS_v2.md` has the exact byte layout,
  namespaces and test vectors. Until iOS reads v2, a 5.0.1-signed file shows as signed but
  unverifiable on iOS 4.x.
- The iOS-side audit findings are tracked in the private audit report, not here, until the
  iOS fixes ship. The H-1 decision (duress means PIN-only) applies there too.
- The key transfer code (if iOS gets key transfer) must use `TransferCode` exactly as in
  `agepony-core/.../portability/TransferCode.kt`.

## 7. RelayPony note

RelayPony pins agepony-core as a submodule and uses the LAN transport. This release changes
`LanTransfer.receive` (per-connection threads, deadlines) and tightens every parser. Bumping
RelayPony's submodule to 5.0.1 needs its own test pass; leave it pinned until then.
