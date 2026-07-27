# AgePony 3.1.0 plan

Working document for the 3.1.0 Android release. Reference this throughout the chat.
Last updated: 2026-07-27.

## 1. Release framing

3.1.0 is driven by two user reports from a GrapheneOS / Pixel 8 tester, plus a small
set of backlog items that live in the same code paths.

**Theme: large files stop failing, and multi-file encrypt stops forcing a bundle.**

Decisions already made:

- Scope = the two reports plus 2 to 3 backlog items (not a patch release first).
- Multi-file output: **ask at pick time**. After picking 2+ files, show a chooser
  (one bundle, or separate files). No hidden default either way.
- Passphrase path: **both** accurate diagnosis/messaging **and** a scrypt work-factor
  control.

Backlog items pulled in (rationale: each one touches code we are already opening):

| Item | Why now |
| --- | --- |
| Diceware passphrase generator + scrypt work-factor control | The work-factor control is the mitigation for the passphrase memory ceiling. Diceware ships alongside it in the same passphrase UI. |
| age header / stanza inspector | Read-only, small, and it is the tool we want while validating that streamed output is byte-identical to buffered output. |
| Recipients / identity file import-export (stretch) | Only if the above land early. Otherwise it moves to 3.2.0. |

Deferred to 3.2.0 (a coherent "trust and exchange" release): recipient address book +
verification, QR recipient exchange, localization, iOS post-quantum parity,
within-tab navigation state preservation.

## 2. Report 1: out of memory on large files

### 2.1 What the user saw

Encrypt of a 131.2 MB file, one recipient chosen, armor off. The app showed:

> Not enough memory to encrypt with a passphrase on this device. Try a smaller file,
> or encrypt to recipient keys instead.

Device: Pixel 8, GrapheneOS build 2026071501, hardened memory allocator ON,
memory tagging ON.

### 2.2 Two separate defects

**Defect A: the message is wrong.** `EncryptFlow.kt` catches `OutOfMemoryError` and
emits hardcoded passphrase wording regardless of the actual mode
(`app/src/main/java/com/agepony/app/ui/files/EncryptFlow.kt`, lines 253 to 256). The
screenshot shows `1 recipient`, so `passphrase` was null and the advice given
("encrypt to recipient keys instead") was already what the user was doing. Same
hardcoded pattern exists twice in `DecryptFlow.kt` (lines ~138 and ~234).

**Defect B: the file flows never stream.** `agepony-core` already has bounded-memory
paths that nothing in the app calls:

- `Age.encryptStream(InputStream, List<AgeRecipient>, OutputStream)` (`Age.kt:82`)
- `Age.decryptStream(InputStream, List<AgeIdentity>, OutputStream)` (`Age.kt:106`)
- `AgePayload.encryptStream` / `decryptStream`, 64 KiB chunks (`AgePayload.kt:100`, `:131`)

Grep confirms zero non-test callers. The Compose flows use the whole-buffer API instead.

### 2.3 Memory math for the reported case

Path today, 131.2 MB input, one recipient, armor off:

| Allocation | Size | Where |
| --- | --- | --- |
| `sourceBytes` from `readBytes()` | 131 MB, with transient doubling during stream growth | `EncryptFlow.kt:90` |
| `AgePayload.encrypt` output buffer | ~131.5 MB | `Age.kt:51` |
| `header + payload` concatenation | another ~131.5 MB copy | `Age.kt:52` |
| `outputBytes` retained until the SAF save completes | ~131.5 MB | `EncryptFlow.kt:249` |

Peak is comfortably past 500 MB. `android:largeHeap="true"` is set
(`app/src/main/AndroidManifest.xml:13`), which buys headroom but not this much.

With armor on (the default, `armor = true` at `EncryptFlow.kt:74`) it is much worse:
`Armor.encode` builds a Java `String` of base64 (roughly 175 MB of characters, so
~350 MB of `char` storage) and then `toByteArray` allocates ~175 MB more
(`Armor.kt:22`, `FileEncryptor.kt:63`).

Independently, passphrase mode has a hard floor: scrypt at work factor 18 with r=8
allocates `128 * N * r` = **256 MiB** in one block inside Bouncy Castle
(`crypto/Scrypt.kt`, `recipients/Scrypt.kt:27`). On GrapheneOS with hardened_malloc
and MTE, a single 256 MiB allocation is more fragile than on stock Android. That is
why the passphrase message existed in the first place; it was just wired to fire for
every OOM.

### 2.4 Fix strategy

Stream everything in the Files flows. Keep the whole-buffer API for Notes and Text,
which are small by construction.

Three pieces are missing from `agepony-core` before the app can stream end to end:

1. **Streaming armor.** `Armor.encodeStream(InputStream, OutputStream)` and
   `Armor.decodeStream(InputStream, OutputStream)`. Encode reads 48 plaintext bytes
   at a time (48 bytes maps to exactly 64 base64 chars, matching `LINE_WIDTH`), so
   output stays byte-identical to `Armor.encode`. Decode must be lenient about CRLF
   and trailing whitespace exactly as `Armor.decode` is.
2. **Streaming tar.** `TarArchive.writeEntry(OutputStream, name, size, InputStream)`
   plus `finish(OutputStream)`, and a streaming `extract` that yields entries without
   materializing the archive. Current `create`/`extract` are whole-buffer
   (`TarArchive.kt:24`, `:36`).
3. **Streaming signed bundle.** SSHSIG signs a hash of the message, so signing large
   input needs a two-pass approach: pass 1 hashes the SAF input stream, pass 2 writes
   the tar (marker, payload, signature) into the encrypt stream. Requires reopening
   the input `Uri`, which is fine, and requires the payload size upfront for the tar
   header. If SAF reports no size, fall back to staging the input into app cache
   first and measuring it there.

App-side change with a UX consequence: **the destination must be picked before work
starts.** Today `createOutput.launch(...)` runs after the ciphertext exists
(`EncryptFlow.kt:251`). Streaming needs an output stream to write into, so the order
becomes pick inputs, configure, pick destination, then stream with byte progress.
This also removes the retained `outputBytes`.

### 2.5 Passphrase-specific mitigation

- Precheck before attempting scrypt: compare `Runtime.getRuntime().maxMemory()` minus
  current usage against `128 * N * r` plus slack. If it will not fit, say so before
  spending time, and point at the work-factor setting rather than at "use a smaller file"
  (file size is not the constraint for scrypt).
- Add the work-factor control (backlog item). Values 16 through 20, stored in
  `agepony_vault_settings`, default 18 to stay aligned with the age CLI. Show the real
  tradeoff in plain language: 2^16 is about 64 MiB and faster, 2^18 is about 256 MiB
  and the age default, 2^20 is about 1 GiB and will not work on most phones. The work
  factor is written into the stanza, so every value stays interoperable with age.
- Fix the OOM catch blocks to report what actually ran out: scrypt work factor, armor
  buffer, or payload.

## 3. Report 2: individual files instead of a bundle

Today, picking 2+ files tars them into `bundle.tar` and encrypts once
(`EncryptFlow.kt:97` to `:112`). The user wants N inputs to produce N `.age` outputs.

Design (chooser at pick time, per the decision above):

- After the picker returns 2+ URIs, show a small step: "One encrypted archive" or
  "One encrypted file each", with a one-line explanation of each.
- "One encrypted file each" needs a destination **folder**, not a file. Reuse the
  pattern already proven in `MigrateFlow.kt`: `ActivityResultContracts.OpenDocumentTree`
  (`MigrateFlow.kt:84`) plus `DocumentsContract.createDocument` and
  `openOutputStream` in `writeToTree` (`MigrateFlow.kt:300`). That helper should be
  lifted into a shared file (`ui/files/SafIo.kt`) and made streaming.
- Per-file naming reuses `FileEncryptor.encryptedName` (`name` to `name.age`). Handle
  collisions in the destination folder the way `uniqueName` does today
  (`EncryptFlow.kt:350`), by suffixing `-1`, `-2`.
- Per-file results screen: a checkmark or warning per file, same shape as
  `MigrateFlow`'s `DONE` stage, so one failure does not abort the batch.
- Signing applies per file when "one file each" is chosen: each output is its own
  signed bundle.
- Recipient selection and armor apply to the whole batch.

Note that "one file each" plus streaming is also the memory answer for the batch case:
today a multi-file pick materializes every input plus the whole tar in memory at once
(`EncryptFlow.kt:100` to `:106`).

## 4. Workstreams

| ID | Work | Files |
| --- | --- | --- |
| W1 | Streaming armor in core | `agepony-core/.../Armor.kt`, new tests |
| W2 | Streaming tar and signed bundle in core | `archive/TarArchive.kt`, `archive/SignedBundle.kt`, new tests |
| W3 | Streaming encrypt flow, destination picked first, byte progress | `ui/files/EncryptFlow.kt`, `vault/FileEncryptor.kt`, new `ui/files/SafIo.kt` |
| W4 | Streaming decrypt flow, same reordering | `ui/files/DecryptFlow.kt` |
| W5 | Multi-file chooser and per-file output to a tree | `ui/files/EncryptFlow.kt`, `ui/files/SafIo.kt` |
| W6 | Honest OOM diagnosis, scrypt precheck, work-factor setting, diceware generator | `ui/files/EncryptFlow.kt`, `ui/files/DecryptFlow.kt`, `ui/files/RecipientPicker.kt`, `vault/VaultModels.kt`, settings UI |
| W7 | age header / stanza inspector (read-only view of recipients and stanza types) | new `ui/files/InspectFlow.kt`, reuses `AgeHeader.parse` |
| W8 | Stretch: recipients / identity import-export | `vault/RecipientImport.kt`, `vault/IdentityImport.kt` |
| W9 | Version bump, changelog, F-Droid metadata | `app/build.gradle.kts`, `fastlane/metadata/android/en-US/changelogs/` |

Suggested order: W1 and W2 together (core, testable without a device), then W3, then
W4, then W5, then W6, then W7, then W9. W8 only if there is room.

## 5. Verification

Every workstream carries its own check. Nothing is called done without one.

- **Byte-identity tests (core).** For each of armor, tar, payload and full age encrypt,
  assert the streamed output equals the whole-buffer output for the same input and the
  same nonce/salt. `Age.kt` already promises this ("Output is byte-identical to the
  whole-buffer methods for the same inputs"); make it a test, not a comment.
- **Round-trip against the age CLI v1.3.0+.** Encrypt streamed on device, decrypt with
  `age -d` on the Mac, and the reverse. `generate-fixtures.sh` is the existing hook.
- **Large-file manual test on hardware.** 150 MB and 1 GB inputs, armor on and off,
  recipients and passphrase, single file and 5-file batch both ways. Watch the heap in
  Android Studio's memory profiler and confirm the ceiling stays flat rather than
  tracking file size.
- **Low-memory simulation.** Run the same tests with a deliberately small heap so the
  bounded-memory claim is tested rather than assumed.
- **Regression on the small paths.** Notes, Text, migrate, and decrypt of files produced
  by 3.0.2 must all still work.
- **Build gate:** `./gradlew :agepony-core:test` then
  `./gradlew assembleFossRelease assemblePlayRelease` (run locally; the cloud sandbox
  has no Android SDK).

## 6. Version and release mechanics

Current state in the tree: `app/build.gradle.kts` still reads `versionCode = 7` /
`versionName = "3.0.2"`, so the 3.0.3 nav-restore work on `main` has not been
version-bumped yet. Changelogs present: `5.txt`, `6.txt`, `7.txt`.

Two things to settle before tagging 3.1.0:

1. Does 3.0.3 ship on its own (versionCode 8, changelog `8.txt`), making 3.1.0
   versionCode 9 with changelog `9.txt`? That is the assumption in this doc.
2. If 3.0.3 folds into 3.1.0 instead, 3.1.0 becomes versionCode 8.

Constraints to respect:

- 3.0.2 is in F-Droid review pinned to commit `fd49cb3`. Do not retag or disturb it.
- F-Droid fixes get a new tag and a version bump, never a moved tag.
- Reproducibility guards stay in place: `dependenciesInfo.includeInApk = false` and
  `vcsInfo { include = false }`.
- The fdroiddata recipe lives in the GitLab fork, not in the app repo.

## 7. Mirror rule

Source of truth is `~/Apps/AgePonyAndroid` (holds `agepony-upload.jks` and
`keystore.properties`, not a git repo). The git repo is
`~/Documents/GitHub/AgePonyAndroid`. Every change must land in both, byte-identical.

After each change set, run in your Mac Terminal:

```
rsync -a --delete \
  --exclude '.git' --exclude 'build' --exclude '.gradle' --exclude '.idea' \
  --exclude '.kotlin' --exclude 'local.properties' \
  --exclude 'agepony-upload.jks' --exclude 'keystore.properties' \
  ~/Apps/AgePonyAndroid/ ~/Documents/GitHub/AgePonyAndroid/
```

Then commit and tag yourself; the sandbox will hand you the commands rather than
running git.

## 8. Open questions

1. **3.0.3 first, or folded in?** Drives the versionCode arithmetic in section 6.
2. **Streaming everywhere, or above a threshold?** Recommendation: stream
   unconditionally in the Files flows. One code path is easier to keep correct than
   two, and the 64 KiB chunking costs nothing on small files.
3. **Signed bundle two-pass read.** Acceptable to read the input twice for
   sign-and-encrypt (once to hash, once to write)? The alternative is staging to app
   cache, which needs free disk equal to the file size.
4. **Armor default for large files.** Armor roughly triples output size and is on by
   default. Worth auto-suggesting binary above, say, 25 MB?
5. **Decrypt of a multi-file bundle.** With per-file encrypt available, should decrypt
   also learn to extract a `.tar` bundle straight into a chosen folder rather than
   writing `bundle.tar`?
6. **Work-factor range.** 16 through 20, or cap at 19 so the setting cannot produce a
   file this app cannot open on a mid-range phone?

## 9. Progress log

**2026-07-27 — W1 and W2 done (core streaming primitives).**

Changed, in `~/Apps/AgePonyAndroid` (mirror still pending):

- `agepony-core/.../Armor.kt`: added `encodeStream`, `decodeStream`, `looksArmored`, `SNIFF_LEN`.
  Purely additive; `encode` and `decode` are untouched. Encode chunks on 48-byte groups (48
  bytes is exactly one 64-char line), so streamed output is byte-identical to `encode`.
- `agepony-core/.../archive/TarArchive.kt`: added `writeEntry` (bytes and stream forms),
  `finish`, `forEachEntry`, `MAX_ENTRY_SIZE`. `create` now delegates to `writeEntry` + `finish`,
  `header` takes a `Long` size, and `readOctal` raises `TarException` instead of leaking
  `NumberFormatException` on a corrupt header.
- `agepony-core/.../archive/SignedBundle.kt`: added `buildStream`, `parseStream`, `StreamParsed`,
  `BundleException`. Purely additive. `parseStream` hashes the payload (sha512 and sha256) as it
  streams past, so a signature can be verified without holding the payload.
- New tests: `ArmorStreamTests.kt`, `archive/TarArchiveStreamTests.kt`,
  `archive/SignedBundleStreamTests.kt`.

Verification actually run (not just planned): the three core files plus all six test classes
were compiled with kotlinc 2.2.10 and executed in the sandbox. 34 tests pass, including the
pre-existing `TarArchiveTest.matchesReferenceArchiveBytes` golden SHA-256, which is what proves
the `create` refactor did not move a single byte. The armor bounded-memory test encodes 40 MB
under a 32 MB heap, which is the property the bug report needs. A streamed archive was also
listed by the system `tar` to confirm USTAR compatibility survived.

To confirm on real Gradle:

```
cd ~/Apps/AgePonyAndroid && ./gradlew :agepony-core:test
```

Next: W3 (encrypt flow). It needs one more core piece first, streaming SSHSIG hashing
(`SSHSig.hashStream` plus hashed sign/verify entry points), since sign-and-encrypt currently
takes the whole plaintext as a `ByteArray`.

## 10. Style reminders

- No em dashes anywhere that ships or gets sent.
- Read the concrete file before proposing a change.
- Mirror every edit to both repos.
- Every plan step ends in a build or test.
