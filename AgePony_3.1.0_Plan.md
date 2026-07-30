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
verification, QR recipient exchange, encrypted identity transfer between devices (see report 4
below), localization, iOS post-quantum parity, within-tab navigation state preservation.

Note on QR: partly present already. `RecipientsScreen` can scan a recipient QR code today; what is
missing is showing one.

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

## 3b. Second round of reports (2026-07-27)

Same tester, two more suggestions plus a question.

### Report 3: name your recipients

**Already shipped, which makes this a discoverability problem rather than a feature gap.**
`StoredRecipient` has had a `name` since 3.0.0, `RecipientsScreen` shows an editable name field
before saving (paste, QR scan, or GitHub username import), and named recipients are what the
encrypt picker lists.

Two real gaps behind the request, both small:

1. **No rename after saving.** `Vault.renameIdentity` exists; there is no `renameRecipient`.
2. **A key pasted in the encrypt picker is one-shot.** `RecipientPicker.parseAdHoc` builds an
   `AdHocRecipient` with an auto label (`shorten(...)`) and never offers to save it. That is right
   for a one-off send, but there should be a "save with a name" affordance next to it.

Proposed for 3.1.0 since both are a few lines: add `Vault.renameRecipient`, a rename row in
`RecipientsScreen`, and a save-with-name button on ad-hoc entries in `RecipientPicker`.

### Report 4: move identities between devices without an OTP

The tester's scheme: keep a key pair on the laptop, give the phone the public half, have the phone
encrypt its identities to it, move the file however, decrypt on the laptop.

**This is the right design and it is worth stating why**, since the comparison to OpenKeychain's
one-time password is not just ergonomics. An OTP protects the transport and does nothing for the
endpoint, and it necessarily displays a secret, which is precisely what a compromised phone can
capture. Encrypting to an already-trusted public key displays nothing secret, types nothing, and
keeps the private half on the laptop. The residual risk is unchanged either way: a compromised
phone has already lost the identities it holds.

Design (this is the backlog's "recipients / identity import-export", now with a clear shape):

- **Export:** Identities tab, pick which identities, pick a target (saved recipient, or paste or
  scan a public key), confirm the target's fingerprint, get one `.age` file.
- **Plaintext format:** a USTAR archive, same machinery as `SignedBundle`, with a manifest entry
  and one entry per identity in *standard* form (`AGE-SECRET-KEY-...`, OpenSSH PEM). So the
  receiving end can `age -d` it and get usable key files without AgePony. No proprietary blob, no
  lock-in.
- **Optionally signed** via the existing sign-then-encrypt path, so the receiver can tell the
  bundle came from the sender's key rather than from anyone who knows the target's public key.
- **Import:** decrypt, detect the manifest, list the identities, let the user choose which to add.
- **Non-exportable identities** (`HARDWARE_KEY`, `SK_ED25519`, `SK_ECDSA_P256`) are listed and
  greyed with a reason, never silently dropped. Their private keys cannot leave the device.
- **Fingerprint confirmation before send.** Encrypting to the wrong public key fails silently and
  irreversibly, so the target must be confirmed rather than assumed.

Sizing: the crypto is all present, so this is mostly UI plus a bundle format. It pairs naturally
with the address book and verification work, so the recommendation is to land it as the headline
of 3.2.0 rather than stretching 3.1.0 further. If 3.1.0 finishes early it can move up.

### The question: is the repo open for issues?

Yes. Issues are enabled on `github.com/norsehorse-dev/AgePonyAndroid` (checked 2026-07-27).
Worth answering warmly and pointing future requests there, where they are visible and votable.

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
| W8 | Rename a saved recipient, and save an ad-hoc pasted key with a name (report 3) | `vault/Vault.kt`, `ui/identities/RecipientsScreen.kt`, `ui/files/RecipientPicker.kt` |
| W10 | Deferred to 3.2.0: encrypted identity transfer between devices (report 4) | new `vault/IdentityBundle.kt`, `ui/identities/*` |
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
6. **Work-factor range.** Settled at 16 through 20. 2^20 is 1 GiB and will fail on most phones,
   but it is reachable deliberately rather than by accident, and the precheck explains it.
7. **Diceware wordlist.** Which list ships, and under what attribution? The EFF long list (7776
   words, CC BY 3.0 US) is the obvious choice and needs a line in `NOTICE`; a shorter or
   self-authored list avoids the attribution but weakens the "diceware" claim. Also worth
   deciding: does the generated passphrase go straight into the field, or is it shown once for the
   user to write down first?

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

Committed as `07f0185` after `./gradlew :agepony-core:test` passed locally.

**2026-07-27 — W3 part one (everything the encrypt flow needs except the UI).**

- `Armor.kt`: added `EncodingSink` (an `OutputStream` that armors what is written) and
  `DecodingSource` (an `InputStream` that reads armored text as binary), plus
  `encodingSink` / `decodingSource`. `encodeStream` / `decodeStream` are now thin wrappers over
  them, so there is one implementation of each direction. The push/pull shapes are what actually
  compose with `Age.encryptStream` (which writes to an `OutputStream`) and `Age.decryptStream`
  (which reads from an `InputStream`). Neither wrapper closes the stream it wraps, so SAF streams
  stay the caller's to manage.
- `signing/SSHSig.kt`: added `hashStream`, the bounded-memory twin of `hashMessage`.
- `signing/SSHSigner.kt`: `signEd25519` now delegates to a new `signEd25519Hashed`, which takes a
  precomputed message hash. Sign-and-encrypt of a large file becomes two passes over the input
  (hash, then bundle) instead of one whole-file buffer.
- `signing/SSHSigVerifier.kt`: `verify` now delegates to a new `verifyHashed(signature,
  namespace) { alg -> hash }`, so a signed bundle can be verified from the hash
  `SignedBundle.parseStream` computes while the payload streams past.
- `app/.../vault/FileEncryptor.kt`: added `encryptStream`, `decryptStreamWithIdentities`,
  `decryptStreamWithPassphrase`, and `sniffArmored` (peeks the head through a
  `PushbackInputStream` to decide armor without a second read). Recipient-rule checking moved to
  a shared private helper, so the buffered and streaming paths cannot drift. `OutOfMemoryError`
  is deliberately not caught in the streaming path: scrypt's 256 MiB allocation is unrelated to
  file size, and only the caller can report which one failed (W6).
- New test: `signing/SSHSigStreamTests.kt`. `ArmorStreamTests.kt` grew sink/source cases,
  including odd write-size boundaries (1, 7, 47, 48, 49, 64, 1000 bytes per write).

Sandbox verification: 39 tests green across the armor, tar and signed-bundle suites, old and new,
under a 64 MB heap. The signing tests need Bouncy Castle, which the sandbox cannot fetch, so
those are verified by the Gradle run.

**2026-07-27 — W3 part two and W5 (the encrypt flow itself).**

Two more core pieces were needed first, both pull-shaped, because `Age.encryptStream` reads its
plaintext from an `InputStream` while `buildStream` and `writeEntry` are push-shaped:

- `TarArchive.source(entries)` presents a list of `StreamEntry(name, size, open)` as one readable
  archive. Each entry is opened only when reached, so a fifty-file bundle never has fifty files
  open. An `ExactSizeInputStream` refuses an entry whose bytes do not match its declared size,
  because a file that shrank between the size query and the read would otherwise corrupt the tar.
- `TarArchive.sizeOf(entries)` gives the archive's exact length without building it, which is what
  lets a multi-file bundle be signed (the signed bundle's header declares the inner tar's size
  before the inner tar exists).
- `SignedBundle.bundleSource(...)`, the pull-shaped twin of `buildStream`.

App side:

- New `app/.../ui/files/SafIo.kt`: `SourceRef`, `PreparedSource`, and the SAF helpers
  (`openInput`, `openOutput`, `createInTree`, `prepare`, `uniqueName`, `humanSize`), plus
  `CountingInputStream` for progress. Two details worth keeping: `openOutput` asks for mode `wt`
  first, since a plain `w` leaves the tail of a longer previous file behind on some providers; and
  `prepare` stages a copy into the app cache only when the provider refuses to report a size and
  the size is actually needed (tar headers need it, a plain single-file encrypt does not).
- `EncryptFlow.kt` rewritten. The destination is now chosen before any work starts, which is what
  streaming requires and is the whole fix for the report. There is no `outputBytes` state any
  more. Progress is real: a byte counter batched to 512 KiB so a 130 MB file asks for a few
  hundred recompositions instead of a few thousand.
- Multi-file chooser: picking 2+ files goes to a MODE step offering "One encrypted archive" or
  "One encrypted file each". Separate mode asks for a destination folder
  (`OpenDocumentTree`), writes one `.age` per input, and reports a per-file result list so one
  failure does not sink the batch.
- Sign-and-encrypt now reads the input twice (hash, then encrypt) instead of holding it, and the
  progress bar accounts for both passes.
- The out-of-memory message finally tells the truth: the passphrase text only appears when a
  passphrase was actually used, and it says scrypt needs about 256 MB regardless of file size, so
  a smaller file will not help.

Sandbox verification: 45 core tests green under a 64 MB heap (new: `source` matches `create`,
lazy opening, shrunk-entry rejection, `sizeOf`, `bundleSource` matches `build`). The app module
needs the Android SDK, so `EncryptFlow.kt` and `SafIo.kt` are on the local build.

**2026-07-27 — W4 (decrypt flow).**

Decrypt had a problem encrypt did not: whether the plaintext is a signed bundle is only knowable
once its first block has been decrypted, and `Age.decryptStream` pushes plaintext into an
`OutputStream`, so there is nothing to probe.

- `SignedBundle.UnwrappingSink(payloadOut)` is the answer: an `OutputStream` that decides
  mid-stream. If the first 512 bytes are the bundle's marker header it strips the tar wrapper as
  bytes arrive, routing the payload to `payloadOut` while hashing it; anything else passes
  through byte for byte and `result()` is null. Handles arbitrary write boundaries, which matters
  because chunk sizes are not block-aligned.
- `TarArchive.parseHeaderBlock` was extracted for it, and `forEachEntry` now uses the same
  function, so there is one header parser rather than two.
- `Age.canDecryptStream(ciphertext, identities)` reads only the header and reports whether any
  identity can unwrap it.
- `FileVerifier.verifyHashed(...)` mirrors the core change, with `verify` delegating to it.
- `DecryptFlow.kt` rewritten: pick file, probe the header, ask for a passphrase only if needed,
  pick destination, stream. Because the scrypt stanza lives in the header, a wrong passphrase is
  now caught in a few hundred bytes of reading, before the user is asked where to save anything.

One honest consequence, called out in the code and in the DONE screen: the signature entry sits
after the payload in a bundle, so a bad signature is reported once the file is already written.
The verdict says so plainly rather than implying the file was verified before saving.

Sandbox verification: 49 core tests green under a 64 MB heap. The new ones cover unwrapping at
write sizes of 1, 3, 511, 512, 513, 4096 and 65536 bytes, pass-through for plain tars and random
bytes and inputs shorter than one block, truncation reported as damage, and push/pull agreement
between `UnwrappingSink` and `parseStream`.

**2026-07-27 — W6 part one (scrypt memory: precheck and work-factor control).**

- `crypto/Scrypt.kt`: `memoryBytes(n, r)` = `128 * N * r`, documented next to the KDF it describes,
  because that number is the whole explanation for the reported failure.
- `FileEncryptor`: `DEFAULT_SCRYPT_WORK_FACTOR` (18), `MIN` (16), `MAX` (20),
  `scryptMemoryBytes`, `freeHeapBytes`, `scryptFitsInMemory`, and a new `ScryptMemoryException`.
  `encrypt` and `encryptStream` take a `workFactor`, and the shared recipient helper refuses to
  start when scrypt would not fit, with 32 MiB of headroom. The user now gets a sentence with real
  numbers before any work begins, instead of an `OutOfMemoryError` partway through a file.
- `Vault.scryptWorkFactor`, persisted in `agepony_vault_settings`, clamped to 16..20.
- Settings gains a "Passphrase work factor" row showing the live memory cost, whether the value is
  age's default, and that the factor travels in the file so any age tool can still open it.
- The recipient picker's hardcoded "Work factor 2^18" line now reads the setting, shows the memory
  cost, and turns red when the device does not currently have that much free.
- `EncryptFlow` threads the setting through and reports `ScryptMemoryException` directly.

**2026-07-27 — W6 part two (diceware).**

Decisions taken: EFF long list (7776 words), and the suggestion is shown first and only fills the
fields when the user accepts it.

- `crypto/Diceware.kt`: `generate`, `entropyBits`, `parseWordlist`, and the EFF list size as a
  constant. Selection uses `SecureRandom.nextInt(bound)`, which is rejection-sampled and unbiased;
  the obvious `nextInt() % size` would favour the front of the list and quietly cost entropy.
  `parseWordlist` rejects a mangled entry rather than skipping it, because silently skipping lines
  would shrink the keyspace without anyone noticing.
- `vault/Wordlist.kt` loads the list from `assets`, not `res/raw`, so a missing file is a runtime
  absence (the generator does not appear) rather than a compile error. It also refuses a list that
  is not exactly 7776 words, rather than falling back to something weaker.
- The recipient picker gains "Suggest a passphrase": the phrase is displayed with its word count
  and entropy, with Shorter / Longer / Again, and only fills both fields on "Use it".
- `NOTICE` (git repo only, as before) carries the CC BY 3.0 US attribution.

**The wordlist file itself is not in the tree yet.** The sandbox cannot reach eff.org, so it has to
be fetched locally, which is arguably better provenance anyway:

```
curl -o ~/Apps/AgePonyAndroid/app/src/main/assets/eff_large_wordlist.txt \
  https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
cp ~/Apps/AgePonyAndroid/app/src/main/assets/eff_large_wordlist.txt \
   ~/Documents/GitHub/AgePonyAndroid/app/src/main/assets/eff_large_wordlist.txt
wc -l ~/Apps/AgePonyAndroid/app/src/main/assets/eff_large_wordlist.txt   # expect 7776
```

The app builds and runs without it; the suggestion button simply does not appear.

Sandbox verification: 57 core tests green, including diceware word counts, clamping, an unbiased
draw across all four quartiles of the list over 4000 samples, the standard entropy figures
(6 words from 7776 = 77.5 bits), and parser rejection of mangled lists.

**2026-07-27 — tested on hardware.** Installed as `assembleFossRelease` over the existing 3.0.2
(same signing key, so the vault survived) and worked through `AgePony_3.1.0_DeviceTests.md` on the
Pixel 8 / GrapheneOS that filed the original report. Passed. The reported failure is fixed on the
device that reported it, which is the bar this release was set against.

Diceware section 9 was not exercised: the wordlist asset is still absent, so the generator is
correctly invisible.

**2026-07-27 — W8 (the recipient-naming gaps from report 3).**

- `Vault.renameRecipient(id, name)`, mirroring `renameIdentity`, but ignoring a blank name rather
  than accepting one and leaving an unidentifiable row.
- `RecipientsScreen`'s detail view gains a Rename control: the headline becomes a text field with
  Save and Cancel.
- `RecipientPicker` can promote a one-time pasted key into a saved, named recipient. The entry
  keeps the text that was pasted, so Save re-parses it through `RecipientImport.parsePastedText`
  and writes exactly the `StoredRecipient` the Recipients tab would have written. On save the
  one-time copy is dropped and the newly saved recipient is selected in its place, so the encrypt
  in progress is unaffected.

**Versioning decided: 3.0.3 folds into 3.1.0.** 3.1.0 is `versionCode 8`, changelog `8.txt`, one
tag, and the nav-restore fix ships as a line in the 3.1.0 notes. One F-Droid recipe update rather
than two while 3.0.2 is still in review. Section 6's arithmetic follows from that.

**2026-07-27 — W7 (header inspector).**

- `Age.parseHeaderStream(input)` returns the parsed header and leaves the stream at the payload.
- New `ui/files/InspectFlow.kt`, reachable from the Files landing screen. Reads the header and
  stops, so it is instant on a 1 GB file, and shows: size, armored or binary, header length,
  whether any vault identity can open it, and each recipient stanza described in words. The scrypt
  stanza reports the file's own work factor and what it will cost in memory, which is the same
  number W6 surfaces at encrypt time, now readable from a file someone else made.
- Deliberately read-only, and it says so on screen: stanzas are public information, and showing
  them reveals nothing the holder of the file does not already have.

Both W7 and W8 are committed but **not yet built**, since the tested APK predates them.

**2026-07-27 — W9 (release mechanics).**

- `app/build.gradle.kts`: `versionCode 8`, `versionName "3.1.0"`.
- `fastlane/metadata/android/en-US/changelogs/8.txt`, 498 characters against F-Droid's 500 limit.
  Written around what a user notices, not what was refactored, and it includes the folded-in
  3.0.3 tab-restore line.
- `full_description.txt` leads with 3.1.0 and keeps post-quantum below it, with four new feature
  bullets.

Reproducibility guards were already in place and are untouched: `dependenciesInfo.includeInApk =
false`, `vcsInfo { include = false }`, no minification.

Remaining before the tag: build, a short manual pass on the new screens, commit, tag `3.1.0`, push,
then a new build block in the fdroiddata fork. 3.0.2's existing recipe stays exactly as it is.

## 10. Style reminders

- No em dashes anywhere that ships or gets sent.
- Read the concrete file before proposing a change.
- Mirror every edit to both repos.
- Every plan step ends in a build or test.
