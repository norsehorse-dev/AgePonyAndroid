# AgePony 3.2.0

Encrypting more than one file stops being a chore.

Everything in the encrypt flow reset itself. Armor went back on, passphrase mode went back off,
recipients were forgotten, and finishing a file dropped you at an empty form to start over.
Encrypting ten files meant setting the same three things ten times. Choosing recipients also
pushed a second full screen over the form and returned you to the top of it afterwards.

This release makes the encrypt screen one window that remembers what you told it.

Reported by [Umotas](https://github.com/norsehorse-dev/AgePonyAndroid/issues/2), who tested
against PGPony and listed five specific things that were slower here than they needed to be. All
five are fixed.

## Fixed

- **"Armor as text" is remembered**, between files and between launches. It also appears in
  Settings → Encryption, so it can be set without starting an encrypt.
- **Passphrase (scrypt) only is remembered** the same way, with its own Settings switch. Anyone
  who mostly encrypts to a passphrase no longer re-flips it every time.
- **A passphrase is entered once per session.** It is held until the vault locks, so a run of
  files asks for it once rather than once each. Memory only: it is never written to disk, never
  enters the encrypted vault snapshot, and is dropped by the same code path that drops the vault
  key — which runs whenever the app is backgrounded. "Forget passphrase" is on the encrypt screen
  and in Settings for when you want it gone sooner.
- **Recipients are chosen inline.** The picker opens in place on the encrypt screen instead of
  replacing it, so the whole setup is one window and confirming a choice no longer bounces you to
  the top of the form.
- **Finishing an encrypt keeps every setting.** "Encrypt more files" holds recipients, passphrase,
  signing key and armor and goes straight to the file picker. "Clear recipients & passphrase" is
  there for when starting fresh is what you actually want.

Also folded in, from earlier work that had not shipped:

- **Add Recipient no longer pre-fills the name with the key.** The field started out holding a
  truncated key, which testers read as a read-only display of what they had pasted rather than an
  editable name, so recipients ended up saved as `age1pqdu27d…d8swW`. The name field now starts
  empty with the key rendered above it, and saving without a name asks first.

## Deliberate limits

- **The Text tab does not inherit a file passphrase.** A passphrase typed to encrypt a file stays
  with the file flow; opening the recipient picker from Text starts empty. Convenience should not
  quietly carry a passphrase between contexts.
- **The encrypt button is disabled while the picker is open.** Inlining the picker put it on the
  same screen as unconfirmed edits, and encrypting from there would have used the last *confirmed*
  choice — silently sending a file to the previous recipient. Confirm or cancel first.
- **Signing-only identities are never preselected.** Hardware and security-key identities can be
  active but cannot receive a file, so preselecting one ticked nothing visible and then hydrated
  to no recipients at all.

## Compatibility

- **No format change, and no change to `agepony-core` at all.** The age implementation, every
  recipient type and the streaming payload cipher are untouched in this release. Files written by
  3.2.0 are ordinary age files, and files from earlier AgePony versions or the age CLI open
  unchanged.
- **No change to the vault format.** The two new settings are stored as app preferences, not in
  the encrypted vault snapshot, so upgrading in place keeps every identity, recipient and note.
- **No new dependencies.** Every source change lives in `src/main`, so the F-Droid `foss` flavor
  gains nothing, and the reproducibility guards (`vcsInfo.include = false`, stripped
  `dependenciesInfo`) are unchanged. The unsigned `foss` release APK builds byte-identically from
  two independent clean clones.

## Build fix

`buildTypes.release` assigned the release signing config unconditionally while the config was only
populated when `keystore.properties` existed. Any tree without the keystore — a clean clone, a CI
checkout, F-Droid's clean room — failed in `packageRelease` with *SigningConfig "release" is
missing required property "storeFile"*. The assignment is now inside the same guard, so those
builds produce an unsigned APK, which is what the README always claimed and what F-Droid expects.

This was present in `v3.0.2` and `3.1.0` too; it is not a 3.2.0 regression.

> **Note when building for Play:** the fix means a tree without `keystore.properties` now produces
> an *unsigned* artifact rather than failing loudly. Confirm the AAB is signed before uploading.

---

## Short form, for Play and F-Droid

Already in `fastlane/metadata/android/en-US/changelogs/9.txt`, 488 characters:

```
AgePony 3.2.0 makes encrypting a run of files quick.

- Recipients are chosen on the encrypt screen itself, not a second page.
- Armor and passphrase-only are remembered between files and launches.
- A passphrase is held until the vault locks, so a run asks once.
- "Encrypt more files" keeps every setting and goes to the picker.
- Add Recipient no longer pre-fills the name field with the key.

Also carries 3.1.0: files of any size, one archive or one file each, and a file inspector.
```

It mentions 3.1.0 on purpose. 3.1.0 was never tagged, so F-Droid's tag sequence runs
`v3.0.2 → v3.2.0` and F-Droid users will never be shown `changelogs/8.txt`.
