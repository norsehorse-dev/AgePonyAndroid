# AgePony 3.2.0 — release steps

Closes GitHub issue #2 (Umotas). `versionCode 9`, `versionName 3.2.0`.

**The release artifact is built from a clean clone of the tag, not from a working directory.**
That is the PGPony lesson: F-Droid clones the repo at the pinned commit and builds in a clean
room with no git context and none of your local files. Anything the build quietly depends on that
git has never seen does not exist over there. The `vcsInfo { include = false }` comment already in
`app/build.gradle.kts` is the scar tissue from the last time this bit.

Nothing here has been compiled yet. Step 4 is the gate.

## What the audit found

Only one untracked file exists anywhere in the source trees: `app/.DS_Store`. No assets, no
resources, no generated sources — so nothing silently vanishes in a clean-room build. The
gitignored files in `~/Apps` (`keystore.properties`, `agepony-upload.jks`, `local.properties`)
affect **signing and SDK path only**, not APK content.

The real divergence was upstream of that: `~/Apps` held two source files git had never seen (the
Jul 30 Add Recipient fix). Both copies are byte-identical now and everything is in the git tree,
but that is exactly the class of drift that produces "reproducible on my Mac, not on the build
server". Hence the clean-clone step below rather than trusting the copies to stay in step.

| File | What changed |
| --- | --- |
| `vault/Vault.kt` | `armorDefault`, `passphraseModeDefault`, in-memory `sessionPassphrase` |
| `ui/files/RecipientPicker.kt` | Selection hoisted into `RecipientSelection`; split into `RecipientPickerContent` + wrapper |
| `ui/files/EncryptFlow.kt` | Inline picker, remembered settings, `encryptMore()` |
| `ui/settings/SettingsScreen.kt` | Two new Encryption rows + "forget passphrase" |
| `ui/identities/RecipientsScreen.kt` | The Jul 30 Add Recipient fix, previously only in `~/Apps` |
| `vault/Hydration.kt` | `RecipientCandidate.publicDisplayString()`, same fix |
| `app/build.gradle.kts` | 8 / 3.1.0 → 9 / 3.2.0 |
| `changelogs/9.txt` | New, 488 chars |

---

## 1. Housekeeping

```
cd ~/Documents/GitHub/AgePonyAndroid
rm -rf _to_delete/          # transfer tarball + a stale .git/index.lock
```

Neither is tracked, but clear them so `git status` is clean before you commit.

## 2. Confirm no new dependency reached the foss flavor

```
git diff app/build.gradle.kts agepony-core/build.gradle.kts gradle/libs.versions.toml
```

Should show **only** the versionCode/versionName lines. Every source change in this release lives
in `src/main`, so `foss` gains nothing new. If this diff shows a dependency, stop.

## 3. Commit and tag — locally, nothing pushed yet

Message inline via a heredoc, so no editor opens:

```
git add -A
git commit -F - <<'MSG'
AgePony 3.2.0: one-window encrypt setup, remembered settings (#2)

Recipients are chosen inline on the encrypt screen instead of a second
full screen. Armor and passphrase-only persist; the passphrase is held
until the vault locks. Finishing an encrypt keeps every choice.

Also folds in the Add Recipient naming fix.

Closes #2.
MSG
git tag -a v3.2.0 -m "AgePony 3.2.0"
```

`-F -` reads the message from stdin; the quoted `<<'MSG'` stops the shell touching `#2` or
anything else in the text. `git tag -a` already has `-m`, so it won't prompt either.

If you'd rather never get dropped into pico by git again:

```
git config --global core.editor "nano"      # or "vim", or "code --wait"
```

**Use `v3.2.0`, with the `v`.** The 3.1.0 pre-release doc says to tag without one, but every tag
in the repo is `v3.0.0` / `v3.0.1` / `v3.0.2`, and `UpdateCheckMode: Tags` matches what's actually
there.

Nothing is pushed yet, and that's deliberate: if verification fails you `git tag -d v3.2.0`,
amend, and re-tag. The "never move a tag" rule only binds once a tag is published.

## 4. Build the artifact the way F-Droid will

Clone the tag out of your local repo into a scratch directory. This is the step that makes the
test meaningful — a fresh clone has no `build/`, no `.gradle/`, no untracked files, no signing
keys, and no editor state.

```
rm -rf /tmp/agepony-verify
git clone --branch v3.2.0 --depth 1 \
  file://$HOME/Documents/GitHub/AgePonyAndroid /tmp/agepony-verify
cd /tmp/agepony-verify
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties   # the one thing you must add back
./gradlew clean :agepony-core:test :app:assembleFossRelease
```

`local.properties` is gitignored and points at the SDK — F-Droid supplies its own equivalent, so
adding it back is legitimate. Add **nothing else**. In particular do not copy `keystore.properties`
in yet: without it the build is unsigned, which is exactly what F-Droid produces before it applies
its own signature.

```
export APK=/tmp/agepony-verify/app/build/outputs/apk/foss/release/app-foss-release-unsigned.apk
```

If that path doesn't exist, `ls` the directory — the filename tells you whether it picked up a
signing config it shouldn't have.

## 5. Artifact checks — run these on the clean-clone build

| # | Check | Expect |
| --- | --- | --- |
| A1 | `~/Library/Android/sdk/build-tools/*/aapt2 dump badging $APK \| head -3` | `versionCode='9'`, `versionName='3.2.0'` |
| A2 | `unzip -l $APK \| grep -ci "com/google/android/play"` | `0` — no Play libraries in the foss flavor |
| A3 | `unzip -l $APK \| grep -i "version-control-info\|dependencies.pb"` | Nothing. Both reproducibility guards holding |
| A4 | `unzip -l $APK \| grep -i eff_large_wordlist` | Nothing. The wordlist asset is in neither copy, so the Diceware suggestion is dark in this build — expected, just know it |
| A5 | `shasum -a 256 $APK`, then `./gradlew clean :app:assembleFossRelease` and hash again | Same hash |

For a stronger A5, clone a **second** time into a different path and build there. Same hash across
two different directories catches anything that bakes in an absolute path — which a rebuild in the
same directory cannot.

## 6. Install and test that same artifact

Now, and only now, sign the clean-clone build so you can put it on a phone. Same source, same
compile, just signed:

```
cp ~/Apps/AgePonyAndroid/keystore.properties /tmp/agepony-verify/
cp ~/Apps/AgePonyAndroid/agepony-upload.jks  /tmp/agepony-verify/
cd /tmp/agepony-verify && ./gradlew :app:assembleFossRelease
export ADB=~/Library/Android/sdk/platform-tools/adb
export APK=/tmp/agepony-verify/app/build/outputs/apk/foss/release/app-foss-release.apk
$ADB install -r $APK
```

Check `storeFile` in `keystore.properties` resolves — it's relative to the repo root, so a bare
filename works after the copy, an absolute path works anywhere.

### Issue #2 checks

| # | Check | Expect |
| --- | --- | --- |
| 1 | Encrypt a file with **armor off**, then encrypt another | Armor still off the second time, and after force-quitting |
| 2 | Choose recipients → **Passphrase only**, confirm, encrypt. Encrypt a second file | Mode still on; Configure reads "Passphrase only (scrypt)" and "Kept until the vault locks" — no re-prompt |
| 3 | Background the app, reopen, unlock, go to Encrypt | Passphrase is **gone**. Security gate — if it survives a lock, stop |
| 4 | On Configure, tap "Change recipients" | Picker opens **in place**, no new screen; encrypt button greys out with "Confirm or cancel the recipient list above" |
| 5 | With the picker open, untick the current key, tick another, **don't confirm**, try to encrypt | Button stays disabled. Confirm, then encrypt → opens with the *new* key |
| 6 | After an encrypt, tap **"Encrypt more files"** | Straight to the file picker; recipients, passphrase and armor still set |
| 7 | "Clear recipients & passphrase", then reopen the picker | Everything blank — no prefilled passphrase, nothing ticked |
| 8 | Settings → Encryption | Switches match what you last set while encrypting; "Forget the remembered passphrase" shows only when one is held |
| 9 | **Text tab** → Encrypt text → Choose recipients | Passphrase field **empty**, even with a file passphrase held. Deliberately not linked |
| 10 | Identities → Recipients → Add, paste a key | Name starts empty, key summary above it; saving unnamed asks first |
| 11 | Set the active identity to a **hardware/security key**, open the encrypt picker | Nothing falsely preselected; count matches what's ticked |

Then sections B and D of the 3.1.0 pre-release doc — the upgrade path and the large-file sweep.
**B4 (decrypt a file made by 3.0.2) matters most**; nothing else counts if that fails.

## 7. Push — only after 5 and 6 pass

```
cd ~/Documents/GitHub/AgePonyAndroid
git push origin main
git push origin v3.2.0
```

Do **not** touch `v3.0.2` (`fd49cb3e`). The open fdroiddata MR builds that commit by hash; moving,
deleting or force-pushing it is the only thing that breaks the review.

## 8. F-Droid

The MR is unaffected by everything above. Two things worth doing anyway:

- Comment that `v3.2.0` now exists and 3.1.0 was never tagged, so the sequence is
  `v3.0.2 → v3.2.0`. A reviewer who finds a two-release gap on their own will ask about it.
- Expect the first published F-Droid build to be **3.2.0, not 3.0.2**, if the recipe uses
  `AutoUpdateMode: Version` + `UpdateCheckMode: Tags` — it takes the highest version code across
  all tags. `changelogs/9.txt` mentions the 3.1.0 work for exactly that reason: F-Droid users will
  never see `8.txt`.

## 9. Play

Separate artifact, separate checklist — the 3.1.0 Play doc still applies. Build it from the same
clean clone for the same reason:

```
cd /tmp/agepony-verify
./gradlew :agepony-core:test :app:assemblePlayRelease :app:bundlePlayRelease
```

- `versionCode 9` must beat **anything ever uploaded to any track**, including internal testing.
  Check the Console first; if 9 is taken, bump both copies and re-tag before anything goes out.
- Re-run the section 6 checks against the Play-signed artifact from the internal track. Play App
  Signing re-signs the upload, so that's the only way to test what users receive.
- `full_description.txt` still claims QR **sharing** while the code only scans. Outstanding from
  3.1.0 — fix the copy or the feature before this ships.

## 10. Housekeeping after

`~/Apps/AgePonyAndroid` is a working copy with no `.git`, which is how the two trees drifted in
the first place. Worth deciding what it's for: either make it a real clone of the repo, or treat
it as scratch and stop building releases there. Release artifacts come from a clean clone either
way.

## 11. Reply to the issue

Umotas raised all five points. Worth saying which landed, and that the passphrase is held in
memory only and dropped on lock — that's the part someone using an encryption app will ask about.
