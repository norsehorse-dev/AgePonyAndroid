# AgePony 4.1.1 — release steps

Closes GitHub issue #9 (msalini). `versionCode 14`, `versionName 4.1.1`.

**The release artifact is built from a clean clone of the tag, not from a working directory.**
Same rule as 3.2.0: F-Droid clones the repo at the pinned commit and builds in a clean room with
no git context and none of your local files, so anything the build quietly depends on that git has
never seen does not exist over there.

Nothing here has been compiled yet. Section 4 is the gate.

## What changed since 4.1.0

The whole release is one bug fix and its test. No dependency moved, and every code change is in
`src/main`, so the `foss` flavor gains nothing new.

| File | What changed |
| --- | --- |
| `vault/Vault.kt` | `bootstrap` and `unlock` now store `vaultKey.copyOf()` instead of the caller's array |
| `app/build.gradle.kts` | 13 / 4.1.0 to 14 / 4.1.1 |
| `androidTest/.../vault/VaultKeyLifecycleInstrumentedTest.kt` | New. Reproduces the lockout and asserts the fix |
| `changelogs/14.txt` | New, 468 chars |

### The bug, in one paragraph

A vault protected by an app password or device PIN, rather than a fingerprint, cleared its own
vault key from memory right after setup. `Vault.bootstrap` stored the caller's key array by
reference, and the three bootstrap paths (`bootstrapWithPassword`, `bootstrapWithDeviceCredential`,
`performDuressWipe`) wipe that array with `vk.fill(0)` for hygiene, which zeroed the vault's live
key. The first `persist()` after setup (creating an identity) then sealed `vault.dat` under an
all-zero key. After the app auto-locked and the user re-entered the password, unlock recovered the
real key from `vault.key.pw`, tried to open `vault.dat` with it, and GCM tag verification failed:
`BAD_DECRYPT`. Biometric vaults were untouched because that path never wipes the key. The fix makes
the vault keep its own copy.

## 1. Confirm the release changeset

```
cd ~/Documents/GitHub/AgePonyAndroid
git status -s
git diff app/build.gradle.kts
```

`git diff app/build.gradle.kts` must show only the versionCode and versionName lines. If it shows a
dependency, stop. Expect four entries in status: the two modified files, the new androidTest
directory, and `changelogs/14.txt`.

Also clear the stale git lock the editing session left behind, so it does not confuse a later
command:

```
rm -rf ~/Documents/GitHub/AgePonyAndroid/.git/_stale_locks
```

## 2. Commit and tag, locally, nothing pushed yet

```
git add app/build.gradle.kts app/src/main/java/com/agepony/app/vault/Vault.kt app/src/androidTest/java/com/agepony/app/vault/VaultKeyLifecycleInstrumentedTest.kt fastlane/metadata/android/en-US/changelogs/14.txt
git commit -F - <<'MSG'
AgePony 4.1.1: fix password/PIN vault lockout (#9)

A vault protected by an app password or device PIN cleared its vault key
from memory right after setup, because Vault.bootstrap stored the
caller's key array by reference and the bootstrap paths wipe that array
for hygiene. The first persist after setup then sealed vault.dat under a
zeroed key, and the next unlock failed GCM verification with BAD_DECRYPT.
Vault.bootstrap and unlock now keep their own copy.

Adds an instrumented regression test over create, add identity, lock,
unlock.

Closes #9.
MSG
git tag -a v4.1.1 -m "AgePony 4.1.1"
```

Nothing is pushed yet, so if verification fails you `git tag -d v4.1.1`, amend, and re-tag. Use the
`v` prefix, matching every existing tag and `UpdateCheckMode: Tags`.

The release runbook doc itself is not in that commit. Add it separately if you want it tracked like
the 3.2.0 one:

```
git add AgePony_4.1.1_Release.md
git commit -m "Add 4.1.1 release runbook"
```

## 3. Build the artifact the way F-Droid will

```
rm -rf /tmp/agepony-verify
git clone --branch v4.1.1 --depth 1 file://$HOME/Documents/GitHub/AgePonyAndroid /tmp/agepony-verify
cd /tmp/agepony-verify
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties
./gradlew clean :agepony-core:test :app:assembleFossRelease
```

Add `local.properties` back because it is gitignored and only points at the SDK. Add nothing else,
and do not copy `keystore.properties` in yet: without it the build is unsigned, which is what
F-Droid produces before its own signature.

```
export APK=/tmp/agepony-verify/app/build/outputs/apk/foss/release/app-foss-release-unsigned.apk
```

## 4. Reproducibility checks, on the clean-clone build

| # | Check | Expect |
| --- | --- | --- |
| A1 | `"$(ls -d ~/Library/Android/sdk/build-tools/*/ | sort -V | tail -1)aapt2" dump badging $APK | head -3` | `versionCode='14'`, `versionName='4.1.1'` |
| A2 | `unzip -l $APK | grep -ci "com/google/android/play"` | `0`, no Play libraries in foss |
| A3 | `unzip -l $APK | grep -i "version-control-info\|dependencies.pb"` | Nothing, both reproducibility guards holding |
| A5 | Second clean clone into a different path, build, hash both | Same sha256 |

For A5:

```
rm -rf /tmp/agepony-verify2
git clone --branch v4.1.1 --depth 1 file://$HOME/Documents/GitHub/AgePonyAndroid /tmp/agepony-verify2
cd /tmp/agepony-verify2
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties
./gradlew clean :app:assembleFossRelease
shasum -a 256 /tmp/agepony-verify/app/build/outputs/apk/foss/release/app-foss-release-unsigned.apk /tmp/agepony-verify2/app/build/outputs/apk/foss/release/app-foss-release-unsigned.apk
```

The two hashes must match. A second directory catches anything that bakes in an absolute path,
which a rebuild in the same directory would miss.

## 5. Sign, install, and prove the fix on a device

Sign the clean-clone build so it can go on a phone. Same source, same compile, just signed:

```
cp ~/Documents/GitHub/AgePonyAndroid/keystore.properties /tmp/agepony-verify/
cp ~/Documents/GitHub/AgePonyAndroid/agepony-upload.jks /tmp/agepony-verify/
cd /tmp/agepony-verify && ./gradlew :app:assembleFossRelease
export ADB=~/Library/Android/sdk/platform-tools/adb
export APK=/tmp/agepony-verify/app/build/outputs/apk/foss/release/app-foss-release.apk
$ADB uninstall com.agepony.app
$ADB install -r $APK
```

The `uninstall` matters: the bug leaves a corrupted `vault.dat` on the device, and only a clean
install proves the new build creates a good one. If you want to first reproduce the original
failure, install the 4.1.0 build, hit the lockout, then install this one over a clean uninstall.

### Issue #9 functional test, on the signed build

| # | Check | Expect |
| --- | --- | --- |
| 1 | First run, choose "Use a password instead", set a password, create one identity | Vault opens, identity listed |
| 2 | Background the app for over 30 seconds so it auto-locks, reopen | "AgePony is locked", password field shown |
| 3 | Enter the password | Vault opens, the identity is still there, no `BAD_DECRYPT` |
| 4 | Repeat 1 to 3 choosing PIN instead of password | Same, opens cleanly |
| 5 | Reset the vault, create with password, add identity, add a recipient and a note, lock, unlock | Everything present after unlock |

The instrumented regression test covers the same path headlessly. With a device or emulator
attached:

```
cd /tmp/agepony-verify && ./gradlew :app:connectedFossDebugAndroidTest
```

`VaultKeyLifecycleInstrumentedTest` must pass. It fails with `BAD_DECRYPT` on the 4.1.0 code and
passes here.

## 6. Push, only after 4 and 5 pass

```
cd ~/Documents/GitHub/AgePonyAndroid
git push origin main
git push origin v4.1.1
```

Do not touch older tags. The F-Droid recipe reads the highest version code across tags, so v4.1.1
becomes the next published build.

## 7. Publish the reproducible artifact

Not optional. The signed FOSS APK, its sha256, and its detached GPG signature are the
reproducible-build record: they let anyone rebuild v4.1.1 from the tag and confirm the bytes
match, and they are what verifiers check against. This ships on every release, same as the
4.0.2 RC. `.apk`, `.apk.asc`, and `.apk.sha256` are gitignored, so they live only on the
release, not in the tree:

```
cp /tmp/agepony-verify/app/build/outputs/apk/foss/release/app-foss-release.apk ~/Downloads/
cd ~/Downloads
gpg --armor --detach-sign app-foss-release.apk
gpg --verify app-foss-release.apk.asc app-foss-release.apk
```

Upload `app-foss-release.apk` and `app-foss-release.apk.asc` to the v4.1.1 release, the same two
asset names every prior release used. GitHub shows each asset's sha256 on the release page, so
there is no separate `.sha256` asset. The `gpg` command uses your default signing key; pass
`--local-user` if you sign with a specific one.

## 8. Play

Separate artifact. Build it from the same clean clone:

```
cd /tmp/agepony-verify
./gradlew :agepony-core:test :app:assemblePlayRelease :app:bundlePlayRelease
```

`versionCode 14` must beat anything ever uploaded to any track, including internal testing. Check
the Console first. Upload `app/build/outputs/bundle/playRelease/app-play-release.aab`, and re-run
the section 5 functional test against the Play-signed artifact from the internal track, since Play
App Signing re-signs the upload.

## 9. Reply to the issue

The reply to msalini is drafted separately. Post it after the release is out and adjust it to say
4.1.1 is available rather than "the next build", and where they can get it (Play, F-Droid once it
picks up the tag, or the signed GitHub release APK).
