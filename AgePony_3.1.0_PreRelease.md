# AgePony 3.1.0 — pre-release checks

Shorter than the full device plan, which already passed. This covers three things: what changed
since that run, what a release specifically risks, and what F-Droid will care about.

Build the artifact you intend to ship, and test *that* one:

```
cd ~/Apps/AgePonyAndroid
./gradlew clean :agepony-core:test :app:assembleFossRelease
export ADB=~/Library/Android/sdk/platform-tools/adb
export APK=app/build/outputs/apk/foss/release/app-foss-release.apk
```

## A. The artifact itself

| # | Check | Expect |
| --- | --- | --- |
| A1 | `~/Library/Android/sdk/build-tools/*/aapt2 dump badging $APK \| head -3` | `versionCode='8'` and `versionName='3.1.0'` |
| A2 | `unzip -l $APK \| grep -ci "com/google/android/play"` | `0`. The foss flavor must carry no Play libraries. |
| A3 | `unzip -l $APK \| grep -i "version-control-info\|dependencies.pb"` | Nothing. Both reproducibility guards are doing their job. |
| A4 | `unzip -l $APK \| grep -i eff_large_wordlist` | Nothing, unless you added the wordlist. Either is fine; just know which you are shipping. |
| A5 | Build twice and compare: `shasum -a 256 $APK`, then `./gradlew clean assembleFossRelease` and hash again | Same hash. Not proof of F-Droid reproducibility, but a cheap way to catch anything that bakes in a timestamp or path. |

## B. The upgrade path (the one that actually bites on release day)

| # | Check | Expect |
| --- | --- | --- |
| B1 | With 3.0.2 or the earlier test build installed, `$ADB install -r $APK` | Succeeds without an uninstall. |
| B2 | Open the app, unlock | **Your vault is intact**: identities, recipients and notes all still there. |
| B3 | Settings → About | Shows 3.1.0. |
| B4 | Decrypt a file encrypted by **3.0.2** — binary, armored, and one signed one | All three open, and the signed one still reports its verdict. This is the format-compatibility gate; nothing else matters if this fails. |
| B5 | Decrypt a file made by the **age CLI**, and open a 3.1.0 file with the CLI | Both directions work. |
| B6 | Background the app, reopen | Vault re-locks and returns you to the tab you were on (the folded-in 3.0.3 fix). |

## C. New since the last device run

W7 and W8 were written after the APK you tested, so these are the untried surfaces.

| # | Check | Expect |
| --- | --- | --- |
| C1 | Files → Inspect a file → a **passphrase** file | "Passphrase (scrypt)", the file's own work factor, and its memory cost. |
| C2 | Inspect a **post-quantum** file | "ML-KEM-768 with X25519" and the quantum-safe marker. |
| C3 | Inspect a file encrypted to **several** recipients | One numbered row each, and the "can you decrypt this" line matches reality. |
| C4 | Inspect a file you **cannot** open | "No identity in your vault can open this", and no crash. |
| C5 | Inspect something that is **not** an age file (a photo) | A clean error, back to the picker. |
| C6 | Inspect a **1 GB** file | Instant. If it hangs, it is reading more than the header. |
| C7 | Identities → Recipients → open one → Rename → Save | New name sticks, and shows in the encrypt picker. |
| C8 | Rename to blank | Save is disabled. Nothing is saved. |
| C9 | Encrypt → Choose recipients → paste a key → **Save**, give it a name | Leaves the one-time list, appears among saved recipients, and stays selected for the encrypt in progress. |
| C10 | Finish that encrypt, then decrypt it | Opens. The promoted recipient is a real recipient, not a display trick. |

## D. Quick regression sweep

Not the full plan again, just proof the release build behaves like the one you tested.

| # | Check | Expect |
| --- | --- | --- |
| D1 | Encrypt the 131 MB file to a recipient, armor off, then decrypt it | Works, flat memory, hashes match. |
| D2 | Same with armor on | Works. |
| D3 | Three files → one archive; and three files → one each | Both, with the results list. |
| D4 | Passphrase encrypt at 2^18 and at 2^16 | Both, and both decrypt. |
| D5 | Sign and encrypt, then decrypt | Verdict names your key. |
| D6 | Notes and Text tabs: encrypt and decrypt something small | Untouched by this release, but they share `FileEncryptor`. Worth thirty seconds. |

## E. Before you push the tag

- [ ] `git --no-optional-locks status` is clean, and both repos are byte-identical.
- [ ] `changelogs/8.txt` is under 500 characters (it is 498).
- [ ] The 3.0.2 tag is untouched. Never move, delete or force-push it while the fdroiddata MR is open.
- [ ] The tag you are about to create is `3.1.0`, matching the pattern the existing recipe uses.
- [ ] `full_description.txt` claims QR **sharing**; the code only appears to scan. Fix the copy or the claim before it ships.
