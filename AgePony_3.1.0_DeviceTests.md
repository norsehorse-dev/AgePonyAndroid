# AgePony 3.1.0 — device test plan (Pixel 8 / GrapheneOS)

The acceptance test for this release. Everything below has been unit-tested or compiled, but
none of it has run on hardware yet, and the whole point of the release is one specific failure on
one specific phone.

## 0. Build and install

Build from `~/Apps/AgePonyAndroid`, not the git repo: the signing keystore lives there.

```
cd ~/Apps/AgePonyAndroid
./gradlew assembleFossRelease
```

Install over the top of what is already on the phone:

```
export ADB=~/Library/Android/sdk/platform-tools/adb
$ADB devices                      # confirm the Pixel shows as "device"
$ADB install -r app/build/outputs/apk/foss/release/app-foss-release.apk
```

Why the release variant rather than debug: it is signed with `agepony-upload.jks`, the same key as
the installed 3.0.2, so it upgrades in place and **your vault survives**. A debug build has a
different signature, so it would force an uninstall and take the vault with it. `versionCode` is
still 7, which `install -r` accepts as an equal-version reinstall.

If it refuses with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, stop and say so rather than uninstalling.

## 1. Test files

```
mkdir -p /tmp/agepony-test && cd /tmp/agepony-test
dd if=/dev/urandom of=big.bin      bs=1m count=131     # the reported case
dd if=/dev/urandom of=huge.bin     bs=1m count=1024    # stretch case
dd if=/dev/urandom of=small-a.bin  bs=1k count=200
dd if=/dev/urandom of=small-b.bin  bs=1k count=340
printf 'hello agepony\n' > note.txt

$ADB push big.bin huge.bin small-a.bin small-b.bin note.txt /sdcard/Download/
```

Random rather than zeros: age does not compress, but random content makes a truncation or
off-by-one visible in a hash comparison instead of hiding in a sea of identical bytes.

## 2. The headline case

| # | Do this | Expect |
| --- | --- | --- |
| 2.1 | Files → Encrypt → pick `big.bin`, one recipient, **armor off** | The save dialog appears **before** any work, not after. Then a progress bar that actually advances, with "x MB of 131.2 MB". Finishes. |
| 2.2 | Same, **armor on** | Same, output roughly a third larger. This is the case that used to be worst. |
| 2.3 | While 2.2 runs, in another terminal: `$ADB shell dumpsys meminfo com.agepony.app \| grep -E "Java Heap\|TOTAL"` every few seconds | Java heap stays in the tens of MB and roughly flat. If it climbs past a couple of hundred MB, streaming is not actually streaming somewhere and I want to know. |
| 2.4 | Repeat 2.1 with `huge.bin` (1 GB) | Slower, but completes, and the heap still stays flat. |

**This is the test that decides whether the release did its job.** If 2.1 and 2.2 pass on the
device that reported the bug, the rest is polish.

## 3. Passphrase and work factor

| # | Do this | Expect |
| --- | --- | --- |
| 3.1 | Settings → Encryption. Read the "Passphrase work factor" row | Shows `2^18` and about 256 MB, and says it is age's default. |
| 3.2 | Encrypt `note.txt` with a passphrase at 2^18 | Works, or fails with the new precheck message naming real MB figures. Either is correct; note which. |
| 3.3 | Set the work factor to 2^16, encrypt `note.txt` with a passphrase | About 64 MB. Should comfortably succeed. |
| 3.4 | Set it to 2^20 (1 GB) and try | Should refuse **before** doing any work, with the message about 1 GB not fitting. It should not spin and then die. |
| 3.5 | Decrypt the 2^16 file, and the 2^18 file | Both open. The work factor travels in the file. |
| 3.6 | Open the recipient picker with a passphrase and read the helper text | Reports the current work factor and its memory cost, and turns red if the device is short right now. |

## 4. Multiple files

| # | Do this | Expect |
| --- | --- | --- |
| 4.1 | Encrypt → pick `small-a.bin`, `small-b.bin`, `note.txt` | A chooser appears: one archive, or one file each. |
| 4.2 | Choose **one archive** | One `bundle.tar.age`. Decrypt it, pull it to the Mac, `tar tvf` should list all three. |
| 4.3 | Choose **one file each** | A folder picker, then three `.age` files in that folder and a per-file result list. |
| 4.4 | Repeat 4.3 into the same folder | Names collide; expect `small-a.bin-1.age` style suffixes rather than overwriting. |
| 4.5 | Pick a file from Google Drive or another cloud provider and encrypt it as part of a **bundle** | Exercises the staging path for providers that do not report a size. Should work, just with a pause up front. |

## 5. Signing

| # | Do this | Expect |
| --- | --- | --- |
| 5.1 | Encrypt `big.bin` with an SSH Ed25519 signer | Two phases: "Signing…" then "Encrypting…". The progress bar covers both passes. |
| 5.2 | Decrypt it | Saves the payload, and the verdict reads "Signed by <name> ✓". |
| 5.3 | Decrypt a signed file whose signer is **not** in your vault | "Valid signature — signer not in your vault". |

## 6. Decrypt

| # | Do this | Expect |
| --- | --- | --- |
| 6.1 | Decrypt an armored and a binary file | Both work; armor is detected from the first bytes. |
| 6.2 | Decrypt a passphrase file and type the **wrong** passphrase | Fails **immediately**, before the save dialog appears. This is the header-only probe; if you get asked where to save first, something regressed. |
| 6.3 | Decrypt a file made by **3.0.2** (find an old one, or install nothing and use a file you already have) | Opens normally. |
| 6.4 | Decrypt a file the age CLI made on the Mac | Opens normally. |

## 7. Cross-check against the age CLI

The strongest correctness check available, because it does not trust any of our own code:

```
$ADB pull /sdcard/Download/big.bin.age /tmp/agepony-test/
cd /tmp/agepony-test
age -d -i /path/to/your/key.txt big.bin.age > roundtrip.bin
shasum -a 256 big.bin roundtrip.bin      # the two hashes must be identical
```

And the other direction:

```
age -r age1... -o mac-made.age big.bin
$ADB push mac-made.age /sdcard/Download/
# decrypt on the phone, pull it back, compare hashes again
```

Do this for **both** armored and binary output. Byte-identical round trips through an independent
implementation is what proves the streaming rewrite did not change the format.

## 8. Edge cases worth five minutes

| # | Do this | Expect |
| --- | --- | --- |
| 8.1 | Start an encrypt, then cancel the destination picker | Returns to the configure screen with everything still selected. No half-written file. |
| 8.2 | Start a 1 GB encrypt and background the app | The vault suppression should hold. Note what happens; this is the area 3.0.3 touched. |
| 8.3 | Encrypt to a recipient with no identities in the vault at all | Still works. Decrypt should then offer the passphrase path. |
| 8.4 | Encrypt an empty file | Works. Zero-length is a real edge in the chunking code. |

## 9. Diceware (only once the wordlist asset is in place)

| # | Do this | Expect |
| --- | --- | --- |
| 9.1 | Recipient picker → passphrase mode | A "Suggest a passphrase" button. If it is absent, the asset is missing or not 7776 lines. |
| 9.2 | Tap it | Six words, and a line reading "about 77 bits". Shorter / Longer / Again all work. |
| 9.3 | Tap "Use it" | Both passphrase fields fill with the phrase. |

## What to send back

For anything that fails, the useful things are: which row number, what the screen said verbatim,
and if it crashed:

```
$ADB logcat -d | grep -iE "agepony|AndroidRuntime" | tail -50
```

A pass/fail list against the row numbers is enough for everything else.
