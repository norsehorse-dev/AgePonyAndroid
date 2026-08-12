# AgePony 4.0.0 — device test plan

The acceptance test for 4.0.0. Everything below compiles and the crypto is unit-tested,
but the two headline features — the full Sign tab and the duress wipe — have not run on
hardware, and both have failure modes a JVM test cannot see: an NFC tap, a biometric
prompt mid-encrypt, and the timing/no-tell properties of the decoy path.

Companion to `AgePony_3.1.0_DeviceTests.md` (its build/install and age-CLI cross-check
sections still apply verbatim; not repeated here).

## 0. Build and install

Build from `~/Apps/AgePonyAndroid` (the signing keystore lives there), install over the
top so the vault survives:

```
cd ~/Apps/AgePonyAndroid
./gradlew assembleFossRelease
export ADB=~/Library/Android/sdk/platform-tools/adb
$ADB install -r app/build/outputs/apk/foss/release/app-foss-release.apk
```

`versionCode` is 10 (up from 9), so `install -r` accepts it as an upgrade. If it refuses
with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, stop and say so rather than uninstalling.

You will need, in the vault before starting: one software SSH Ed25519 identity, one
imported SSH RSA identity (new in 4.0.0), one hardware key, and — if you have a key —
one NFC security key. Plus the Mac's own `ssh-keygen` for the cross-checks.

## 1. Test files

```
mkdir -p /tmp/agepony-test && cd /tmp/agepony-test
printf 'signed by agepony\n' > doc.txt
dd if=/dev/urandom of=big.bin bs=1m count=131
$ADB push doc.txt big.bin /sdcard/Download/
```

## 2. RSA identity import (A5)

| # | Do this | Expect |
| --- | --- | --- |
| 2.1 | On the Mac: `ssh-keygen -t rsa -b 3072 -f /tmp/agepony-test/rsa_id -N ''`. Push `rsa_id` to the phone. Identities → import it | Imports as an SSH RSA identity. Before 4.0.0 this was refused outright. |
| 2.2 | Import an RSA key that has a passphrase (`-N 'pw'`) | Prompts for the passphrase, then imports. |
| 2.3 | Encrypt `doc.txt` to that RSA identity as an encrypt-to-self recipient, then decrypt | Round-trips. RSA identities work as recipients, not just signers. |

## 3. Sign tab — sign a file (A3/A4)

| # | Do this | Expect |
| --- | --- | --- |
| 3.1 | Sign tab exists, second after Files; six tabs total, every label readable | No clipped labels at default font size. |
| 3.2 | Sign → Sign a file → pick the Ed25519 key → pick `doc.txt` → save `doc.txt.sig` | Done screen shows the `ssh-keygen -Y verify -n agepony …` hint. |
| 3.3 | Same with the **RSA** key | Produces an `rsa-sha2-512` signature (confirm in 6.1). |
| 3.4 | Same with the **hardware** key | Biometric prompt appears, then signs. |
| 3.5 | Same with the **NFC security** key | "Hold your security key…" then the PIN dialog if the key wants one; signs on tap. |
| 3.6 | Sign `big.bin` (131 MB) with the Ed25519 key | Completes quickly and at flat memory — the digest streams; the file is not held. |

## 4. Sign tab — verify (A3b)

| # | Do this | Expect |
| --- | --- | --- |
| 4.1 | Verify a file → pick `doc.txt`, then `doc.txt.sig` from 3.2 | "Signed by <your name> ✓" (it matches your own identity). |
| 4.2 | Verify with a signature made by a key **not** in your vault or signers | "Valid signature — signer not in your vault", with an "Add this signer…" button. |
| 4.3 | Add that signer, name it, verify the same file again | Now "Signed by <that name> ✓". |
| 4.4 | Corrupt the file (append a byte) and verify against the old sig | "⚠ Signature invalid". |

## 5. Sign tab — trusted signers (A3b)

| # | Do this | Expect |
| --- | --- | --- |
| 5.1 | Trusted signers → Paste a public key (an `id_ed25519.pub` line), name it | Added; row shows keyType and `SHA256:` fingerprint. |
| 5.2 | Promote a saved SSH recipient | Added from the recipient's key. |
| 5.3 | Export allowed_signers, pull to Mac | `ssh-keygen -Y verify -f allowed_signers -I <principal> -n agepony -s doc.txt.sig < doc.txt` **succeeds** for a name whose key signed `doc.txt`. |
| 5.4 | On the Mac, hand-write an allowed_signers line for a real key; import it | Parses; the signer appears. |
| 5.5 | Import the file exported in 5.3 back in | Duplicates are skipped ("Imported 0, skipped N"). |
| 5.6 | Delete a signer that had signed a file, re-verify that file | Falls back to "valid — not in your vault". |

## 6. Cross-check signing against ssh-keygen (the real correctness test)

```
cd /tmp/agepony-test
# 6.1 — a signature AgePony made verifies with stock OpenSSH:
printf 'ssh-ed25519 AAAA...yourkey... you@host\n' > allowed_signers   # or export from 5.3
ssh-keygen -Y verify -f allowed_signers -I you -n agepony -s doc.txt.sig < doc.txt

# 6.2 — a signature ssh-keygen made verifies in AgePony:
ssh-keygen -Y sign -f rsa_id -n agepony doc.txt        # makes doc.txt.sig
$ADB push doc.txt doc.txt.sig /sdcard/Download/
# then Verify in-app, after adding rsa_id.pub as a signer named to match -I
```

Do 6.1 for the Ed25519, RSA, and hardware-key signatures. Byte-level interop with
OpenSSH is what proves the SSHSIG envelope is right.

## 7. Sign-then-encrypt (A6)

| # | Do this | Expect |
| --- | --- | --- |
| 7.1 | Files → Encrypt `doc.txt`, choose a recipient, pick the **hardware key** as signer | New in 4.0.0: hardware keys appear in this picker. Biometric prompt during the encrypt. |
| 7.2 | Same with the RSA key | RSA appears here too. |
| 7.3 | Security keys are **absent** from this picker | By design — NFC mid-encrypt is excluded (matches iOS). |
| 7.4 | Decrypt a sign-then-encrypt file whose signer is on your trusted-signers list (not your own identity) | Verdict names the signer, not "unknown" — this is the DecryptFlow signers wiring. |

## 8. Duress — the no-tell property (B3)

The whole feature fails if the decoy is distinguishable from a wrong password. Test on a
throwaway vault, or be ready to lose the vault — **the decoy really wipes it.**

Setup: Settings → Security → set a password (say `realpass`), then set a duress password
(say `wipeme`). Add a couple of identities so there is something to lose.

| # | Do this | Expect |
| --- | --- | --- |
| 8.1 | Lock, unlock with `realpass` | Opens normally, identities intact. |
| 8.2 | Lock, unlock with a **wrong** password `zzz` | "Wrong password.", stays locked. |
| 8.3 | Lock, unlock with `wipeme` | Opens to an **empty** vault. No toast, no dialog, no "wiped" message — screen-identical to a brand-new empty vault. |
| 8.4 | Lock again, unlock with `wipeme` again | Still opens (decoy became the real password). Identities still gone. |
| 8.5 | Lock, try `realpass` now | "Wrong password." — the old real password is gone with the old vault. |
| 8.6 | Confirm biometric no longer unlocks (expected: the wipe tore it down) | Password-only from here. Note if this reads as a tell in your threat model. |

## 9. Duress — the timing property (B4, the one unit tests can't do)

Response time must not leak which branch ran. Measure on-device with a debug hook or by
eye over many trials; the criterion is that `wipeme` (duress) and `zzz` (wrong) take
statistically the same time, since both run the same two scrypt derivations.

| # | Do this | Expect |
| --- | --- | --- |
| 9.1 | With a real+duress vault, time 20 unlocks with a wrong password | Record the spread. |
| 9.2 | Time 20 unlocks with the decoy on a freshly re-seeded duress vault each time | Same distribution as 9.1, no systematic gap. |
| 9.3 | Time 20 unlocks with the real password | May differ (it does AEAD-open work the others' failed opens also do); the two that must match are wrong vs. decoy. |

If 9.1 and 9.2 diverge, the branch is leaking and that's a blocker.

## 10. Password/PIN basics

| # | Do this | Expect |
| --- | --- | --- |
| 10.1 | Set a **PIN** instead of a password | Unlock screen shows a numeric keypad. |
| 10.2 | Try to set a duress secret equal to the real one | Refused: "must differ from your real one." |
| 10.3 | Remove the password | Duress removed with it; unlock reverts to biometric. |
| 10.4 | With biometric **on** and a password set, lock | Biometric leads; "Use your password instead" reveals the field. |
| 10.5 | Settings → the biometric toggle copy when off | Reads "no lock at all", not "PIN instead of biometric". |

## 11. Regression — nothing above broke the basics

| # | Do this | Expect |
| --- | --- | --- |
| 11.1 | Decrypt a file made by **3.2.0** | Opens (vault-survives upgrade path). |
| 11.2 | The 3.1.0 large-file sweep (that doc, section 2) | Still flat-memory, still completes. |
| 11.3 | Existing vault with no password set, upgraded from 3.2.0 | Unlocks with biometric exactly as before; the password rows are just new options. |

## What to send back

Pass/fail against the row numbers. For failures: the row, the verbatim screen text, and
for a crash:

```
$ADB logcat -d | grep -iE "agepony|AndroidRuntime" | tail -50
```

Section 9 (timing) is the one to run carefully — it's the property the whole duress
feature rests on and the one no other test covers.
