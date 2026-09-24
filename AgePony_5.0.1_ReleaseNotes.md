# AgePony 5.0.1

A security release. After 5.0.0 went out I ran a full security audit of the Android app, the
iOS app and the shared crypto code. 5.0.1 fixes everything the audit found on Android. None
of it breaks the age format or your existing files, keys or vault.

## New signing key

The keystore AgePony's releases are signed with was committed to this repository's history
by mistake in its first commit, passwords included. It was removed from the tree right away,
but the old commit is still reachable, so the key has to be treated as public.

This key only ever signed the APKs on GitHub Releases. F-Droid builds are signed by F-Droid
with its own key and Google Play copies are re-signed by Google, so installs from either were
never affected.

The GitHub APK for 5.0.1 is signed with a new key, with a rotation proof from the old one.
Android 9 and later accept the update normally and, once 5.0.1 is installed, stop accepting
updates signed only with the old key. Android 8.x doesn't support key rotation. There, only
install updates from GitHub Releases or F-Droid. The new certificate's SHA-256 is
`1B:28:44:FA:FC:B9:B1:71:97:B8:8E:AD:54:E4:22:79:56:1C:D4:F9:A3:3E:C8:F1:E8:0A:AD:DA:9A:06:83:58`,
also in the README.

## Fixed

- **Duress PIN could be skipped.** With a duress PIN set, the lock screen still offered
  fingerprint and the device PIN, and either one opened the real vault. Anyone who knew the
  phone's screen lock got in without ever reaching the duress PIN. Setting a duress PIN now
  makes the vault PIN-only. Fingerprint and device unlock come back if you remove it.
- **The vault stayed unlocked after using the share sheet.** Sharing into AgePony, unlocking
  and tapping Done cancelled the auto-lock timer, so the vault stayed open until Android
  closed the app. Auto-lock is now handled once for the whole app and can't be cancelled
  this way.
- **"No lock" ignored your password.** With No lock and a password set, the vault opened
  without asking for it, even though Settings said the password was the gate. It now asks.
  If you set one up under 5.0.0 and don't remember it, the lock screen offers a one-time way
  to open the vault the old way and remove the password.
- **Password and PIN are harder to guess.** Wrong attempts now cost a wait: 30 seconds after
  5 tries, doubling up to an hour, and it survives restarts. There's an optional setting to
  erase the vault after 10 wrong attempts. The password-wrapped vault key is now also tied to
  this phone's secure hardware, so a copy of the vault files can't be brute-forced somewhere
  else. New PINs need at least 6 digits and new passwords at least 8 characters. Existing
  shorter ones keep working.
- **Screenshots and Recents.** Decrypted text, notes and keys could show up in the Recents
  thumbnail. Screenshots are now blocked across the app by default. Settings has "Allow
  screenshots" if you want them.
- **Key transfer checks the sender too.** Before, the receiving phone couldn't tell who sent
  a transfer, so someone who photographed its QR code on the same Wi-Fi could send first.
  Both phones now show a transfer code, and Import stays disabled until you confirm the codes
  match. The preview lists every key with its fingerprint. Trusted signers have to be ticked
  one by one, and nothing you receive becomes your active key on its own. Both phones need
  5.0.1.
- **Signatures now cover more.** Signed files made by 5.0.1 bind the signature to the
  recipients (for public-key files) and to the file name (for passphrase files), so a
  signed file can't be re-addressed or renamed and still show as signed. Files signed by
  earlier versions still verify, with a note on what their signature doesn't cover.
  Detached `.sig` files are unchanged and still verify with `ssh-keygen -Y verify -n agepony`.
- **allowed_signers restrictions are enforced.** `valid-before`, `valid-after`, `namespaces`
  and `cert-authority` used to be dropped on import. They're now shown in an import preview,
  kept, enforced when verifying, and written back on export. A signer imported by 5.0.0 lost
  its options at the time, so re-import any that had them.
- **Security-key signatures require a touch** unless the signer's entry says
  `no-touch-required`, as OpenSSH does.
- **Failed decrypts leave nothing behind.** A decrypt that failed partway, for example on a
  truncated file, left the part it had written. The destination file is now deleted.
- **Stricter file parsing.** AgePony now reads age headers exactly as strictly as the
  reference age tool and refuses crafted files that tried to exhaust memory or hang the app.
  That covers passphrase files with more than one passphrase entry, huge headers, huge
  bcrypt rounds in SSH keys, and malformed data from NFC security keys.
- **Small RSA keys.** ssh-rsa recipients under 2048 bits can't be encrypted to any more, the
  same limit age has. Files already encrypted to one still decrypt.
- Smaller fixes: temporary copies of shared files are always cleaned up. Shares can't point
  AgePony at its own private files. Other apps' overlays are hidden over AgePony on Android
  12 and later. The duress wipe no longer shows the intro tour or keeps proxy settings.
  Settings are no longer included in Google backups. Weakening the lock asks you to confirm
  first. Paper backups warn about short passphrases.

## Changed

- The app is now built with code shrinking (R8), so the APK is smaller.
- Keys moved with Send keys or restored from paper aren't made your active key. Pick one in
  Settings.
- Archives containing folders, links or extended headers (from desktop `tar`) are no longer
  unpacked in the app. AgePony's own bundles never contain those.

## Verification

- Signing certificate (new key), SHA-256:
  `1B:28:44:FA:FC:B9:B1:71:97:B8:8E:AD:54:E4:22:79:56:1C:D4:F9:A3:3E:C8:F1:E8:0A:AD:DA:9A:06:83:58`
- SHA-256 of `AgePony-5.0.1-foss.apk`: c89662e1020aeae79623d3159b879bedf847ba3910a7f63af0bdf0ed4616f9e3.
