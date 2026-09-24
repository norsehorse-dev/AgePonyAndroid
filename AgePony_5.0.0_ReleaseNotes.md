# AgePony 5.0.0

Keys that live in hardware, keys you can move to another phone or put on paper, and AgePony
in the share sheet.

5.0.0 also carries everything planned for 4.3.0, which never shipped on its own: signed
files that plain age can read, and a fix for a crash on passphrase files made with a high
work factor.

## Added

- **Share sheet and text selection.** Share text or files into AgePony from any app. It sees
  whether what you shared is already encrypted and opens decrypt or encrypt to match.
  Shared files are read straight from the app that shared them and nothing is copied into
  AgePony's storage. Select text in an app, pick AgePony from the ⋮ menu, encrypt it, and
  "Replace the selected text" puts the ciphertext back in place. Apps that only let AgePony
  read the selection get a note to copy and paste instead. Encrypted results share straight
  out. Decrypted text can be shared too, after a warning that it leaves AgePony. (#14)
- **Hardware decryption keys.** Identities > Generate > Hardware decryption key creates a
  P-256 key inside the phone's secure hardware (StrongBox when the phone has one, otherwise
  the TEE). It is published as an age 1.3 `age1tag1...` recipient, so the age command line
  (1.3 or later) can encrypt to your phone with no plugin. Quantum-safe by default: the
  `age1tagpq1...` form adds ML-KEM-768, held in your vault, on top of the hardware P-256
  half. You can require your fingerprint or device PIN for each decrypt. That's off by
  default, because Android deletes keys like this if the screen lock is ever removed.
  Creating one needs Android 12 or later.
- **Encrypt to age 1.3 tag recipients.** Paste an `age1tag1...` or `age1tagpq1...` key as a
  recipient. That covers newer age-plugin-yubikey, age-plugin-se and age-plugin-tpm keys.
- **Decrypt with a YubiKey.** Paste the `AGE-PLUGIN-YUBIKEY-1...` line from
  age-plugin-yubikey into Import identity and tap the YubiKey once so AgePony can read the
  key in that slot. After that, files encrypted to it (older `piv-p256` and newer `p256tag`)
  decrypt over NFC with a tap, plus the PIN when the slot requires it. AgePony only asks for
  a tap when the file is actually addressed to that key. 4.2.0 could encrypt to a YubiKey but
  not decrypt, and the YubiKey report in #10 is why this was on the list.
- **Move keys to another phone.** Settings > Send keys / Receive keys. The receiving phone
  shows a one-time post-quantum key as a QR code, the sending phone encrypts your
  identities, recipients and trusted signers to it, and both screens show the same short
  code so you can confirm you scanned the right phone. With both phones on the same Wi-Fi
  (or one on the other's hotspot) the keys go straight across in a few seconds, using
  RelayPony's local transfer protocol. The QR code carries the receiving phone's address,
  so nothing scans the network, and only encrypted data crosses it. The sending phone
  shows Sent only once the receiving phone has opened the transfer. Without shared Wi-Fi
  there's a file route instead. Either way the transfer is an ordinary age file: `age -d`
  with the receiving key gives a standard age identity file. Hardware keys stay on the
  phone they were made on.
- **Paper backup.** Open an age identity and choose Paper backup to get a printable PDF with
  a QR code and the text. By default the page is protected with a passphrase and is itself
  an ordinary age file, so it restores in AgePony (Settings > Restore from a paper backup)
  or with `age -d` on a computer. A plain, unprotected page is available for people who keep
  it in a safe.
- **Passphrase work without unlocking.** The lock screen has "Continue without unlocking" for
  encrypting or decrypting text with a passphrase and decrypting passphrase files. The vault
  stays locked and none of its keys are touched. A share that arrives while AgePony is
  locked gets the same option. (#13)

## Changed

- **Signed files are plain age files again.** Encrypt-and-sign used to wrap the file and its
  signature together inside the ciphertext, so decrypting with the age command line gave
  back the wrapper instead of your file. The signature now travels in an extra, encrypted
  stanza in the age header. Plain `age -d` ignores it and returns the original bytes;
  AgePony reads it and verifies the signer, who is still hidden from anyone who can't
  decrypt. Signed files from 4.x still open and verify. (#11, surfaced by testing on #10)
- **Software keys are tried before hardware keys.** When a file is encrypted to both a
  hardware key and a normal one, AgePony opens it with the normal key without asking for a
  tap or a prompt. A cancelled prompt or an invalidated hardware key no longer blocks a file
  another key in your vault can open.
- **Wiping the vault removes AgePony's keys from the Keystore too.** That covers a reset and
  the duress password. Removing an identity from Recently deleted also deletes its Keystore
  key. Before this, hardware signing keys stayed in the Keystore after they were gone from
  the vault.

## Fixed

- **Passphrase files with a high work factor crashed the app.** Some tools (rage, for one)
  pick the scrypt work factor by benchmarking the computer, and a fast desktop can choose
  2^20 or more, which needs over a gigabyte of memory to open. AgePony tried anyway, and
  opening such a file as a file closed the app without a word. It now checks the memory
  needed before starting and says clearly when a phone can't open that file, the same way
  for text and files. (#12)
- **A one-time `age1yubikey1...` recipient in the recipient picker was rejected.** It was
  sent to the X25519 parser. It is accepted now, along with the new tag recipients.

## Deliberate limits

- **Hardware keys can't be moved or backed up.** That is what makes them hardware keys. The
  create screen says so, and suggests encrypting important files to a second recipient.
- **YubiKey decrypt is NFC only.** USB-C YubiKeys need a smart card layer AgePony doesn't
  have yet.
- **Replace works only where the other app allows it.** Some apps let AgePony read selected
  text but won't take a replacement back. AgePony tells you when that happens.
- **Paper backup covers age keys only.** SSH keys aren't included.
- **A passphrase-encrypted signed file keeps the old wrapped format.** The age spec requires a
  passphrase stanza to be alone in the header, so the signature can't ride along there.

## Permissions

- **One new permission, ACCESS_NETWORK_STATE.** Android grants it at install without a
  prompt. It lets the key transfer keep its connection on Wi-Fi so it never goes over mobile
  data. No location, nearby devices or Bluetooth permission is needed. The receiving phone
  only listens while the Receive keys screen is open, and only accepts the sender holding
  the one-time code from its QR.

## Compatibility

- **Plain age reads everything AgePony writes.** Checked against the age 1.3 command line:
  signed files, post-quantum `age1pq1` files in both directions, tag recipients in both
  directions (with age's own test plugin), and key transfers. Paper backups are ordinary
  passphrase (scrypt) age files.
- **Vault.** Upgrading keeps every identity, recipient and note. Once a vault holds one of
  the new key types (hardware decryption key, YubiKey), a version older than 5.0.0 can't
  open it.
- **F-Droid gets everything.** Every change is in `src/main` and `agepony-core`, so the `foss`
  flavor carries the whole release.

`versionCode 16`, `versionName 5.0.0`.

## Verifying this build

This release is reproducible. Two independent builds from clean clones of the `v5.0.0` tag
are byte-identical, and the published APK matches them; the same check runs in F-Droid's
clean room.

- Content hash (signatures ignored, for reproducible-build verification): `TODO`
- Whole-file SHA-256 of the download: `TODO` (also in `AgePony-5.0.0-foss.apk.sha256`)
- Signature: `AgePony-5.0.0-foss.apk.asc`, made with the NorseHorse release key, the same key
  F-Droid distributes.

The `foss` APK is the F-Droid build; it installs over an F-Droid copy with no uninstall.
