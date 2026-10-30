# AgePony 5.1.0

A feature release with a new look, a quicker YubiKey decrypt, a biometrics only lock and a set of
security fixes. Some of the fixes come from an internal security review of the iOS 5.1.0 app. I
checked each finding against the Android code and fixed the ones that applied here too. None of
it changes the age format or your existing files, keys or vault.

## New

- **YubiKey asks for the PIN first.** A YubiKey decrypt used to start with a tap that had no PIN,
  fail when the key wanted one, then ask for the PIN and need a second tap. AgePony now stores
  each YubiKey identity's PIN policy. It reads it from the identity file's comment when you
  import one, asks the key during the import tap on firmware 5.3 and later, and otherwise learns
  it from the first decrypt. A key that needs a PIN gets the PIN dialog first and then one tap. A
  key set to never ask gets one tap and no dialog. Existing YubiKey identities get the PIN dialog
  first, with a "This key has no PIN" button for keys that don't use one. The policy travels with the key when you move it to another phone.
- **Biometrics only lock.** A new lock mode that opens the vault with a strong biometric or your
  app password or PIN, and never with the phone's screen lock. The vault key sits behind a
  Keystore key that Android invalidates when fingerprints or faces are added or removed, so after
  a change only the app password or PIN gets you in. That's why the mode needs one set.
- **New Files tab.** Encrypt and Decrypt are the two buttons at the top, with Sign, Verify,
  Inspect and the other tools listed under them. Signing moved here from its own tab.
- **Key pickers show more than the name.** Every place you pick a key, including the signer
  choice on Encrypt and the key list on Sign, shows the key type and a short form of the key
  under the name. Two keys with the same name can now be told apart.
- **Paste button on Text decrypt.**
- **Clearer errors.** Error messages are whole sentences that say what went wrong and what to
  do, with no raw exception text. Every string in the app now lives in resources, which is the
  groundwork for translations.
- The look of the app was reworked throughout: section headers, list rows, buttons and spacing
  now follow one consistent style.

## Security

- **The first app password needs the owner.** If you skipped setting a password during setup,
  setting one later from Settings asked for nothing. On a phone with a screen lock it now asks
  for a biometric or the screen lock first. Changing the lock mode on a password-only vault asks
  for the password.
- **Decrypted temp files are cleaned up.** AgePony's working copies are swept at launch and when
  the vault locks, so a decrypt you backed out of halfway doesn't leave plaintext in the app's
  cache.
- **Text decrypt checks signatures.** Encrypted text that carries a signature is now verified
  the same way a file is. A bad signature shows as "Decrypted, signature failed", never as a
  plain success.
- **Passphrase files that need more memory than the phone has** show a message saying so,
  instead of crashing.
- **Safer NFC retries.** When a security key's reply is lost mid-tap, AgePony only resends
  commands that are safe to repeat. A PIN check is never resent, so a lost reply can't use up a
  PIN try.
- **A file can't make you tap over and over.** At most 4 entries in a file are tried against
  each hardware key, and a key that errors once is skipped for the rest of that file.
- **Small-order keys refused.** The age core refuses X25519 exchanges that produce an all-zero
  secret, and tests pin the same refusal for ssh-ed25519 recipients.
- **Tested against the C2SP age test vectors.** The age core runs the 147 community test vectors
  (CCTV) as unit tests. The few cases where AgePony answers differently are listed in
  `AgePony_5.1.0_E7_Android.md` with the reason for each.

## Verification

- Signing certificate, SHA-256:
  `1B:28:44:FA:FC:B9:B1:71:97:B8:8E:AD:54:E4:22:79:56:1C:D4:F9:A3:3E:C8:F1:E8:0A:AD:DA:9A:06:83:58`
- SHA-256 of `AgePony-5.1.0-foss.apk`: 82fbfb64ac5149bf7ff515c91327a6a96e2c80cd6b50a8bf86e0233f77473c46
