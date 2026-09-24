# AgePony for Android

AgePony is an encryption app for Android built on the [age](https://age-encryption.org/v1) file encryption format. It encrypts and decrypts files and text, signs and verifies them with SSH keys, generates post-quantum hybrid keys, and can keep decryption keys in secure hardware or on a YubiKey. Everything runs on the device: no accounts, no servers, no analytics.

Play Store listing: `com.agepony.app`
Website: https://agepony.com

## Features

- age encryption and decryption for files and text, byte-compatible with the `age` CLI
- Post-quantum hybrid recipients (ML-KEM-768 + X25519), encoded as `age1pq1...` keys
- Passphrase encryption using scrypt recipients, also available from the lock screen without unlocking the vault
- Hardware decryption keys held in the Android Keystore (StrongBox where available), as age 1.3 tag recipients: `age1tag1...` (P-256) or `age1tagpq1...` (ML-KEM-768 + P-256), with optional fingerprint or PIN per decrypt
- Encrypt to age 1.3 tag recipients and to `age1yubikey1...` keys, covering age-plugin-yubikey, age-plugin-se and age-plugin-tpm
- Decrypt with a YubiKey over NFC using the `AGE-PLUGIN-YUBIKEY-1...` identity from age-plugin-yubikey (`piv-p256` and `p256tag` stanzas, PIN when the slot requires it)
- Encrypt to SSH public keys (`ssh-ed25519`, `ssh-rsa`)
- Sign and verify files with SSHSIG from a dedicated Sign tab, using software Ed25519 or RSA keys, Android Keystore hardware keys, or a FIDO2 security key over NFC
- Trusted-signers list that names known keys on a valid signature, round-tripping through the OpenSSH `allowed_signers` format
- Multi-file tar bundling, so a set of files travels as one signed and encrypted archive
- Migration flow that batch re-encrypts existing files to a quantum-safe key, keeping originals until the new copy verifies
- Recipient and identity vault, encrypted with a Keystore-backed master key, unlocked by biometrics or an app-owned password/PIN (so it works on devices with no screen lock)
- Optional duress password that silently wipes the vault when entered under coercion
- Share sheet and text selection: share text or files into AgePony from any app, or select text and encrypt, decrypt or replace it in place where the other app allows
- Move keys to another phone: the receiving phone shows a one-time post-quantum key as a QR code, and the keys go across the local Wi-Fi encrypted to it (RelayPony's local transfer protocol), with a file route when the phones share no network
- Paper backup of age identities as a printable PDF with a QR code, passphrase-protected by default and restorable with `age -d`
- QR scanning and display for exchanging recipient keys
- ASCII armor support

## Verifying your download

This section is about the APK on GitHub Releases. The F-Droid build is built and signed by
F-Droid with its own key, and a Google Play copy is re-signed by Google, so their
certificates differ from the one below by design.

GitHub releases from 5.0.1 on are signed with a new certificate. The key behind the old one
was exposed in this repository's history, so it can't be trusted for anything newer than
5.0.0. Each release carries a signed rotation from the old key to the new one, which lets
Android 9 and later update a 5.0.0 install normally and then refuse updates signed only with
the old key.

To check the signer with [AppVerifier](https://github.com/soupslurpr/AppVerifier), paste this
as the verification info:

```
AgePony
com.agepony.app
1B:28:44:FA:FC:B9:B1:71:97:B8:8E:AD:54:E4:22:79:56:1C:D4:F9:A3:3E:C8:F1:E8:0A:AD:DA:9A:06:83:58
```

The same certificate from `apksigner verify --print-certs` or `keytool`:

```
SHA-256  1B:28:44:FA:FC:B9:B1:71:97:B8:8E:AD:54:E4:22:79:56:1C:D4:F9:A3:3E:C8:F1:E8:0A:AD:DA:9A:06:83:58
SHA-1    93:79:40:57:7B:95:DB:9D:8E:09:7E:EF:F4:BC:70:9F:C4:27:F4:DF
```

`apksigner lineage --in AgePony-5.0.1-foss.apk --print-certs` shows the rotation: the old
certificate first, then the one above. The old certificate is still in the APK's v2
signature, which is the only scheme Android 8.x checks, so on Android 8.x key rotation
offers no protection. On Android 8.x, only install AgePony from GitHub Releases or F-Droid.

Old certificate (5.0.0 and earlier, and the first link of the rotation):

```
SHA-256  6D:02:B1:83:9D:3D:1A:11:9F:24:E9:2B:12:F9:72:86:69:4D:00:1F:F9:96:ED:20:74:B6:B8:39:CC:D0:83:BA
SHA-1    6A:A2:2B:04:B9:8F:0F:0E:1B:D6:16:D3:E0:06:D1:EA:2E:EB:2C:E1
```

Each GitHub release also lists the whole-file `sha256sum` of its APK, for checking the download itself. That value changes every release and only matches the exact file from GitHub Releases.

## Modules

```
agepony-core/   age implementation, no Android UI dependencies
app/            Compose UI, vault, Keystore, NFC, share sheet and local network integration
```

`agepony-core` holds the format work: header and stanza parsing, the streaming payload cipher, Bech32, armor, recipient types (`X25519`, `Scrypt`, `SSHEd25519`, `SSHRSA`, `Hybrid`, `P256` for `piv-p256`, `Tag` for `p256tag` and `mlkem768p256tag`, `YubiKey`), SSH key parsing, SSHSIG, tar bundling, the primitives (ChaCha20-Poly1305, HKDF, scrypt, bcrypt-pbkdf, AES-CTR/CBC, SHA-3, X25519, P-256 HPKE, ML-KEM-768), a CTAP2/CBOR stack for security keys, PIV smart card commands for YubiKeys, and the key transfer, paper backup and local network transfer formats. It depends on Bouncy Castle 1.79 or later, which is the first release with the finalized FIPS 203 ML-KEM.

The public entry point is `Age`:

```kotlin
val ciphertext = Age.encrypt(plaintext, to = listOf(recipient))
val plaintext = Age.decrypt(ciphertext, identities = listOf(identity))
```

`encrypt` and `decrypt` buffer the whole message. `encryptStream` and `decryptStream` are the bounded-memory versions for large files, streaming the payload in 64 KiB chunks with byte-identical output. Output is binary; call `Armor.encode` if you want ASCII armor.

## Build

Requirements: JDK 17, Android SDK 36. The Gradle wrapper is committed, so no separate Gradle install is needed.

```
./gradlew assemblePlayDebug
./gradlew test
```

There are two product flavors on the `store` dimension:

- `play` includes the Google Play In-App Review library and is the Play Store build
- `foss` has no Google dependencies and is the F-Droid build

Each flavor supplies its own `com.agepony.app.review.ReviewPrompt`. The `foss` version is a no-op.

Release builds read signing config from `keystore.properties` at the repo root, which is gitignored and not published. `assembleRelease` without it produces an unsigned build.

For F-Droid reproducibility the release build disables VCS metadata embedding and strips the Google dependency-metadata blob from the APK and bundle. Leave `vcsInfo.include = false` and `dependenciesInfo` alone unless you know what breaks.

minSdk is 26 for the app and 21 for `agepony-core`.

## Tests

```
./gradlew :agepony-core:test
```

Roughly 390 JUnit 5 tests covering the primitives, header and stanza round trips, streaming payloads, SSH key parsing including encrypted private keys, SSHSIG, every recipient type, YubiKey PIV against a simulated card, key transfer and paper backup, and the local network transfer over loopback.

Cross-implementation fixtures live in `agepony-core/src/test/resources/fixtures` and are regenerated by `generate-fixtures.sh` using the reference `age` and `ssh-keygen` tools. `CrossImplFixtureTests` and `CrossImplEncryptedFixtureTests` decrypt them, so a passing suite means files written elsewhere open here and vice versa.

## Interoperability

X25519, scrypt, and SSH recipients follow the age v1 spec and work with the `age` CLI, rage, and AgePony for iOS.

Post-quantum `age1pq1...` recipients (`mlkem768x25519`) and tag recipients (`age1tag1...`, `age1tagpq1...`) follow age 1.3 and are checked against the age 1.3 command line in both directions. Versions of age before 1.3 and other clients that haven't added them yet won't recognize these, so use X25519 recipients when the other side runs an older age.

Signed files decrypt with plain age: the signature rides in its own header stanza, which other clients skip. A passphrase-encrypted signed file keeps the older wrapped format, because age requires a passphrase stanza to be alone in the header.

Key transfers and passphrase-protected paper backups are ordinary age files, so `age -d` opens them on a computer.

## Not implemented on purpose

- Hardware keys can't be moved or backed up. Encrypt important files to a second recipient as well.
- Paper backup covers age keys only. SSH keys aren't included.
- YubiKey decrypt is NFC only. USB-C YubiKeys need a smart card layer AgePony doesn't have yet.

## Permissions

AgePony asks for the camera (QR scanning) and NFC (security keys and YubiKeys). It also holds INTERNET and ACCESS_NETWORK_STATE, used in exactly two places:

- Importing someone's SSH keys from `github.com/<username>.keys`, when you ask for it. This goes through the optional proxy setting (Orbot/Tor) and fails rather than connecting directly if the proxy is down.
- Moving keys between your own phones on the same Wi-Fi. ACCESS_NETWORK_STATE keeps that connection on Wi-Fi so it never uses mobile data. The receiving phone listens only while its Receive keys screen is open, accepts only the sender holding the one-time code from its QR, and only encrypted data crosses the network.

There are no accounts, servers or analytics.

## Contributing

Issues and pull requests are welcome: https://github.com/norsehorse-dev/AgePonyAndroid/issues

For bug reports include the app version, your Android version, and what you were encrypting, decrypting, signing, or verifying. Never paste private keys or real ciphertext into an issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

AgePony is an independent app built on the open age format and is not affiliated with the age project.

## Contact

NorseHorse@norsehor.se

## A note on how this is built

This app is developed solo and with heavy use of AI assistance, which I don't hide. What matters for a tool like this is the crypto, and AgePony implements the open age format and checks its output against the reference age tool in both directions, so a broken encryption path fails a test instead of passing quietly. The full source is here to audit, and bug reports and code review are welcome.
