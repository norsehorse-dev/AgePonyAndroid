# AgePony

AgePony is an iOS app for file encryption and signing, built on
[age](https://age-encryption.org) and SSH. Everything happens on device — no
accounts, no servers, no tracking.

- **Encrypt / decrypt** files and text to age recipients (X25519, ssh-ed25519,
  ssh-rsa) or with a passphrase (scrypt). Output is standard age, readable by the
  `age` CLI on macOS and Linux.
- **Detached signing** via SSHSIG (`ssh-keygen -Y sign/verify` compatible),
  namespace `agepony`. Sign with an in-app SSH key, a Secure Enclave key, or an
  external **FIDO security key** over NFC — including PIN-protected keys
  (`sk-ssh-ed25519` and `sk-ecdsa-sha2-nistp256`).
- **Multi-file bundles**: pick several files and AgePony tars them into one
  `bundle.tar.age`.
- On-device vault with biometric lock; no telemetry (see `PrivacyInfo.xcprivacy`).

## AgePonyCore

The cryptography lives in `Sources/AgePonyCore`, a dependency-free Swift package
(CryptoKit + Security + CommonCrypto). It implements age, SSH key parsing,
SSHSIG, the FIDO/CTAP2 + PIN-protocol stack, and a USTAR archiver, each pinned to
reference vectors in `Tests/AgePonyCoreTests`. It has no UIKit/app dependencies
and can be reused on its own.

## Build

Open `AgePony.xcodeproj` in Xcode and build the `AgePony` scheme (iOS 16+). Set
your own signing team under Signing & Capabilities — the committed project has an
empty `DEVELOPMENT_TEAM` so you can drop in yours. The NFC security-key feature
needs the Near Field Communication Tag Reading capability and a device (NFC isn't
available in the simulator).

Run the crypto tests:

    swift test

## Sibling project

AgePony's PGP-focused sibling is **PGPony**, which shares the same design and
backend conventions:

- App Store: https://apps.apple.com/us/app/pgpony/id6759994432
- Open-source core: https://github.com/norsehorse-dev/PGPonyCore

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Links

- Website: https://agepony.com
- Contact: NorseHorse@norsehor.se
