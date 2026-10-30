# AgePony key transfer, `agepony.com/transfer v1`

How AgePony moves keys between devices (Send keys / Receive keys, 5.0.0). Both apps read and
write exactly this; a transfer made on one opens on the other. The Kotlin reference is
`agepony-core/.../portability/KeyTransfer.kt` (container) and `app/.../vault/KeyPortability.kt`
(`agepony.json`). iOS mirrors them in `KeyPortability.swift`.

## Container

The receiving device makes a one-time post-quantum identity and shows its recipient. The sender
encrypts a ustar archive to it, so the transfer is an ordinary age file. Archive entries:

| Entry | Contents |
| --- | --- |
| `FORMAT` | `agepony.com/transfer v1` and a newline. |
| `identities.txt` | A standard age identity file: `# name:`, `# created:`, `# public key:` comments, then the secret key (or an `AGE-PLUGIN-YUBIKEY-1` line for a YubiKey). Works with `age -i` as it is. |
| `ssh/<name>` | OpenSSH private keys, when any were sent. |
| `agepony.json` | AgePony's metadata, below. |

Keys bound to one device's secure hardware (Keystore on Android, Secure Enclave on iOS) never
travel. Senders leave them out and readers drop them.

## agepony.json

```json
{
  "format": "agepony.com/transfer v1",
  "app": "AgePony Android",
  "identities": [ ... ],
  "recipients": [ ... ],
  "signers": [ ... ]
}
```

Readers ignore keys they don't know, and decode each record on its own, so one record from a
newer version (a key type this one doesn't have) is skipped without losing the rest.

### Identity records

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Replaced with a fresh id on import. |
| `name` | string | |
| `type` | string | `x25519`, `mlkem768x25519`, `sshEd25519`, `sshRSA`, `skEd25519`, `skEcdsaP256`, `yubikeyPiv`. |
| `publicKeyB64` | string | Base64, shape per type below. |
| `privateKeyB64` | string | Base64, shape per type below. |
| `sshComment` | string, optional | |
| `keystoreAlias` | string, optional | Always dropped on import. |
| `createdAt` | integer | Unix time in milliseconds. |
| `pinPolicy` | string, optional | `yubikeyPiv` only (5.1.0), see below. |

| `type` | `publicKeyB64` | `privateKeyB64` |
| --- | --- | --- |
| `x25519` | 32-byte X25519 public key | 32-byte scalar |
| `mlkem768x25519` | 1216-byte hybrid public key | 32-byte seed |
| `sshEd25519` | 32-byte Ed25519 public key | 32-byte seed |
| `sshRSA` | UTF-8 `ssh-rsa BASE64 [comment]` line | UTF-8 OpenSSH PEM, unencrypted |
| `skEd25519`, `skEcdsaP256` | sk public key wire | credential id |
| `yubikeyPiv` | 33-byte compressed P-256 point | 9-byte AGE-PLUGIN-YUBIKEY stub |

A reader checks that the private half gives the stated public key (for a YubiKey, that the
stub's tag is the hash of the public key) and drops a record that doesn't.

### `pinPolicy` (5.1.0)

Whether the YubiKey PIV slot needs its PIN before an ECDH, so the receiving app asks for the PIN
before the tap instead of after a failed one.

- `"required"`: PIN policy Once or Always (age-plugin-yubikey's default is Once; every NFC tap is
  a new PIV session, so both need the PIN on every tap).
- `"notRequired"`: PIN policy Never.
- Left out when the policy isn't known, and on every type other than `yubikeyPiv`.

A reader treats a missing value, `null`, or a value it doesn't know as unknown: it asks for the
PIN first, with a "This key has no PIN" choice. Readers before 5.1.0 ignore the field.

### Recipient records

`id`, `name`, `type` (`x25519`, `mlkem768x25519`, `sshEd25519`, `sshRSA`, `yubikeyP256`, `tag`,
`tagPQ`), `publicKeyB64`, `sshComment` (optional), `source`, `sourceMetadata` (optional),
`createdAt`. Key shapes as for identities; `tag` is a 33-byte compressed P-256 point and `tagPQ`
the 1249-byte hybrid recipient.

### Signer records

`id`, `name`, `keyType`, `publicKeyWireB64` (SSH public key wire), `comment` (optional),
`source`, `createdAt`, `options` (optional, the allowed_signers options verbatim). Only signers
the user ticks are imported, and signers whose options AgePony can't enforce are skipped.
