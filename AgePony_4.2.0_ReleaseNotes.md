# AgePony 4.2.0

Fetch a recipient's key over Tor, encrypt to a YubiKey, and find your way around
a little more easily.

This release adds the network and hardware pieces people asked for, and fills in
the parts of the app that were doing their work without ever explaining
themselves. Nothing about the file format or the vault changes, so upgrading in
place keeps every identity, recipient and note.

## Added

- **Proxy for key lookup.** The one time AgePony reaches the network, the GitHub
  key fetch under Add Recipient, can now go through a proxy, set in Settings >
  Network. Off (a direct connection, the default), Orbot (Tor, one tap for
  127.0.0.1:9050), or Custom (your own SOCKS5 or HTTP host and port). An optional
  username and password are sent as SOCKS auth; for Tor that is stream isolation,
  so AgePony's traffic rides its own circuit. The hostname is resolved at the
  proxy, not on the device, so a lookup over Tor does not leak the name to the
  local network.
- **YubiKey recipients.** AgePony now accepts `age1yubikey1...` recipients from
  age-plugin-yubikey and encrypts to them, using the piv-p256 format (P-256 ECDH,
  HKDF-SHA256, ChaCha20-Poly1305). Only the YubiKey can decrypt, so AgePony
  encrypts to one of these but does not read it back; the file opens with `age`
  and the key.
- **Configurable auto-lock.** Settings > Auto-lock now sets how long AgePony waits
  after you leave the app before it locks: immediately, 15 seconds, 30 seconds
  (the default), one minute, or five minutes. A quick switch to paste a key no
  longer costs you your place.
- **Recently deleted.** Deleting an identity or recipient now moves it to a recycle
  bin instead of erasing it, reachable from the Identities screen. Restore an
  accidental delete, or remove it for good; entries age out after 30 days. This
  matters most for identities, where a delete otherwise takes a private key with
  it.
- **Key avatars.** Identities and recipients now carry a small colored avatar
  derived from the key, so two `age1...` entries are easy to tell apart at a
  glance. The same key always draws the same avatar.
- **In-app Help, Security, and Licenses.** Settings gains a plain-language FAQ, a
  single page describing how AgePony protects your files and what it does not do,
  and the open-source notices for the libraries the app builds on.

## Fixed

- **Passphrase fields are hidden.** The passphrase boxes on the Decrypt, Text
  decrypt, and Migrate screens showed what you typed in the clear. They are now
  masked and use a password keyboard, so the input is not offered to autocorrect.
  The other passphrase and PIN fields were already masked; these three were not.

## Deliberate limits

- **The proxy covers the key fetch, nothing else.** That GitHub request is the
  only time AgePony reaches the network for key material, so it is the only thing
  routed. Links you open from Settings still go to the system browser.
- **A half-set or dead proxy fails loudly.** Enable a proxy with a blank host or
  port, or point it at something unreachable, and the fetch reports the failure
  rather than quietly falling back to a direct connection. A direct connection you
  did not ask for is the exact leak the proxy exists to prevent.
- **AgePony encrypts to a YubiKey recipient but cannot decrypt for one.** The
  private key never leaves the YubiKey, so decryption happens with `age` and the
  key, not in AgePony.

## Compatibility

- **No format change.** `agepony-core` gains the piv-p256 recipient and a
  read-only helper for spotting a tar header, and nothing else. The age
  implementation, the other recipient types and the streaming payload cipher are
  untouched. Files written by 4.2.0 are ordinary age files, and files from earlier
  AgePony versions or the age CLI open unchanged.
- **No vault change.** Proxy and auto-lock settings are stored as app preferences,
  not in the encrypted vault, so upgrading in place keeps every identity, recipient
  and note.
- **F-Droid gets everything.** Every change lives in `src/main` and `agepony-core`;
  the `foss` flavor carries the whole release. The only Google dependency stays
  scoped to the `play` flavor, as before.

`versionCode 15`, `versionName 4.2.0`.
