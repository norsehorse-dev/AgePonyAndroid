# AgePony 4.2.0

Fetch a recipient's key over a proxy, and get your files out of a bundle.

Three changes this release: the GitHub key fetch can go through a proxy, passphrase
fields are hidden as you type, and decrypting a multi-file bundle can extract straight
into a folder instead of leaving you a `.tar` to open yourself.

## Added

- **Proxy for key lookup.** Add Recipient → GitHub fetches `github.com/<user>.keys`, and
  that request can now go through a SOCKS5 or HTTP proxy, set under Settings → Network.
  Point it at Tor or Orbot (127.0.0.1:9050) to pull a recipient's key over Tor, or at a
  network proxy where GitHub is otherwise blocked. It is off by default, and off behaves
  exactly as before: a direct connection. The hostname is handed to the proxy unresolved,
  so DNS goes through it too rather than leaking to the local network, which is what makes
  the Tor case actually private. A fetch to `https://github.com` through an HTTP proxy uses
  CONNECT, so the TLS session stays end to end and the proxy sees only the hostname.
- **Extract files when decrypting a bundle.** Encrypting several files at once packs them
  into one archive. Until now, decrypting that gave you a single `.tar` to unpack with
  another tool. When the decrypted file is a bundle, the Done screen now offers "Extract
  files into a folder" and writes each file out where you choose. A single file decrypts
  exactly as before, with no extra prompt.

## Fixed

- **Passphrase fields are hidden.** The passphrase boxes on the Decrypt screen, the Text
  decrypt screen, and the Migrate screen showed what you typed in the clear. They are now
  masked, and use a password keyboard so the input is not offered to autocorrect or
  prediction. The other passphrase and PIN fields in the app were already masked; these
  three were not.

## Deliberate limits

- **The proxy covers the key fetch, nothing else.** That GitHub request is the only time
  AgePony reaches the network for key material, so it is the only thing routed. Links you
  open from Settings still go to the system browser as they always did.
- **A half-set proxy fails loudly.** Turn the proxy on but leave the host or port blank and
  the fetch reports "Incomplete proxy settings" rather than quietly falling back to a direct
  connection. A direct connection you did not ask for is the exact leak the proxy exists to
  prevent.
- **Extraction flattens folders.** Each entry is written by its own name into the folder you
  pick, with any path stripped, so a crafted bundle cannot write outside that folder.
  Bundles AgePony writes are flat anyway; a bundle from another tool that carried directories
  loses them. Name clashes are de-duplicated (`report.pdf`, then `report-1.pdf`).

## Compatibility

- **No format change.** `agepony-core` gains one read-only helper for spotting a tar header
  and nothing else. The age implementation, every recipient type and the streaming payload
  cipher are untouched. Files written by 4.2.0 are ordinary age files, and files from earlier
  AgePony versions or the age CLI open unchanged.
- **No vault change.** The proxy settings are stored as app preferences, not in the encrypted
  vault snapshot, so upgrading in place keeps every identity, recipient and note.
- **No new permissions, no new dependencies.** The GitHub fetch already used INTERNET; nothing
  else was added. Every source change lives in `src/main` and `agepony-core`, so the F-Droid
  `foss` flavor gets all three changes too.

`versionCode 15`, `versionName 4.2.0`.

---

## Short form, for Play and F-Droid

For `fastlane/metadata/android/en-US/changelogs/15.txt`, 379 characters:

```
AgePony 4.2.0 adds a proxy for key lookup, and two fixes.

- Fetch a recipient's GitHub keys over a SOCKS5 or HTTP proxy, set in Settings > Network. Point it at Tor/Orbot to pull keys over Tor, or past a network block. Off by default.
- Passphrase fields are now hidden as you type.
- Decrypting a multi-file bundle can extract the files into a folder instead of leaving a .tar.
```
