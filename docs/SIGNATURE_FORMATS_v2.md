# AgePony signature formats, v2 (5.0.1)

This is the byte-level spec for the two v2 signature formats added in AgePony 5.0.1 (audit L-8).
The iOS app must produce and accept exactly these bytes. The Kotlin reference is
`agepony-core/.../signing/SignatureStanza.kt` and `agepony-core/.../archive/SignedBundle.kt`.

Why v2: in 5.0.0 every AgePony signature covered only H(payload), all under the SSHSIG namespace
`agepony`. A recipient could re-wrap a signed file to someone else, or rename a signed bundle, and
the signature still checked. v2 signs a structured message that also covers the recipients (sig
stanza) or the manifest with the file name (bundle), under a namespace of its own.

Writers produce v2. Readers accept v1 and v2 and must tell the user which one they verified: a v1
signature does not cover the recipients or the file name.

Detached signatures (`file.sig`) do not change: namespace `agepony`, SSHSIG over the file itself,
checkable with `ssh-keygen -Y verify -n agepony`.

## Conventions

- `string` is SSH wire framing: a big-endian uint32 byte length, then the bytes.
- `uint32` is big-endian.
- SHA-512 is FIPS 180-4 SHA-512 (64 bytes).
- "SSHSIG over M under namespace N" is the standard OpenSSH PROTOCOL.sshsig construction with
  message M: the signature algorithm signs
  `"SSHSIG" || string(N) || string("") || string(hash_alg) || string(H(M))`.
  AgePony writes `hash_alg = "sha512"`; readers accept any hash algorithm SSHSIG allows.
  A signer that takes a precomputed hash is given SHA-512(M).

## Summary

| Format | Version marker | SSHSIG namespace | Message |
| --- | --- | --- | --- |
| Detached `.sig` | none | `agepony` | the file bytes |
| Sig stanza v1 | stanza args `v1` | `agepony` | the plaintext |
| Sig stanza v2 | stanza args `v2` | `agepony-sig-v2` | M_sig below |
| Signed bundle v1 | manifest line `agepony-signed/1` | `agepony` | the payload |
| Signed bundle v2 | manifest line `agepony-signed/2` | `agepony-bundle-v2` | M_bundle below |

A v2 signature re-labelled as v1 fails, because the v1 check requires namespace `agepony`.

## 1. Signature stanza v2 (`agepony.com/sig v2`)

Used for signed files encrypted to public-key recipients. The stanza is an extra age header stanza,
placed after the recipient stanzas:

```
-> agepony.com/sig v2
<base64 body>
```

The argument list is exactly `["v2"]`. A reader treats any other argument list with a `v2` first
argument as unreadable.

### Body (same shape as v1)

```
body  = nonce(12 random bytes) || ChaCha20-Poly1305(key, nonce, plaintext = armored SSHSIG, aad = empty)
key   = HKDF-SHA256(ikm = fileKey, salt = empty, info = "agepony.com/sig-v2", L = 32)
```

v1 uses `info = "agepony.com/sig-v1"`. The labels differ from each other and from age's
`header` and `payload`, so a body sealed for one version never opens as the other.

### Signed message M_sig

```
M_sig = string  "agepony.com/sig v2"        ASCII, 18 bytes
        string  SHA-512(plaintext)           64 bytes
        string  SHA-512(R)                   64 bytes
        string  original file name, UTF-8    always empty (0 bytes) for this stanza

R     = uint32  n
        then n times, in header order, for every header stanza whose type is not "agepony.com/sig":
          string  type                       ASCII
          uint32  argc
          argc times:
            string  arg                      ASCII
          string  body                       raw body bytes (base64-decoded, not the base64 text)
```

The SSHSIG is over M_sig under namespace `agepony-sig-v2`.

Because R holds every wrapped file key, adding, removing or replacing a recipient changes R and the
signature fails. So does re-encrypting the plaintext under a new file key.

### Writing

1. Make the file key and wrap it to every recipient. This gives the recipient stanzas.
2. Compute SHA-512(plaintext) and build M_sig from it and the recipient stanzas.
3. Sign: SSHSIG over M_sig, namespace `agepony-sig-v2`.
4. Seal the armored SSHSIG into the v2 stanza under the file key and append it after the
   recipient stanzas.
5. Write the header (MAC over all stanzas) and the payload as usual.

A passphrase (scrypt) file cannot carry the stanza (age requires scrypt to stand alone). It uses
the signed bundle instead.

### Reading (three-way result)

After the header MAC checks out under the file key:

- no `agepony.com/sig` stanza: **absent** (unsigned);
- more than one, unknown version, missing version, a `v2` stanza with extra arguments, a body
  shorter than 12 + 16 bytes, or an AEAD failure: **unreadable**. Show it as a failed signature,
  never as unsigned;
- otherwise **opened**, with its version. For v2, rebuild R from the parsed header stanzas and
  verify the SSHSIG over M_sig under `agepony-sig-v2`. For v1, verify over the plaintext under
  `agepony`.

### Test vector

Header stanzas, in order:

1. type `X25519`, args `["AAAA"]`, body bytes `00 01 02 ... 1f` (32 bytes)
2. type `agepony.com/sig`, args `["v2"]`, body 40 zero bytes (skipped by R)
3. type `mlkem768x25519`, no args, body `7f 7f 7f`

With SHA-512(plaintext) replaced by 64 bytes of `0x11` and an empty name, SHA-256(M_sig) is

```
8c7f506293ca9e956acaa380e6ee07f3d613e56e8b181158dbc98a97ed65524f
```

## 2. Signed bundle v2 (`agepony-signed/2`)

Used for signed passphrase files: a USTAR archive, age-encrypted as a whole, with entries in this
order:

| Entry | Contents |
| --- | --- |
| `.agepony-signed` | manifest |
| `payload` | the original file bytes |
| `payload.sig` | the armored SSHSIG |

### Manifest

```
agepony-signed/2\n
name=<original name>\n
```

In the name, CR and LF are replaced with `_`, surrounding whitespace is trimmed, and an empty
result becomes `file`. The first line must be exactly `agepony-signed/2` for v2. Any other
`agepony-signed/` first line is read as v1. Readers cap the manifest at 4096 bytes and the
signature entry at 8192 bytes.

### Signed message M_bundle

```
M_bundle = string  "agepony.com/bundle v2"   ASCII, 21 bytes
           string  manifest                  the exact bytes of the .agepony-signed entry
           string  SHA-512(payload)          64 bytes
```

The SSHSIG is over M_bundle under namespace `agepony-bundle-v2`. The manifest goes in byte for
byte, so the name and any line a later version adds are covered.

### Test vector

manifest = `agepony-signed/2\nname=report.pdf\n` (33 bytes), SHA-512(payload) replaced by 64 bytes
of `0x22`. SHA-256(M_bundle) is

```
f1e944ee38ee10dac9cbf6601f0dd110e826244d8dc01aa0662104433386d0b7
```

## 3. allowed_signers and the v2 namespaces

An allowed_signers entry restricted with `namespaces="agepony"` was written for AgePony. AgePony
treats it as also permitting `agepony-sig-v2` and `agepony-bundle-v2`, unless the pattern list
explicitly negates them (for example `namespaces="agepony,!agepony-sig-v2"`). Other tools
(`ssh-keygen -Y verify`) match namespaces literally.

## 4. Key-transfer code (not a signature, listed for the iOS port)

Both phones show a code over the exact sealed transfer so the user can check the receiver got the
sender's transfer (audit M-6). The wire format is unchanged.

```
digest = SHA-256("agepony.com/transfer-code v1" || 0x00 || sealed)
code   = first 60 bits of digest, as 12 Crockford base32 characters
         (alphabet 0123456789ABCDEFGHJKMNPQRSTVWXYZ), grouped XXXX-XXXX-XXXX
```

`sealed` is the binary age file. An armored transfer (the paste route) is de-armored first.

Test vector: sealed = the 36 ASCII bytes `age-encryption.org/v1\n-> X25519 abc\n` gives
`QNED-DFQW-8WY0`.
