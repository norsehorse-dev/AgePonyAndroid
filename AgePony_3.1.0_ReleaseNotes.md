# AgePony 3.1.0

Large files no longer fail.

AgePony used to read a whole file into memory before encrypting it, then hold the result in memory
again until you chose where to save it. On a phone that put a hard ceiling on file size, and a
130 MB file could exhaust the heap on a device with plenty of storage free. Files are now streamed
from the provider's input straight to the provider's output, one 64 KiB chunk at a time, so a 1 GB
file encrypts the same way a 1 KB file does and the app never holds more than a small buffer.

Thanks to the anonymous tester who reported this with a precise description and full device
details. It was reproduced and fixed on the same hardware it was reported from.

## Fixed

- **Out of memory on large files.** Reported against a 131 MB file on a Pixel 8 running
  GrapheneOS with hardened_malloc and memory tagging enabled. Encrypt and decrypt are now
  bounded-memory throughout, including ASCII armor, multi-file archives, and encrypt-and-sign.
- **A misleading error message.** The out-of-memory notice claimed the passphrase was at fault
  even when no passphrase was used, and suggested trying a smaller file, which does not help.
  scrypt allocates 256 MB at the default work factor no matter how large the file is. The app now
  says which allocation actually failed, and checks that scrypt will fit before starting rather
  than failing part way through.
- **The vault no longer forgets which tab you were on** when it re-locks on background. This fix
  was queued as 3.0.3 and is folded into this release.

## Added

- **One archive, or one file each.** Picking several files now asks which you want. Choosing
  separate files asks for a destination folder and writes one `.age` per input, with a per-file
  result list so one failure does not sink the batch.
- **A header inspector.** Shows which keys can open an age file without decrypting it: recipient
  types, the post-quantum marker, and for passphrase files the work factor and what it will cost
  in memory. It reads only the header, so it is instant on a file of any size. Recipient stanzas
  are public information, so this reveals nothing that the holder of the file does not already
  have.
- **An adjustable scrypt work factor** (2^16 to 2^20, default 2^18, in Settings), for devices
  that cannot spare 256 MB. The factor is written into the file, so every value stays readable by
  any age implementation.
- **Real progress** while encrypting and decrypting, in bytes.
- **Rename saved recipients**, and save a key pasted during an encrypt as a named recipient
  instead of a one-time entry.

## Compatibility

- No format change. Files produced by 3.1.0 are ordinary age files, and files produced by earlier
  AgePony versions or by the age CLI open unchanged.
- Every streaming path was tested to produce byte-identical output to the buffered path it
  replaces, including a golden checksum on the archive format that guarantees parity with the iOS
  implementation.
- Wrong passphrases are now rejected from the header alone, so a bad passphrase fails immediately
  instead of after a full decrypt attempt.

## Under the hood

`agepony-core` gained pull and push shaped counterparts to its whole-buffer APIs: an armor
encoding sink and decoding source, a tar reader and writer that never materialize an archive, a
signed-bundle wrapper that is stripped mid-stream while its payload is hashed, streaming SSHSIG
hashing so a large file can be signed without being held, and a header-only decryption probe.

---

## Short form, for Play and F-Droid

Already in `fastlane/metadata/android/en-US/changelogs/8.txt`, 497 characters:

```
AgePony 3.1.0 makes file size stop mattering.

- Encrypt and decrypt files of any size. Nothing is held in memory, so a 1 GB file works like a small one.
- Encrypting several files now asks: one archive, or one encrypted file each.
- Inspect any age file to see what it is encrypted to, without decrypting it.
- The scrypt work factor is adjustable now, for devices with less memory to spare.
- Rename saved recipients, and save a pasted key with a name.
- Returns to the tab you left on re-lock.
```
