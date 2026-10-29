# CCTV runner notes (iOS)

Runner: `Tests/AgePonyCoreTests/CCTVTestkitTests.swift`, one XCTest (`testCCTVVectors`) that runs
every vector and fails once with a list of every mismatch. Run it with
`swift test --filter CCTVTestkitTests`.

## API used

- Vectors: `Bundle.module.url(forResource: "Testkit", withExtension: nil)`, then every file in the
  folder except `CCTV-README.md`, `SOURCE.md` and this file. `Package.swift` declares
  `resources: [.copy("Testkit")]` on `AgePonyCoreTests`.
- zlib: the 2-byte zlib header and 4-byte Adler-32 trailer are stripped, the DEFLATE body goes
  through `NSData.decompressed(using: .zlib)` (raw DEFLATE, macOS 10.15+ / iOS 13+), and the
  Adler-32 is checked against the output.
- Armor: `AgeArmor.decode(_ text: String)`, the same `ArmorLineParser` the streaming
  `ArmorDecodingSource` uses.
- Identities: `X25519Identity(ageIdentity:)` for `AGE-SECRET-KEY-1`, `HybridIdentity(ageIdentity:)`
  for `AGE-SECRET-KEY-PQ-1`, `ScryptIdentity(passphrase:)` with the default cap (the app's
  `FileEncryptor` builds it the same way). All identities and passphrases in a vector go in one list.
- Decrypt: `Age.decryptStream(ciphertext: InputStream(data:), identities:, into: OutputStream.toMemory())`.
  Whatever the memory stream holds when it returns or throws is the released plaintext, and its
  SHA-256 is compared with `payload` for `success` and `payload failure`.

## Error mapping and aliases

| AgePony error | CCTV result | Note |
|---|---|---|
| `AgeArmorError` (any) | armor failure | |
| `AgeError.headerError(.invalidMAC)` | HMAC failure | |
| `AgeError.headerError(...)` (other) | header failure | |
| `AgeError.payloadError(.missingNoncePrefix)` | header failure | alias: AgePony reads the nonce in the payload stage, CCTV counts it as header (`stream_no_nonce`, `stream_short_nonce`) |
| `AgeError.payloadError(...)` (other) | payload failure | `streamReadFailed`/`streamWriteFailed` map to "unexpected" (runner problem) |
| `AgeError.noMatchingIdentity`, `.wrongPassphrase` | no match | |
| `AgeError.scryptNotAlone` | header failure | `scrypt_and_x25519`, `scrypt_double` |
| `AgeError.invalidFileKeyLength`, `.truncatedFile` | header failure | |
| `ScryptStanzaError.invalidWorkFactor` | header failure | `scrypt_work_factor_23` |
| anything else | unexpected error | never matches |

Alias "no match" accepted for "header failure": every `AgeIdentity.unwrap` returns nil both for
"not for me" and for a stanza of its own type it can't use, so AgePony reports `no match` where Go
age fails the header. The runner accepts it only when the header parsed and at least one stanza has
a type one of the vector's identities handles. It prints each vector that passes this way. Predicted
(31):

- X25519: `x25519_extra_argument`, `x25519_identity`, `x25519_long_file_key`, `x25519_long_share`,
  `x25519_low_order`, `x25519_not_canonical_share`, `x25519_short_share`
- Hybrid: `hybrid_extra_argument`, `hybrid_identity`, `hybrid_long_file_key`, `hybrid_long_share`,
  `hybrid_low_order`, `hybrid_not_canonical_enc`, `hybrid_short_share`, `hybrid_x25519_arg`
- scrypt: `scrypt_extra_argument`, `scrypt_long_file_key`, `scrypt_not_canonical_salt`,
  `scrypt_salt_long`, `scrypt_salt_missing`, `scrypt_salt_short`, and the work factor vectors
  `_hex`, `_leading_garbage`, `_leading_plus`, `_leading_zero_decimal`, `_leading_zero_octal`,
  `_missing`, `_negative`, `_overflow`, `_trailing_garbage`, `_zero`

All of these fail closed. Matching Go exactly would mean the three identities throw for a malformed
stanza of their own type instead of returning nil; then the alias can go.

## Known divergences (`knownDivergences` in the runner)

Each entry names the outcome AgePony gives instead, and the test fails if a listed vector starts
passing.

Armor whitespace (AgePony gives `success`, CCTV expects `armor failure`): `AgeArmor.decode` trims
every byte <= 0x20, CR included, from both ends of each line on purpose, so pasted armor opens. Its
doc comment says so. The bytes decode the same.
`armor_cr_line_start`, `armor_double_crlf`, `armor_whitespace_eol`, `armor_whitespace_last_line`,
`armor_whitespace_line_start`.

Stream read-ahead (category matches, released plaintext is shorter): `AgePayload.decryptStream`
reads one chunk ahead and opens a chunk only once it knows whether it's the last, so a chunk it would
have to reject is never released. Go opens the chunk first (retrying it as final) and fails
afterwards, so it releases one more chunk. The CCTV hashes match Go's behaviour exactly; this was
checked with a Python model of both readers.
`armor_garbage_encoded`, `stream_no_final_full`, `stream_no_final_two_chunks_full`,
`stream_short_second_chunk`, `stream_trailing_garbage_long`, `stream_trailing_garbage_short`,
`stream_two_final_chunks`, `stream_two_final_chunks_full`, `stream_two_final_chunks_second`.

## Predicted failures

Predictions come from reading the core and running a Python model of AgePony's decrypt path
(header parser, stanza rules, X25519/hybrid/scrypt unwrap, MAC, streaming payload, armor parser)
over all 147 vectors. With the aliases and exceptions above, the model predicts one failure:

- `armor_empty_last_line` (expects armor failure, AgePony gives success). The body ends with a
  full 64-column line, then an empty line, then END. In `ArmorLineParser`'s `.body` state the empty
  line decodes to 0 bytes, counts as the short final line and moves to `.needEnd`, so END is
  accepted. Go rejects it. Not covered by the whitespace leniency. This looks like a bug. Fix:
  reject an empty line in the `.body` state. The Android `Armor.LineParser` mirrors this parser, so
  it probably has the same gap. Left out of `knownDivergences` on purpose.

Possible, depending on CryptoKit:

- `hybrid_identity`, `hybrid_low_order`. `HpkeMlkem768X25519.x25519Exchange` has no all-zero
  check of its own. It relies on CryptoKit throwing for a low-order peer key (its comment says it
  does). If CryptoKit returns the all-zero secret instead, both vectors decrypt fully and the runner
  reports `got success`, which would be a real bug. The fix would be an all-zero check like
  `X25519Identity.isAllZero`. If CryptoKit throws, both pass through the alias. `x25519_identity`
  and `x25519_low_order` are safe either way because `X25519Identity` checks for zero itself.

## Other notes

- The scrypt cap is `ScryptIdentity.maxWorkFactor = 22` (default), not 20 as the E7 plan says.
  `scrypt_work_factor_23` still maps to header failure because 23 > 22. The scrypt vectors use work
  factor 10, so they run fast.
- No vector has an unknown header key at 50a8ecf, so `expectedSkipped` is empty.
- Biggest inputs: `stream_257_chunks`, `stream_257_chunks_full` and `stream_258_chunks` inflate to
  about 16 MB each, about 52 MB in total. Released plaintext goes to a memory stream.

## Compile-time uncertainties

- `NSData.decompressed(using: .zlib)` on raw DEFLATE: Apple documents `.zlib` as raw DEFLATE
  (RFC 1951). The runner strips the zlib wrapper first. If it rejects the input anyway, the 22
  compressed vectors come back as `unexpected error (runner: zlib: ...)`, which would point to the
  runner, not the core.
- The test target uses Swift 6 language mode. All static tables are `Sendable` types. The
  `AgeError` switch ends in `default:`, so new error cases still compile (with at most a
  "default will never be executed" warning).
- With `resources:` on the test target, SwiftPM generates `Bundle.module` for `AgePonyCoreTests`.
  No other non-Swift files sit in `Tests/AgePonyCoreTests`.


## Decisions after the first pass (Oct 26 2026)

- `armor_empty_last_line` is a known divergence, not a bug: AgePony accepts one blank line
  between a full final line and END, as age 1.1.1 does (see StrictFormatTests
  `test_armorWithAFullFinalLine`). Added to `knownDivergences`.
- `hybrid_identity` and `hybrid_low_order`: fixed in the core. `HpkeMlkem768X25519.x25519Exchange`
  now throws `HybridKEMError.lowOrderPoint` on an all-zero shared secret, as the plain X25519
  path already did, for both encapsulation and decapsulation.
- The scrypt cap in the core is 22 (`ScryptIdentity.maxWorkFactor`); the app's memory guard
  refuses earlier on devices that can't fit it. `scrypt_work_factor_23` maps to header failure.
