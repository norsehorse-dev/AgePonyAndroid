# AgePony 5.1.0 E7 (Android core)

Port of two core changes already done on iOS (commit 5a0c70d): the C2SP CCTV age test vectors
in the core's tests, and the low-order X25519 check in the hybrid KEM. Only `agepony-core/` is
touched. Not built or run yet.

Run: `./gradlew :agepony-core:test` (or `--tests com.agepony.core.CCTVTestkitTest` for the
vectors alone).

## Files

Added:

- `agepony-core/src/test/resources/cctv-testkit/`: the 147 CCTV vectors (commit 50a8ecf), plus
  `SOURCE.md`, `CCTV-README.md` and `RUNNER-NOTES.md`, copied byte for byte from the iOS repo's
  `Tests/AgePonyCoreTests/Testkit` (checked with sha256sum). `RUNNER-NOTES.md` is the iOS notes
  file, kept as is for reference.
- `agepony-core/src/test/kotlin/com/agepony/core/CCTVTestkitTest.kt`: the runner.
- `agepony-core/src/test/kotlin/com/agepony/core/crypto/HpkeMlkem768X25519Tests.kt`: low-order
  tests for the hybrid KEM.

Changed:

- `agepony-core/src/main/kotlin/com/agepony/core/crypto/HpkeMlkem768X25519.kt`: new
  `HpkeMlkem768X25519.LowOrderPointException` (an `IllegalArgumentException`), a private
  `x25519Exchange` used by both `encap` and `decap`, and a constant-time `isAllZero`.

## Low-order X25519 in the hybrid KEM

iOS added `HybridKEMError.lowOrderPoint` and an all-zero check on the X25519 shared secret. On
Android, Bouncy Castle already refuses the all-zero secret by throwing `IllegalStateException`,
so the behaviour was safe but depended on the provider, and `decap` let that raw exception out.
Now both sides go through `x25519Exchange`, which maps the Bouncy Castle refusal and an explicit
all-zero result (OR of every byte, no early exit) to `LowOrderPointException`:

- encap: "hybrid recipient X25519 key is a low-order point; refusing to encrypt to it" (same
  message as before, and still an `IllegalArgumentException`, so the existing
  `MLKEM768ValidationTest` check holds).
- decap: "hybrid enc X25519 share is a low-order point".

`HybridIdentity.unwrap` still returns null for it (it catches any exception), so decrypt
behaviour is unchanged: the file reports no match.

The plain X25519 path (`X25519Recipient`, `X25519Identity`, and `SSHEd25519`) already rejects
an all-zero secret through `X25519Crypto.keyExchangeOrNull`, which turns the Bouncy Castle
refusal into null. No change there. `X25519Crypto`'s comment says the old explicit `isAllZero`
checks were removed on purpose as unreachable, so they were not put back.

The new tests feed seven low-order u-coordinates (0, 1, the two order-8 points, p-1, p, p+1)
into `decap` and `encap` and expect `LowOrderPointException`, check that `HybridIdentity.unwrap`
returns null for such a stanza, that encap/decap still round-trip, and that `isAllZero` looks
at every byte.

## How the runner works

One JUnit 5 test, `CCTVTestkitTest.cctvVectors`, mirrors the iOS runner:

1. Lists `cctv-testkit/` on the test classpath (anchored on `SOURCE.md`), skips the three .md
   files, parses each vector's header (`expect`, `payload`, `identity`, `passphrase`, `armored`,
   `compressed`, `file key`, `comment`). An unknown key skips the vector, and an unexpected skip
   fails the test.
2. Builds identities: `X25519Identity(String)` for `AGE-SECRET-KEY-1`, `HybridIdentity(String)`
   for `AGE-SECRET-KEY-PQ-1`, `ScryptIdentity(passphrase)` with the default cap (22). The two
   vectors with no key (`empty`, `armor_empty`) get an identity that never matches, because
   `Age.decryptStream` requires a non-empty list.
3. Inflates `compressed: zlib` bodies with `InflaterInputStream` (zlib header and Adler-32
   checked), runs `Armor.decode` for armored ones, then `Age.decryptStream` into a
   `ByteArrayOutputStream`. Whatever reached the stream before a failure is the released
   plaintext, and its SHA-256 is compared with `payload` for `success` and `payload failure`.
4. Maps exceptions to CCTV results: `Armor.ArmorException` to armor failure;
   `AgeHeader.HeaderException` to HMAC failure when the message is "MAC verification failed",
   header failure otherwise; `AgePayload.PayloadException` "payload too short" (the nonce) to
   header failure, any other to payload failure; `Age.NoMatchingIdentityException` to no match;
   anything else to "unexpected error", which never matches.
5. Accepts "no match" for an expected "header failure" when the header parsed and one of its
   stanza types is handled by the vector's identities (an identity returns null for a malformed
   stanza of its own type where Go fails the header). About 31 vectors pass this way and are
   listed in the output.
6. `KNOWN_DIVERGENCES` waives one exact outcome per listed vector, each with a one-line reason.
   A listed vector that starts passing, or fails in a different way, fails the test.

Output: every vector's line (name, expected, got, verdict) is printed to stdout and written to
`agepony-core/build/reports/cctv-testkit/results.txt`. The assertion message lists each failure
as name, expected, got. That file is enough to settle the divergence list after the first run.

## Divergence list (needs confirming on the first run)

14 entries, the iOS list minus one:

Armor whitespace (gives success, CCTV expects armor failure; `Armor` trims whitespace around each
line on purpose): `armor_cr_line_start`, `armor_double_crlf`, `armor_whitespace_eol`,
`armor_whitespace_last_line`, `armor_whitespace_line_start`.

Blank line before END (gives success; accepted on purpose as age 1.1.1 does, see
`StrictFormatTests.armorWithAFullFinalLineOpensHereAndInGo`): `armor_empty_last_line`.

Stream read-ahead (payload failure as expected, shorter released plaintext than Go):
`armor_garbage_encoded`, `stream_no_final_full`, `stream_no_final_two_chunks_full`,
`stream_trailing_garbage_long`, `stream_trailing_garbage_short`, `stream_two_final_chunks`,
`stream_two_final_chunks_full`, `stream_two_final_chunks_second`.

Left out compared with iOS: `stream_short_second_chunk` (a full chunk followed by 12 bytes).
iOS reads the whole next chunk first and never releases the first one. The Android reader only
peeks one byte, releases the first chunk, then fails on the short one, as Go does. A Python model
of the Android decrypt path (armor, header, X25519, scrypt, payload) reproduced the CCTV hash for
it and predicted exactly the 14 entries above for every non-hybrid vector. The hybrid vectors
were not modeled (no ML-KEM in the model); by reading the code they should pass, with
`hybrid_identity` and `hybrid_low_order` going through the no match alias.

If the first run disagrees, the results file shows which entries to add or remove.
