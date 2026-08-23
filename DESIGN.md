# Design

## SHA-256

`src/sha256.rs` implements SHA-256 as specified in FIPS 180-4. The message is padded with a single `0x80` byte, zero bytes up to a length congruent to 56 mod 64, and a 64-bit big-endian bit length. Each 64-byte block is expanded into a 64-word message schedule using the small sigma functions, then run through 64 rounds of the compression function using the eight round constants `K` and the eight initial hash values `H0`, both defined directly from the spec, no derivation tricks. The eight working variables `a` through `h` are updated round by round with wrapping arithmetic, and the block's output is added into the running hash state. The final state, big-endian encoded, is the 32-byte digest.

## HMAC-SHA256

`src/hmac.rs` implements HMAC as specified in RFC 2104, keyed with SHA-256. A key longer than the 64-byte block size is first hashed down to 32 bytes; a shorter key is zero-padded up to 64 bytes. The key block is XORed with the inner pad `0x36` and the outer pad `0x5c` to produce `ipad` and `opad`. The tag is `SHA256(opad || SHA256(ipad || message))`.

Comparison of two tags never uses an early-exit byte compare. `constant_time_eq` ORs the XOR of every byte pair into a single accumulator and only checks that accumulator against zero at the end, so the number of iterations does not depend on where two tags first differ. A length mismatch is checked separately since comparing different lengths is not a secret-dependent branch.

## Token layout

A token is `base64url(header) + "." + base64url(payload) + "." + base64url(signature)`.

- `header` is the fixed JSON `{"alg":"HS256","typ":"JWT"}`.
- `payload` is `{"sub":"...","iat":N,"exp":N}`, hand-encoded and hand-decoded by a small parser in `src/token.rs` that understands exactly this shape. It is not a general JSON library.
- `signature` is `HMAC-SHA256(header_b64 + "." + payload_b64, secret)`.

`base64url` (`src/base64url.rs`) is RFC 4648 section 5 without padding, encode and decode both written from the bit-packing up.

### Issuing

`token::issue` builds the header and payload, base64url-encodes both, signs the joined string with the caller's secret, and appends the base64url-encoded signature.

### Verifying

`token::verify`:

1. Rejects tokens over `MAX_TOKEN_LEN` bytes before doing any parsing work.
2. Splits on `.` and requires exactly three segments.
3. Decodes the header and requires it to match the fixed `{"alg":"HS256","typ":"JWT"}` exactly, so a token naming a different algorithm is rejected up front.
4. Recomputes the HMAC over the received header and payload segments using the caller's secret.
5. Compares the recomputed tag against the received signature with `constant_time_eq`. Any mismatch, whether from a tampered payload or a wrong secret, is reported as the same `BadSignature` error, so a caller cannot distinguish the two from the error alone.
6. Only after the signature checks out does it decode and parse the payload, then check `now >= exp` for expiry.

Every step returns a typed `GatekeeperError` variant. There is no `unwrap`, `expect`, or indexing panic reachable from attacker-controlled input in this path; malformed base64, a malformed JSON shape, a wrong number of segments, and an oversized token are all distinct, non-panicking error returns.

## Password hashing

`src/password.rs` implements a stretch-and-compare scheme, labeled `gkdf-hmac-sha256` in its own output so it is unambiguous which construction produced a given hash string.

- A random 16-byte salt is drawn from `/dev/urandom` (falling back, only if that is unavailable, to a non-cryptographic mix of the system clock, purely to keep the function total rather than panicking).
- `stretch(password, salt, rounds)` seeds the loop with `HMAC-SHA256(key=password, message=salt)`, then for `rounds - 1` further iterations feeds the previous round's output back in as the new message, still keyed by the password. The default is 100,000 rounds.
- The stored hash string is `gkdf-hmac-sha256$rounds$salt_b64$hash_b64`, all four fields self-describing so `check` does not need external configuration to know how a given hash was produced.
- `check` re-derives the stretch with the embedded salt and round count and compares against the stored digest with the same constant-time comparison used for tokens.

This is explicitly not a memory-hard KDF. It has no defense against a parallel GPU or ASIC attacker beyond the round count, which is exactly the property Argon2's memory-hardness exists to fix. It is included to make the "salt, stretch, compare" idea concrete and readable, not to be a production password hash.

## Bounded input

Every entry point checks a size ceiling before doing hashing work:

- `MAX_TOKEN_LEN` (8 KiB) on the full encoded token string.
- `MAX_SUBJECT_LEN` (512 bytes) on the subject claim, checked both at issue time and after decoding at verify time.
- `MAX_SECRET_LEN` (4 KiB) on the signing secret.
- `MAX_PASSWORD_LEN` (1024 bytes) on passwords passed to `hash` and `check`.

These exist so that a caller cannot force unbounded work or unbounded allocation by handing the library an oversized token or password.

By Pavan Nallamothu.
