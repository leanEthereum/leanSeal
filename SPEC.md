# chainseal v1 specification

chainseal is a time-lock encryption scheme built only from SHA-256. A sender encrypts a message so that anyone can decrypt it after doing a fixed amount of sequential hashing, and the sender can also reveal the key early. The construction is the chained-hash time-lock puzzle of Mahmoody, Moran and Vadhan (CRYPTO 2011, section 3.1), with each random-oracle call replaced by a long SHA-256 chain, as proposed by Vitalik Buterin.

This document is normative. The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Sections marked *informative* are not part of the format.

## 1. Notation

- All integers are unsigned and encoded big-endian. `u8(x)`, `be32(x)` and `be64(x)` are the 1-, 4- and 8-byte encodings of `x`.
- `a ‖ b` is byte-string concatenation. `x[i:j]` is bytes `i` up to but not including `j`.
- `⊕` is bytewise XOR of equal-length strings.
- `SHA256(x)` is SHA-256 (FIPS 180-4). `HMAC(k, x)` is HMAC-SHA256 (RFC 2104) with key `k` and message `x`.
- `TH(label, x) = SHA256(u8(len(label)) ‖ label ‖ x)` is a labelled hash. `label` is an ASCII string of at most 255 bytes. The length prefix makes the set of labels prefix-free.

Labels used in v1:

| Label | Used for |
|---|---|
| `chainseal/v1/start` | chain start values |
| `chainseal/v1/key` | the session key |
| `chainseal/v1/commit` | the key commitment |
| `chainseal/v1/enc` | the encryption subkey |
| `chainseal/v1/mac` | the authentication subkey |
| `chainseal/v1/puzzle-id` | puzzle identifiers in checkpoints |

## 2. Parameters

| Name | Meaning | Allowed range |
|---|---|---|
| `n` | number of chains | 1 ≤ n ≤ 2^20 |
| `m` | hash steps per chain | 1 ≤ m ≤ 2^48 |
| `b` | link width in bytes | 1 ≤ b ≤ 32 |
| `salt` | 16 random bytes | |

The total sequential work to open a puzzle is `n·m` chain steps (plus `n` start hashes and two final hashes).

## 3. The chain step

For chain index `i` (1 ≤ i ≤ n), the step function maps a 32-byte state `s` to

    F_i(s) = SHA256(s ‖ salt ‖ be32(i))

The input is exactly 52 bytes, so it is one SHA-256 compression of one padded block:

| Message words (32-bit, big-endian) | Content |
|---|---|
| W0–W7 | the state `s` |
| W8–W11 | `salt` |
| W12 | `i` |
| W13 | `0x80000000` (padding) |
| W14 | `0x00000000` |
| W15 | `0x000001A0` (message length, 416 bits) |

`F_i^m` denotes `m` applications of `F_i`.

*Informative.* W8–W15 are constant for a whole chain, exactly as the padding words of `SHA256(s)` would be, so adding the salt and index costs nothing. It makes every step specific to one chain of one puzzle, which rules out reusing precomputed chain segments.

## 4. Puzzle generation

Inputs: parameters `n`, `m`, `b`. The generator MUST draw `salt` and the links `x_1, …, x_n` (each `b` bytes) from a cryptographically secure random number generator.

1. Let `ctx = u8(1) ‖ u8(b) ‖ 0x0000 ‖ be32(n) ‖ be64(m) ‖ salt`, 32 bytes. These are bytes `[4:36)` of the puzzle encoding (section 6.1): version, `b`, reserved, `n`, `m`, `salt`.
2. For each `i` in 1..n, independently:

       s_i = TH("chainseal/v1/start", salt ‖ be32(i) ‖ x_i)
       y_i = F_i^m(s_i)

3. For each `i` in 1..n−1, hide the next link: `z_i = y_i[0:b] ⊕ x_{i+1}`.
4. Derive the session key and its commitment:

       K = TH("chainseal/v1/key", ctx ‖ y_n)
       C = TH("chainseal/v1/commit", ctx ‖ K)

5. The puzzle is the header with commitment `C`, followed by the links `x_1 ‖ z_1 ‖ … ‖ z_{n−1}` (section 6.1).

Step 2 is where the generator spends its time. The `n` chains are independent and SHOULD be computed in parallel.

## 5. Solving

Given a valid puzzle:

1. Read `ctx`, `x_1` and `z_1, …, z_{n−1}`. Set `x ← x_1`.
2. For `i` = 1, …, n: compute `y_i = F_i^m(TH("chainseal/v1/start", salt ‖ be32(i) ‖ x))`. If `i < n`, set `x ← y_i[0:b] ⊕ z_i`.
3. Compute `K = TH("chainseal/v1/key", ctx ‖ y_n)`.
4. Accept `K` only if `TH("chainseal/v1/commit", ctx ‖ K) = C`. Otherwise the puzzle is malformed and MUST be reported as such.

Chain `i + 1` cannot start before chain `i` ends, because its start link is hidden under the end of chain `i`.

A *revealed* key `K'` (the fast path) is checked the same way: accept it only if `TH("chainseal/v1/commit", ctx ‖ K') = C`.

## 6. Encodings

Every encoding starts with a 4-byte magic and a version byte equal to `0x01`. Reserved bytes MUST be zero. A decoder MUST reject any input whose magic, version or reserved bytes are wrong, whose parameters are out of range, or whose length differs from the length the fields imply. Trailing bytes are an error.

### 6.1 Puzzle

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"CSPZ"` |
| 4 | 1 | version `0x01` |
| 5 | 1 | `b` |
| 6 | 2 | reserved |
| 8 | 4 | `n` |
| 12 | 8 | `m` |
| 20 | 16 | `salt` |
| 36 | 32 | commitment `C` |
| 68 | n·b | `x_1`, then `z_1, …, z_{n−1}` |

Total length: `68 + n·b` bytes. `ctx` is bytes `[4:36)`.

### 6.2 Envelope (an encrypted message)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"CSEN"` |
| 4 | 1 | version `0x01` |
| 5 | 3 | reserved |
| 8 | 68 + n·b | puzzle (section 6.1) |
| p | 16 | `nonce` |
| p + 16 | 4 | `L`, the ciphertext length, 0 ≤ L ≤ 2^24 |
| p + 20 | L | ciphertext |
| p + 20 + L | 32 | `tag` |

Here `p = 76 + n·b`. Total length: `128 + n·b + L` bytes.

### 6.3 Secret (a puzzle built in advance, with its key)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"CSSK"` |
| 4 | 1 | version `0x01` |
| 5 | 3 | reserved |
| 8 | 32 | `K` |
| 40 | 68 + n·b | puzzle |

A decoder MUST check that `K` matches the puzzle's commitment.

### 6.4 Checkpoint (partial progress of a solve)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"CSCK"` |
| 4 | 1 | version `0x01` |
| 5 | 3 | reserved |
| 8 | 32 | puzzle id: `TH("chainseal/v1/puzzle-id", puzzle)` |
| 40 | 4 | `i`, the current chain, 1 ≤ i ≤ n |
| 44 | 8 | `j`, steps of chain `i` already done, 0 ≤ j ≤ m |
| 52 | 32 | state `F_i^j(s_i)` |

Total length: 84 bytes. A solver resuming from a checkpoint MUST check the puzzle id.

## 7. Encryption

Encryption uses only SHA-256, as an encrypt-then-MAC composition of a keyed-hash stream cipher and HMAC.

To encrypt a message `M` (0 ≤ len(M) ≤ 2^24) under a puzzle with key `K`:

1. Draw a fresh 16-byte `nonce` from a cryptographically secure random number generator.
2. Derive subkeys:

       k_enc = TH("chainseal/v1/enc", K ‖ nonce)
       k_mac = TH("chainseal/v1/mac", K ‖ nonce)

3. Keystream block `j`, for `j` = 0, 1, 2, …, is `HMAC(k_enc, be64(j))`. The ciphertext is `M ⊕` the first `len(M)` bytes of the concatenated keystream blocks.
4. Write the envelope (section 6.2) up to and including the ciphertext. The tag is `HMAC(k_mac, E)`, where `E` is every envelope byte before the tag. It covers the magic, the whole puzzle, the nonce, the length and the ciphertext.

To decrypt, given a key `K` already accepted against the commitment (section 5), recompute `k_enc` and `k_mac`, recompute the tag and compare it in constant time. If the tags differ, the decoder MUST reject the envelope and MUST NOT output any plaintext. Otherwise it recomputes the keystream and outputs `M`.

A key MAY encrypt several messages, each with its own nonce. All of them open together once the key is known.

## 8. Security considerations

*Informative.*

- **What the delay rests on.** Nobody computes `m` chained steps much faster than `m·ℓ`, where `ℓ` is the fastest attainable latency of one SHA-256 compression. This covers both the absence of shortcuts for iterating SHA-256 and the circuit speed of the best hardware. In the random-oracle model, Mahmoody, Moran and Vadhan show the construction needs `n·m` sequential rounds, and that no hash-only puzzle can provably need more rounds than its generator makes queries.
- **Guessing the last link.** An attacker can skip to the last chain by guessing `x_n`: each guess costs `m` steps and succeeds with probability `2^(−8b)`. Against a fleet computing `R` chain steps per second in parallel, the chance of opening one puzzle within delay `T` is at most `R·T / (m·2^(8b))`. Use `b = 12` unless a smaller value is justified by this bound. Against `R = 10^21`, `T = 60 s` and `m = 2^25`, a failure chance of `2^(−32)` per puzzle needs `b ≥ 11`.
- **The delay starts at publication.** Anyone holding a puzzle can start solving it. A puzzle built in advance (a secret file) MUST be kept private until its first envelope is published. From then on the clock runs for every envelope under that puzzle: a message encrypted later under the same puzzle opens at the same time as the first, not one full delay after its own publication. Encrypt together all messages that should open together, then discard the secret.
- **Malformed puzzles.** Nothing in v1 lets a verifier check, before solving, that a puzzle leads to its commitment. A malformed puzzle is detected only when the solve ends with a commitment mismatch.
- **What the tag protects.** The tag stops anyone who does not know `K` from changing an envelope. Anyone who knows `K`, because it was revealed or solved, can seal a new message under the same puzzle, with a valid tag. A puzzle or its commitment therefore does not identify a message. A system that orders or references envelopes MUST bind to the whole envelope, for example by its SHA-256 hash.
- **Binding.** The 32-byte commitment and the full 32-byte HMAC tag bind the key and the ciphertext under the collision resistance of SHA-256. Shorter values would not: a 16-byte commitment can be collided with about 2^64 hashes.
- **Key reuse.** Reusing `K` with distinct nonces is safe for confidentiality and integrity. Reusing a nonce under the same key reveals the XOR of the two plaintexts.
- **Not provided.** Side-channel hardening beyond constant-time tag and commitment comparison; proofs of well-formedness; anything about how a network schedules, pays for or prioritises solving.

## 9. Choosing parameters (informative)

For a target delay `T` against an attacker with per-step latency `ℓ`, choose `n` to match the sender's parallelism and set `m = ⌈T / (n·ℓ)⌉`. The puzzle is `68 + n·b` bytes, and an envelope adds `60` bytes plus the message. Building takes about `n·m / R_sender` seconds once `n` covers all the sender's parallel lanes. An honest solver takes `n·m·ℓ_solver`.

## 10. Test vectors (informative)

`tests/vectors.json` holds deterministic vectors produced by the reference C implementation. It has two lists.

`cases`: valid puzzles. Each entry gives the parameters `n`, `m`, `b`, the random inputs `salt`, `x` (the links `x_1..x_n`), `nonce` and `message`, and the values an implementation must reproduce from them: `start` (the `s_i`), `y` (the `y_i`), `key`, `commit`, `puzzle` (section 6.1), `puzzle_id`, `secret` (section 6.3) and `envelope` (section 6.2, sealed with the given nonce). `checkpoint` gives a position `i`, `j`, the state `F_i^j(s_i)` at that position, and its encoding (section 6.4). All byte strings are lowercase hex.

`invalid`: inputs that MUST be rejected. Each entry has a `kind`, the index `case` of the valid case it was derived from, a short `why`, and `hex`:

| `kind` | An implementation MUST |
|---|---|
| `puzzle` | fail to decode it as a puzzle |
| `envelope` | fail to decode it, or fail to open it with that case's `key` |
| `secret` | fail to decode it as a secret, including the key check |
| `checkpoint` | fail to decode it as a checkpoint for that case's puzzle |

