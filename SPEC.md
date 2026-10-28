# leanSeal v1 specification

leanSeal is a time-lock encryption scheme built only from SHA-256. A sender encrypts a message so that anyone can decrypt it after doing a fixed amount of sequential hashing, and the sender can also reveal the key early. The construction is the chained-hash time-lock puzzle of Mahmoody, Moran and Vadhan (CRYPTO 2011, section 3.1, the variant in which each link is a hash iterated many times), instantiated with SHA-256 for encrypted mempools as Vitalik Buterin proposed.

This document is normative. The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Sections marked *informative* are not part of the format.

## 1. Notation

- All integers are unsigned and encoded big-endian. `u8(x)`, `be32(x)` and `be64(x)` are the 1-, 4- and 8-byte encodings of `x`.
- `a ‖ b` is byte-string concatenation. `x[i:j]` is bytes `i` up to but not including `j`.
- `⊕` is bytewise XOR of equal-length strings.
- `SHA256(x)` is SHA-256 (FIPS 180-4). `HMAC(k, x)` is HMAC-SHA256 (RFC 2104) with key `k` and message `x`.
- `TH(label, x) = SHA256(u8(len(label)) ‖ label ‖ x)` is a labelled hash. `label` is an ASCII string of at most 255 bytes. The length prefix makes the set of labels prefix-free.
- `N = n·m` is the total number of chain steps, and `P = n·(m + 3) + 1` bounds the number of 32-byte values on the honest path (section 8). The parameters `n` and `m` are defined in section 2.

Labels used in v1:

| Label | Used for |
|---|---|
| `leanseal/v1/start` | chain start values |
| `leanseal/v1/mask` | the masks that hide links |
| `leanseal/v1/acc` | the hash of the chain ends |
| `leanseal/v1/key` | the session key |
| `leanseal/v1/commit` | the key commitment |
| `leanseal/v1/enc` | the encryption subkey |
| `leanseal/v1/mac` | the authentication subkey |
| `leanseal/v1/puzzle-id` | puzzle identifiers in checkpoints |

## 2. Parameters

| Name | Meaning | Allowed range |
|---|---|---|
| `n` | number of chains | 1 ≤ n ≤ 2^20 |
| `m` | hash steps per chain | 1 ≤ m ≤ 2^48 |
| `b` | link width in bytes | 1 ≤ b ≤ 32 |
| `salt` | 16 random bytes | |

In addition, `n·m ≤ 2^60`, so that every step count fits in 64 bits.

An honest solver does `N = n·m` chain steps in sequence, plus `n` start hashes, `n − 1` mask hashes, `n` hashes of the chain ends and two final hashes. Section 8 discusses what this does and does not guarantee.

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

*Informative.* W8–W15 are constant for a whole chain, exactly as the padding words of `SHA256(s)` would be, so adding the salt and index costs nothing. It makes every step specific to one chain index under one salt. Since every puzzle draws a fresh random salt, chain segments computed for one puzzle are of no use for another, except with negligible probability. Nothing stops an attacker from precomputing on a puzzle after it is published; that is just solving it.

*Informative.* The chain step hashes exactly 52 bytes. Every other SHA-256 input in this format is longer: the labelled hashes hash at least 55 bytes (the start hash with `b = 1`: 1 + 17 + 32 + 4 + 1), and the hashes inside HMAC hash at least 72. So the input of a chain step is never also the input of another hash in this format.

## 4. Puzzle generation

Inputs: parameters `n`, `m`, `b`. The generator MUST draw `salt` and the links `x_1, …, x_n` (each `b` bytes) from a cryptographically secure random number generator.

1. Let `ctx = u8(1) ‖ u8(b) ‖ 0x0000 ‖ be32(n) ‖ be64(m) ‖ salt`, 32 bytes. These are bytes `[4:36)` of the puzzle encoding (section 6.1): version, `b`, reserved, `n`, `m`, `salt`.
2. For each `i` in 1..n, independently:

       s_i = TH("leanseal/v1/start", ctx ‖ be32(i) ‖ x_i)
       y_i = F_i^m(s_i)

3. For each `i` in 1..n−1, hide the next link under a mask derived from the end of chain `i`:

       z_i = TH("leanseal/v1/mask", ctx ‖ y_i)[0:b] ⊕ x_{i+1}

4. Hash the chain ends in order, starting from `a_0 = ctx`:

       a_i = TH("leanseal/v1/acc", a_{i−1} ‖ y_i)    for i = 1, …, n

5. Derive the session key and its commitment:

       K = TH("leanseal/v1/key", ctx ‖ a_n)
       C = TH("leanseal/v1/commit", ctx ‖ K)

6. The puzzle is the header with commitment `C`, followed by the links `x_1 ‖ z_1 ‖ … ‖ z_{n−1}` (section 6.1).

Step 2 is where the generator spends its time. The `n` chains are independent and SHOULD be computed in parallel. Step 4 is `n` more hashes, done in sequence once all chains have ended.

*Informative.* The key depends on the end of every chain, not only the last. A solver who guesses a hidden link and runs the remaining chains from it still needs the ends of all earlier chains, so a right guess saves time but does not by itself open the puzzle (section 8). The mask is a hash of the end rather than the end itself, so that a guess of `x_{i+1}`, which fixes the mask's first `b` bytes, says nothing about `y_i`; with a raw mask and `b = 32`, a right guess would give away all of `y_i`. Hashing the ends one at a time keeps the state a solver carries between chains to 32 bytes.

## 5. Solving

Given a valid puzzle:

1. Read `ctx`, `x_1` and `z_1, …, z_{n−1}`. Set `x ← x_1` and `a ← ctx`.
2. For `i` = 1, …, n: compute `y_i = F_i^m(TH("leanseal/v1/start", ctx ‖ be32(i) ‖ x))` and set `a ← TH("leanseal/v1/acc", a ‖ y_i)`. If `i < n`, set `x ← TH("leanseal/v1/mask", ctx ‖ y_i)[0:b] ⊕ z_i`.
3. Compute `K = TH("leanseal/v1/key", ctx ‖ a)`.
4. Accept `K` only if `TH("leanseal/v1/commit", ctx ‖ K) = C`. Otherwise the puzzle is malformed and MUST be reported as such.

A solver that follows these steps cannot start chain `i + 1` before chain `i` ends, because its start link is hidden under the end of chain `i`. A solver can try to skip ahead by guessing a link instead; section 8 discusses this.

A *revealed* key `K'` (the fast path) is checked the same way: accept it only if `TH("leanseal/v1/commit", ctx ‖ K') = C`.

## 6. Encodings

Every encoding starts with a 4-byte magic and a version byte equal to `0x01`. Reserved bytes MUST be zero. A decoder MUST reject any input whose magic, version or reserved bytes are wrong, whose parameters are out of range, or whose length differs from the length the fields imply. Trailing bytes are an error.

### 6.1 Puzzle

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"LSPZ"` |
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
| 0 | 4 | magic `"LSEN"` |
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
| 0 | 4 | magic `"LSSK"` |
| 4 | 1 | version `0x01` |
| 5 | 3 | reserved |
| 8 | 32 | `K` |
| 40 | 68 + n·b | puzzle |

A decoder MUST check that `K` matches the puzzle's commitment.

### 6.4 Checkpoint (partial progress of a solve)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"LSCK"` |
| 4 | 1 | version `0x01` |
| 5 | 3 | reserved |
| 8 | 32 | puzzle id: `TH("leanseal/v1/puzzle-id", puzzle)` |
| 40 | 4 | `i`, the current chain, 1 ≤ i ≤ n |
| 44 | 8 | `j`, steps of chain `i` already done, 0 ≤ j ≤ m |
| 52 | 32 | state `F_i^j(s_i)` |
| 84 | 32 | `a_{i−1}`, the hash of the ends of chains 1 to i−1 (`ctx` when i = 1) |

Total length: 116 bytes. A solver resuming from a checkpoint MUST check the puzzle id. Nothing authenticates the state or `a_{i−1}`; a damaged checkpoint leads to a key that fails the commitment check of section 5.

## 7. Encryption

Encryption uses only SHA-256, as an encrypt-then-MAC composition of a keyed-hash stream cipher and HMAC.

To encrypt a message `M` (0 ≤ len(M) ≤ 2^24) under a puzzle with key `K`:

1. Draw a fresh 16-byte `nonce` from a cryptographically secure random number generator.
2. Derive subkeys:

       k_enc = TH("leanseal/v1/enc", K ‖ nonce)
       k_mac = TH("leanseal/v1/mac", K ‖ nonce)

3. Keystream block `j`, for `j` = 0, 1, 2, …, is `HMAC(k_enc, be64(j))`. The ciphertext is `M ⊕` the first `len(M)` bytes of the concatenated keystream blocks.
4. Write the envelope (section 6.2) up to and including the ciphertext. The tag is `HMAC(k_mac, E)`, where `E` is every envelope byte before the tag. It covers the magic, the whole puzzle, the nonce, the length and the ciphertext.

To decrypt, given a key `K` already accepted against the commitment (section 5), recompute `k_enc` and `k_mac`, recompute the tag and compare it in constant time. If the tags differ, the decoder MUST reject the envelope and MUST NOT output any plaintext. Otherwise it recomputes the keystream and outputs `M`.

A key MAY encrypt several messages, each with its own nonce. All of them open together once the key is known.

## 8. Security considerations

*Informative.*

- **What the delay rests on.** The delay rests on two assumptions about attackers. In the random-oracle model, the theorem below shows that a classical attacker who makes `Q` queries in total derives the key even one round before the honest solver only with negligible probability; this needs no assumption beyond modelling SHA-256 and its compression function as random oracles. Turning rounds into seconds assumes that nobody computes one chain step faster than `ℓ`, the fastest attainable latency of one SHA-256 compression, and that the attacker's total hash rate is bounded. Mahmoody, Moran and Vadhan prove asymptotically that their construction needs about `n·m` sequential rounds, and that no hash-only puzzle can provably need more rounds than its generator makes queries. leanSeal keeps their dependency structure. There is no analysis of leanSeal's encoding against quantum attackers.
- **The delay theorem.** The statement below is proved in the random-oracle model, against classical attackers, and covers every saving, however small. Model each step function `F_i` and each labelled hash as an independent random oracle (the input lengths and labels of sections 1 and 3 keep their domains apart). The attacker is a classical randomized algorithm `A = (A_0, A_1)`: `A_0` runs before the puzzle exists and makes `Q_pre` queries; its whole state passes to `A_1`, which receives the puzzle and makes `Q_on` queries; `Q = Q_pre + Q_on`. After publication, time is counted in oracle rounds: all queries in a round are chosen before any answer from that round arrives. The solver of section 5, computing each chain's mask and accumulator hashes in the same round, derives `K` in round `T_key = n·(m + 2) + 1` and returns it, checked against `C`, one round later. A generator needs `m + n + 3` rounds. Call the 32-byte values the solver computes (each chain's start value, its `m` states, its mask and its accumulator value, `K` and `C`) the path values; there are `P = n·(m + 3) + 1` of them.

  *Theorem.* Let the puzzle and `K` be generated as in section 4, with randomness independent of the oracles. Then `A_1` outputs `K` within fewer than `T_key` oracle rounds with probability at most `Q_on / 2^(8b) + Q_pre / 2^(128+8b) + (Q·P + P² + 1) / 2^256`. For `n = 1` the first term is absent.

  *Proof.* Each path value `v` is the oracle's answer on one path input `u(v)`; its predecessors are the path values in `u(v)`, and the mask of chain `i − 1` is also a predecessor of the start of chain `i`. Let `ρ(v)` be the round in which the solver receives `v`; then `ρ(v) = 1 + max ρ(w)` over predecessors `w`, and `ρ(K) = T_key`.

  Compare the real experiment with an ideal one, `G`. `G` uses the same lazily sampled oracles, but the generator makes no queries: it draws `salt` and `x_1`, and draws `z_1, …, z_(n−1)` and `C` uniformly. A query of `A_1` is legitimate if, when submitted, it equals `u(v)` for a path value `v` whose predecessors are all revealed (for the start of chain `i ≥ 2`, this defines `x_i = z_(i−1) ⊕` the first `b` bytes of the mask of chain `i − 1`). `G` answers a legitimate query with `v`, drawing `v` uniformly the first time, and marks `v` revealed; it answers every other query, and every query of `A_0`, from the lazily sampled oracles. When `A_1` stops, `G` draws the path values never revealed.

  (1) In `G`, no path value `v` is revealed before round `ρ(v)`: by induction, since a legitimate query is submitted after its predecessors are revealed and answers arrive at the end of a round. (2) Let Bad be the event, in `G`, that two path values are equal, or that a query that is not legitimate equals a path input evaluated with the path values as finally drawn. Running both experiments on the same randomness, with the real oracle's answers on path inputs taken to be `G`'s path values, the transcripts agree unless Bad happens: without a collision the path inputs are distinct, so these answers are independent and uniform; `z_i` is uniform because `x_(i+1)` is; and every query is either legitimate, answered with the path value in both, or not a path input, answered alike in both. (3) In `G`, a path value not revealed when a query is submitted is drawn later, independently of the query; so is `x_i` for `i ≥ 2` while the mask of chain `i − 1` is not revealed, and so are `salt` and `x_1` for every query of `A_0`. No probability is conditioned on the transcript. Two of at most `P` path values are equal with probability at most `P² / 2^256`. A start query names one index `i`: from `A_1` with `i = 1` it is legitimate whenever it equals `u(s_1)`; from `A_1` with `i ≥ 2` and not legitimate it contains `x_i` with probability `2^(−8b)`; from `A_0` it must also contain `salt`, probability `2^(−(128+8b))`. Any other query that is not legitimate but equals `u(v)` contains, in a 32-byte field, a predecessor of `v` not yet revealed, probability at most `2^(−256)` for each of at most `P` path inputs. So `Pr[Bad] ≤ Q_on / 2^(8b) + Q_pre / 2^(128+8b) + (Q·P + P²) / 2^256`. (4) In `G`, if `A_1` stops before round `T_key`, then `K` is not revealed, by (1), so it is drawn after `A_1`'s output, which equals it with probability `2^(−256)`; `C` was drawn independently of `K`. Adding `Pr[Bad]` gives the theorem. The argument follows the structure of Lemmas 6 and 9 of Pietrzak and Reyzin, "Optimal Proofs of Sequential Work" (ePrint 2026/2569). It is written out here, not machine-checked.

  The threshold is the round in which `K` is derived: an attacker that skips the check against `C` finishes one round before the solver returns, with certainty. The precomputation term is needed even when `n = 1`: an attacker that guesses `salt` and `x_1` in advance and computes the key opens the puzzle in zero rounds with probability `2^(−(128+8b))`. The theorem counts rounds; turning rounds into seconds is the latency assumption of the first bullet. The theorem is about the key. The encryption of section 7 is intended to hide equal-length message contents under the random-oracle model and the assumption that HMAC-SHA256 is a pseudorandom function; a reduction from distinguishing envelopes to the events above, which must also count queries on the `enc` and `mac` key derivations, has not been written. With `b = 32`, a fleet making `R = 10^21` queries per second for the `T` seconds a puzzle takes (`Q_on = R·T`), `ℓ = 3.5 ns` and `P ≈ N = T / ℓ`, the bound is about `2^(−148)` for `T = 30` s, `2^(−134)` for an hour and `2^(−108)` for a year.
- **Shorter links.** The first term of the theorem, `Q / 2^(8b)`, is the chance of guessing a link, and it is the only place where the link width enters. Use `b = 24` or more. With `b = 24` the bound above is about `2^(−117)` for 30 seconds and `2^(−97)` for a year. With `b = 32` the first term falls below the others, giving about `2^(−148)` and `2^(−108)` for 8 more bytes per chain. With `b = 16` it is about `2^(−53)` and `2^(−33)`, too weak for long delays. This document relies only on the theorem. A sharper bound for short links, which would charge each guess for the work it saves, is not proved and is not relied on here. With `n = 1` the only link is public, so a one-chain puzzle relies on the chain alone.
- **The delay starts at publication.** Anyone holding a puzzle can start solving it. A puzzle built in advance (a secret file) MUST be kept private until its first envelope is published. From then on the clock runs for every envelope under that puzzle: a message encrypted later under the same puzzle opens at the same time as the first, not one full delay after its own publication. Encrypt together all messages that should open together, then discard the secret.
- **Malformed puzzles.** Nothing in v1 lets a verifier check, before solving, that a puzzle leads to its commitment. A malformed puzzle is detected only when the solve ends with a commitment mismatch.
- **What the tag protects.** The tag stops anyone who does not know `K` from changing an envelope. Anyone who knows `K`, because it was revealed or solved, can seal a new message under the same puzzle, with a valid tag. A puzzle or its commitment therefore does not identify a message. A system that orders or references envelopes MUST bind to the whole envelope, for example by its SHA-256 hash.
- **Assumptions behind the encryption.** Confidentiality of the message and unforgeability of the tag, for anyone who does not know `K`, assume that HMAC-SHA256 is a pseudorandom function. That a commitment fixes one key, and that one envelope opens to one message, assume that SHA-256 is collision resistant. Full 32-byte values are used for both; a 16-byte commitment could be collided with about 2^64 hashes.
- **Key reuse.** Under the assumptions above, reusing `K` with distinct nonces keeps confidentiality and integrity. Reusing a nonce under the same key reveals the XOR of the two plaintexts.
- **Not provided.** Side-channel hardening beyond constant-time tag and commitment comparison; proofs of well-formedness; anything about how a network schedules, pays for or prioritises solving.

## 9. Choosing parameters (informative)

For a target delay `T` against an attacker with per-step latency `ℓ`, the total work is `N = T / ℓ` chain steps, whatever `n` is. Choose `n` at least the number of chains the sender runs at once, so that one puzzle can use all of the sender's hardware, and set `m = ⌈T / (n·ℓ)⌉`. The puzzle is `68 + n·b` bytes, 452 bytes for `n = 16` and `b = 24`, and an envelope adds `60` bytes plus the message. Building takes about `n·m / R_sender` seconds, where `R_sender` is the sender's total rate, and never less than `m` steps of one chain. An honest solver takes `n·m·ℓ_solver`. The reference parameters `n = 16`, `m = 2^29`, `b = 24` give a 30-second delay at `ℓ = 3.5 ns`.

## 10. Test vectors (informative)

`tests/vectors.json` holds deterministic vectors. `leanseal vectors` regenerates them byte for byte, and the Python reference checks them. It has two lists.

`cases`: valid puzzles. Each entry gives the parameters `n`, `m`, `b`, the random inputs `salt`, `x` (the links `x_1..x_n`), `nonce` and `message`, and the values an implementation must reproduce from them: `start` (the `s_i`), `y` (the `y_i`), `acc` (the `a_i` for i = 1..n), `key`, `commit`, `puzzle` (section 6.1), `puzzle_id`, `secret` (section 6.3) and `envelope` (section 6.2, sealed with the given nonce). `checkpoint` gives a position `i`, `j`, the state `F_i^j(s_i)` at that position, the accumulator `a_{i−1}` (`acc`), and its encoding (section 6.4). All byte strings are lowercase hex.

`invalid`: inputs that MUST be rejected. Each entry has a `kind`, the index `case` of the valid case it was derived from, a short `why`, and `hex`:

| `kind` | An implementation MUST |
|---|---|
| `puzzle` | fail to decode it as a puzzle |
| `envelope` | fail to decode it, or fail to open it with that case's `key` |
| `secret` | fail to decode it as a secret, including the key check |
| `checkpoint` | fail to decode it as a checkpoint for that case's puzzle |

