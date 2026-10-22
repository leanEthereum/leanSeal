# chainseal v1 specification

chainseal is a time-lock encryption scheme built only from SHA-256. A sender encrypts a message so that anyone can decrypt it after doing a fixed amount of sequential hashing, and the sender can also reveal the key early. The construction is the chained-hash time-lock puzzle of Mahmoody, Moran and Vadhan (CRYPTO 2011, section 3.1, the variant in which each link is a hash iterated many times), instantiated with SHA-256 for encrypted mempools as Vitalik Buterin proposed.

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
| `chainseal/v1/mask` | the masks that hide links |
| `chainseal/v1/acc` | the hash of the chain ends |
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

In addition, `n·m ≤ 2^60`, so that every step count fits in 64 bits.

An honest solver does `n·m` chain steps in sequence, plus `n` start hashes, `n − 1` mask hashes, `n` hashes of the chain ends and two final hashes. Section 8 discusses what this does and does not guarantee.

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

*Informative.* The chain step hashes exactly 52 bytes. Every other SHA-256 input in this format is longer: the labelled hashes hash at least 56 bytes (the start hash with `b = 1`), and the hashes inside HMAC hash at least 72. So the input of a chain step is never also the input of another hash in this format.

## 4. Puzzle generation

Inputs: parameters `n`, `m`, `b`. The generator MUST draw `salt` and the links `x_1, …, x_n` (each `b` bytes) from a cryptographically secure random number generator.

1. Let `ctx = u8(1) ‖ u8(b) ‖ 0x0000 ‖ be32(n) ‖ be64(m) ‖ salt`, 32 bytes. These are bytes `[4:36)` of the puzzle encoding (section 6.1): version, `b`, reserved, `n`, `m`, `salt`.
2. For each `i` in 1..n, independently:

       s_i = TH("chainseal/v1/start", ctx ‖ be32(i) ‖ x_i)
       y_i = F_i^m(s_i)

3. For each `i` in 1..n−1, hide the next link under a mask derived from the end of chain `i`:

       z_i = TH("chainseal/v1/mask", ctx ‖ y_i)[0:b] ⊕ x_{i+1}

4. Hash the chain ends in order, starting from `a_0 = ctx`:

       a_i = TH("chainseal/v1/acc", a_{i−1} ‖ y_i)    for i = 1, …, n

5. Derive the session key and its commitment:

       K = TH("chainseal/v1/key", ctx ‖ a_n)
       C = TH("chainseal/v1/commit", ctx ‖ K)

6. The puzzle is the header with commitment `C`, followed by the links `x_1 ‖ z_1 ‖ … ‖ z_{n−1}` (section 6.1).

Step 2 is where the generator spends its time. The `n` chains are independent and SHOULD be computed in parallel. Step 4 is `n` more hashes, done in sequence once all chains have ended.

*Informative.* The key depends on the end of every chain, not only the last. A solver who guesses a hidden link and runs the remaining chains from it still needs the ends of all earlier chains, so a right guess saves time but does not by itself open the puzzle (section 8). The mask is a hash of the end rather than the end itself, so that a guess of `x_{i+1}`, which fixes the mask's first `b` bytes, says nothing about `y_i`; with a raw mask and `b = 32`, a right guess would give away all of `y_i`. Hashing the ends one at a time keeps the state a solver carries between chains to 32 bytes.

## 5. Solving

Given a valid puzzle:

1. Read `ctx`, `x_1` and `z_1, …, z_{n−1}`. Set `x ← x_1` and `a ← ctx`.
2. For `i` = 1, …, n: compute `y_i = F_i^m(TH("chainseal/v1/start", ctx ‖ be32(i) ‖ x))` and set `a ← TH("chainseal/v1/acc", a ‖ y_i)`. If `i < n`, set `x ← TH("chainseal/v1/mask", ctx ‖ y_i)[0:b] ⊕ z_i`.
3. Compute `K = TH("chainseal/v1/key", ctx ‖ a)`.
4. Accept `K` only if `TH("chainseal/v1/commit", ctx ‖ K) = C`. Otherwise the puzzle is malformed and MUST be reported as such.

A solver that follows these steps cannot start chain `i + 1` before chain `i` ends, because its start link is hidden under the end of chain `i`. A solver can try to skip ahead by guessing a link instead; section 8 discusses this.

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
| 84 | 32 | `a_{i−1}`, the hash of the ends of chains 1 to i−1 (`ctx` when i = 1) |

Total length: 116 bytes. A solver resuming from a checkpoint MUST check the puzzle id. Nothing authenticates the state or `a_{i−1}`; a damaged checkpoint leads to a key that fails the commitment check of section 5.

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

- **What the delay rests on.** The delay is an assumption about attackers, not a theorem of this document. It assumes nobody computes `m` chained steps much faster than `m·ℓ`, where `ℓ` is the fastest attainable latency of one SHA-256 compression; this covers both the absence of shortcuts for iterating SHA-256 and the circuit speed of the best hardware. It also assumes that the only useful way to skip chains is to guess links, as below. In the random-oracle model, Mahmoody, Moran and Vadhan prove asymptotically that their construction needs about `n·m` sequential rounds, except with negligible probability, and that no hash-only puzzle can provably need more rounds than its generator makes queries. chainseal keeps their dependency structure. The bullet "A proved bound" below gives a concrete theorem for chainseal in the random-oracle model; it is weaker than the bound believed for link guessing. There is no analysis against quantum attackers.
- **Guessing a link.** A solver can skip work only by guessing a hidden link `x_k` and running chains `k, k+1, …` from the guess before chain `k − 1` has ended. Because the key depends on every chain end, and a link's mask is a hash of the previous end that reveals nothing about the end itself, a guess is confirmed only when the solver's own chains reach link `k` and reveal `x_k`; until then every guessed run is blind. In the simplest attack one guessed run provides the whole saving: to finish `d` steps sooner than an honest solver, that run must already be `d` steps ahead when it is confirmed. Runs from different guesses of one link share no steps in their first chain, but two runs that reach the same later link need the same steps from then on, and an attacker can compute those once. So a guessed run that gains `a` steps has cost at least `min(a, m)` steps of its own and is right with probability `2^(−8b)`. An attacker who computes `Q` chain steps in total, across all its hardware, is believed to save `d` steps with chance at most about `Q / (min(d, m)·2^(8b))`. This is not proved, and the proved bound below lacks the factor `min(d, m)`: an attack can combine gains from several runs. Two sharper versions are false for short links. Charging each guess its whole saving `d` fails against an attacker that merges runs reaching the same link (audit round 7). Squaring the chance for savings of more than half fails against one that prepares short starts for every value of a link (audit round 8). Saving more than half of the `n·m` steps does need work done ahead beyond one right guess, but this document gives no separate bound for it. For a saving of one whole chain, take `d = m`: a fleet computing `R` chain steps per second makes `Q = R·T` steps within time `T`, so its chance is at most `R·T / (m·2^(8b))`. Guessing the key itself succeeds with chance `2^−256` per guess. Beyond the proved bound below, there is no proof that no other strategy does better. Use `b = 16` unless a smaller value is justified. With `m = T/(n·ℓ)` the chance of saving one chain is `R·ℓ·n / 2^(8b)`, which does not depend on `T`. Against `R = 10^21`, `ℓ = 3.5 ns` and `n = 512`, it is about `2^(−77)` per puzzle with `b = 16`, and keeping it below `2^(−64)` needs `b ≥ 15`. Each byte less multiplies it by 256: `b = 12` gives about `2^(−45)`. An early opening is bounded harm: if the claim holds, the expected time an attacker gains per puzzle is at most this chance times `T`, about `3.5·10^(−22)` s for the figures above. Savings of less than a chain are likelier but worth less: there `min(d, m) = d`. With `n = 1` the only link is public, so a one-chain puzzle relies on the chain alone.
- **A proved bound.** The statement below is proved in the random-oracle model. It covers every saving, however small, but unlike the believed bound above it does not grow with the length of a guessed run. Model each step function `F_i` and each labelled hash as an independent random oracle (the input lengths and labels of sections 1 and 3 keep their domains apart). Count time in rounds: in one round an attacker submits any number of queries at once, then receives all their answers. The solver of section 5, computing each chain's mask and accumulator hashes in the same round, obtains `K` after `n·(m + 2) + 1` rounds (one more to check `C`). Call the 32-byte values it computes (each chain's start value, its `m` states, its mask and its accumulator value, and then `K`) the values on the honest path; there are at most `N = n·(m + 3) + 1` of them.

  *Theorem.* An attacker that receives the puzzle and then makes at most `Q` oracle queries outputs `K` in fewer than `n·(m + 2) + 1` rounds with probability at most `Q / 2^(8b) + (3·Q·N + N² + Q + 1) / 2^256`. For `n = 1` the first term is absent.

  *Proof.* A value on the honest path is *known* once the attacker has received it as an oracle answer. Consider three bad events: (i) some query equals the input of a hash on the honest path before every value in that input is known, or two values on the honest path are equal; (ii) a query other than the one on the honest input returns a value on the honest path; (iii) for some `i ≥ 2`, the attacker submits `TH("chainseal/v1/start", ctx ‖ be32(i) ‖ x_i)` before the mask of chain `i − 1` is known. Replace the oracle answers on the honest path, and `C`, by independent uniform values; the two games agree until a bad event happens. In the second game every value on the honest path that is not yet known is independent of the attacker's view, and so is every link `x_i` whose preceding mask is not yet known, because `z_(i−1)` is `x_i` XOR the first `b` bytes of that unknown mask. Only the inputs of `F_i` and of the start, mask, acc, key and commit hashes lie on the honest path, and each has at most two 32-byte fields, so (i) has probability at most `(2·Q·N + N²) / 2^256` and (ii) at most `Q·N / 2^256`. Each start query names one chain `i` and hits `x_i` with probability `2^(−8b)`, so (iii) has probability at most `Q / 2^(8b)`. If none of them happens, each value on the honest path becomes known only through the query on its predecessor, which must already have been known in an earlier round, and chain `i` can start only in the round after the mask of chain `i − 1` becomes known. So `K` is known no earlier than round `n·(m + 2) + 1`, exactly as for the honest solver. An attacker that outputs `K` without knowing it is right with probability at most `(Q + 1) / 2^256`, counting its tests of guesses against `C`. The argument follows Lemmas 6 and 9 of Pietrzak and Reyzin, "Optimal Proofs of Sequential Work" (ePrint 2026/2569). It is written out here, not machine-checked.

  Queries made before the puzzle is published can be added to `Q` at an extra cost of `2^(−128)` each, because every input on the honest path contains the fresh salt or an earlier value on the path. The theorem counts rounds; turning rounds into seconds is the latency assumption of the first bullet. An attacker holding envelopes can also test guesses of `K` against their tags, which adds terms of order `Q / 2^256`; this is not written out. With `b = 16` and a fleet making `R = 10^21` queries per second for the `T` seconds a puzzle takes (`Q = R·T`), the first term is about `2^(−52)` for `T = 60` s and `2^(−33)` for a year, and the second is below `2^(−100)` for both. The expected time an attacker gains is then at most this chance times `T`: about `10^(−14)` s for the 60-second puzzle and 3 ms for the year-long one. With `b = 32` the first term is `Q / 2^256`, so the bound holds against any feasible attacker, with links twice as long.
- **The delay starts at publication.** Anyone holding a puzzle can start solving it. A puzzle built in advance (a secret file) MUST be kept private until its first envelope is published. From then on the clock runs for every envelope under that puzzle: a message encrypted later under the same puzzle opens at the same time as the first, not one full delay after its own publication. Encrypt together all messages that should open together, then discard the secret.
- **Malformed puzzles.** Nothing in v1 lets a verifier check, before solving, that a puzzle leads to its commitment. A malformed puzzle is detected only when the solve ends with a commitment mismatch.
- **What the tag protects.** The tag stops anyone who does not know `K` from changing an envelope. Anyone who knows `K`, because it was revealed or solved, can seal a new message under the same puzzle, with a valid tag. A puzzle or its commitment therefore does not identify a message. A system that orders or references envelopes MUST bind to the whole envelope, for example by its SHA-256 hash.
- **Assumptions behind the encryption.** Confidentiality of the message and unforgeability of the tag, for anyone who does not know `K`, assume that HMAC-SHA256 is a pseudorandom function. That a commitment fixes one key, and that one envelope opens to one message, assume that SHA-256 is collision resistant. Full 32-byte values are used for both; a 16-byte commitment could be collided with about 2^64 hashes.
- **Key reuse.** Under the assumptions above, reusing `K` with distinct nonces keeps confidentiality and integrity. Reusing a nonce under the same key reveals the XOR of the two plaintexts.
- **Not provided.** Side-channel hardening beyond constant-time tag and commitment comparison; proofs of well-formedness; anything about how a network schedules, pays for or prioritises solving.

## 9. Choosing parameters (informative)

For a target delay `T` against an attacker with per-step latency `ℓ`, choose `n` to match the sender's parallelism and set `m = ⌈T / (n·ℓ)⌉`. The puzzle is `68 + n·b` bytes, 8,260 bytes for `n = 512` and `b = 16`, and an envelope adds `60` bytes plus the message. Building takes about `n·m / R_sender` seconds, where `R_sender` is the sender's total rate, once `n` is several times the number of the sender's parallel lanes. An honest solver takes `n·m·ℓ_solver`.

## 10. Test vectors (informative)

`tests/vectors.json` holds deterministic vectors produced by the reference C implementation. It has two lists.

`cases`: valid puzzles. Each entry gives the parameters `n`, `m`, `b`, the random inputs `salt`, `x` (the links `x_1..x_n`), `nonce` and `message`, and the values an implementation must reproduce from them: `start` (the `s_i`), `y` (the `y_i`), `acc` (the `a_i` for i = 1..n), `key`, `commit`, `puzzle` (section 6.1), `puzzle_id`, `secret` (section 6.3) and `envelope` (section 6.2, sealed with the given nonce). `checkpoint` gives a position `i`, `j`, the state `F_i^j(s_i)` at that position, the accumulator `a_{i−1}` (`acc`), and its encoding (section 6.4). All byte strings are lowercase hex.

`invalid`: inputs that MUST be rejected. Each entry has a `kind`, the index `case` of the valid case it was derived from, a short `why`, and `hex`:

| `kind` | An implementation MUST |
|---|---|
| `puzzle` | fail to decode it as a puzzle |
| `envelope` | fail to decode it, or fail to open it with that case's `key` |
| `secret` | fail to decode it as a secret, including the key check |
| `checkpoint` | fail to decode it as a checkpoint for that case's puzzle |

