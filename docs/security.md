# Security model

This document states what leanSeal guarantees, what those guarantees rest on, and what leanSeal does not do. The [paper](leanseal.pdf) gives the proofs and the analysis; [SPEC.md](../SPEC.md) Section 8 gives the proof for the exact byte encoding.

## Guarantees of the primitive

- **Confidentiality until the work is done.** An honest solver needs `n·m` chain steps in sequence. In the random-oracle model, no classical attacker derives the key even one round sooner, except with the small probability bounded below. How long a round takes is an assumption about hardware.
- **Integrity until the key is known.** Any change to an envelope's puzzle, nonce, ciphertext or tag makes opening fail. Once the key is public, revealed or solved, anyone can seal a different message under the same puzzle. The puzzle and its commitment therefore do not identify a message: refer to an envelope by a hash of all its bytes.
- **A checkable fast path.** A revealed key is checked against the puzzle's commitment before it is used.

## Guarantees in an encrypted mempool

leanSeal's intended use is as a fallback behind commit–reveal: the sender reveals its key after ordering, and the puzzle discloses the transaction if the sender does not.

- **Disclosure, for honestly built puzzles.** If the sender withholds its key, anyone can solve the puzzle, so the transaction becomes public even if its sender went offline or changed its mind.
- **No binding execution.** A transaction recovered after the solve may have expired or may revert, and it cannot wait in its committed position without stalling later transactions. Withholding can therefore still delay or cancel execution. A protocol must deter it with a deposit forfeited on a missed reveal; the reveal deadline makes a missed reveal observable with or without a puzzle.
- **No check of puzzle validity.** A sender can build a puzzle whose key matches the commitment but whose chains lead elsewhere. No efficient check is known, so a sender that plans to withhold from the start can attach such a puzzle, and the deposit is then the only deterrent, as in plain commit–reveal.
- **No privacy for excluded transactions.** A puzzle opens whether or not its transaction is included. The secrecy is temporary in every case.

The paper discusses these points in Section 6, including what the puzzle adds over commit–reveal with the same deposit.

## What the delay rests on

### The random-oracle bound

SHA-256 and its compression function are modelled as random oracles. In this model, a classical attacker making `Q_pre` queries before the puzzle exists and `Q_on` after derives the key even one round before the honest solver with probability at most

```
Q_on / 2^(8b)  +  Q_pre / 2^(128 + 8b)  +  (Q·P + P² + 1) / 2^256
```

where `Q = Q_pre + Q_on`, `P = n(m + 3) + 1` and `b` is the link width in bytes. The first term is absent when `n = 1`.

Against an attacker making `R = 10^21` queries per second, about the Bitcoin network's hash rate, for the whole delay `T` (so `Q_on = R·T`), the bound with 24-byte links is about 2<sup>−117</sup> for a 30-second puzzle and 2<sup>−97</sup> for a one-year puzzle. A query is one SHA-256 compression and a Bitcoin hash costs two, so matching the network exactly costs one bit (2<sup>−116</sup> for 30 seconds). The proof is written out but has not been machine-checked or independently reviewed.

### Round counts: an example with three chains

The bound compares the attacker with the honest solver round by round, where a round is one batch of parallel hash calls. The solver derives the key in round `T_key = n(m + 2) + 1` and checks it against the commitment `C` one round later; the sender needs `m + n + 3` rounds. A small case makes these counts easy to check. Take `n = 3` and `m = 2`, and number the chains from 1. The table gives the first round in which a solver without the key can hold each value (round 0 is publication):

| Value | What it is | In the puzzle | Solver has it in round |
|---|---|---|---|
| `x_1` | link of chain 1 | yes | 0 |
| `z_1`, `z_2` | masked links, `z_i = mask_i[0:b] ⊕ x_{i+1}` | yes | 0 |
| `C` | commitment to the key | yes | 0 |
| `s_1` | start of chain 1 | no | 1 |
| `y_1` | end of chain 1, `m = 2` steps later | no | 3 |
| `mask_1`, `a_1`, `x_2` | mask and accumulator from chain 1; `x_2 = z_1 ⊕ mask_1[0:b]` | no | 4 |
| `s_2`, `y_2` | start and end of chain 2 | no | 5, 7 |
| `mask_2`, `a_2`, `x_3` | mask and accumulator from chain 2; the link of chain 3 | no | 8 |
| `s_3`, `y_3` | start and end of chain 3 | no | 9, 11 |
| `a_3` | accumulator after chain 3 | no | 12 |
| `K` | key, `TH(key, ctx ‖ a_3)` | no | 13 |

So the solver derives `K` in round 13 = 3·(2 + 2) + 1 and checks it against `C` in round 14. Each chain costs `m` steps plus one round for its start and one for its mask and accumulator, which share a round. The sender, which drew all three links itself, needs 8 = 2 + 3 + 3 rounds: the three starts in round 1, the chains in rounds 2 and 3, the accumulator in rounds 4 to 6 with the masks alongside, then `K` and `C`. With the reference parameters these extra rounds are negligible next to the `n·m` chain steps. The only way to start chain 3 early is to guess `x_3`; with 24-byte links each guess is right with probability 2<sup>−192</sup>.

### Link width

The link width enters the first two terms of the bound. With `n = 16` and the budget above:

| Link width | Puzzle size | 30-second lock | One-year lock |
|---|---|---|---|
| 16 bytes | 324 B | 2<sup>−53</sup> | 2<sup>−33</sup> |
| 24 bytes (default) | 452 B | 2<sup>−117</sup> | 2<sup>−97</sup> |
| 32 bytes | 580 B | 2<sup>−148</sup> | 2<sup>−108</sup> |

A one-year lock needs at least 33 chains, because the format limits `m` to 2<sup>48</sup>; the one-year figures assume this. leanSeal relies only on the proved bound, so use links of 24 bytes or more; the tool warns when `-b` is below 24. A puzzle with `n = 1` has no hidden link, and its delay rests on the single chain.

### The hardware assumption

The delay in seconds is `n·m·ℓ`, where `ℓ` is the fastest time in which anyone computes one chained SHA-256 step. leanSeal's reference parameters assume `ℓ = 3.5 ns`, 3.7 times faster than the fastest published SHA-256 design (13.0 ns, a synthesized 7 nm core) and 6.6 times faster than one Apple M4 core. This is an estimate, not a lower bound; the paper's Appendix B gives the circuit model behind it.

An attacker `k` times faster than assumed opens a puzzle `k` times sooner. Restoring the delay costs `k` times more work for every sender, and no extra bytes. Choose `m` against the fastest attacker you assume, not against your own machine.

### Other assumptions

- HMAC-SHA256 is a pseudorandom function. The encryption layer is intended to hide the contents of equal-length messages, but a reduction from distinguishing envelopes to the events of the delay proof has not been written.
- The sender's random number generator is sound.
- The bound is classical. Afshar et al. prove that the idealized chained puzzle keeps its delay against quantum attackers; no analysis covers leanSeal's exact encoding.

## What leanSeal does not do

- **No proof that a puzzle is well formed.** A malformed puzzle wastes the solver's time, and the solver learns this only when the final key fails the commitment check.
- **No control over when the clock starts.** The delay runs from the moment a puzzle becomes public. Keep a secret file private until its first envelope is published.
- **No shared solving.** Each puzzle needs its own full solve; independent puzzles share no work. The honest solver uses one core per puzzle, and more cores help only to solve several puzzles at once.
- **No hiding of metadata.** The message length and the puzzle parameters are public.
- **No side-channel hardening** beyond constant-time comparison of tags and commitments. Keys, plaintexts and HMAC state are zeroed when dropped, on every return path; copies the standard library or the operating system makes are not.
- **No crash-durable checkpoints.** A checkpoint is replaced atomically, but its directory is not synced, so a power failure can lose the latest checkpoint.
- **No network protocol.** Who solves puzzles, who pays for solving and how spam is limited are protocol questions. The paper discusses them, and [the prototype](../poc/README.md) implements one answer on an EVM chain.
