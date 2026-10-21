# chainseal

chainseal encrypts a message so that anyone can read it after a fixed amount of sequential SHA-256 work, and the sender can let everyone read it at once by publishing a key. It uses nothing but SHA-256.

It implements the chained-hash time-lock puzzle of Mahmoody, Moran and Vadhan (CRYPTO 2011, section 3.1), with every random-oracle call replaced by a long SHA-256 chain, as Vitalik Buterin proposed for encrypted mempools. [SPEC.md](SPEC.md) defines the format.

**Status: proof of concept.** The format is versioned and fully specified. It has test vectors and a second, independent implementation, and an AI model has audited the code. No human cryptographer has reviewed it. Do not protect anything valuable with it.

## Build and test

You need a C11 compiler and `make`. For the full test suite you also need `python3`, version 3.11 or later.

```sh
make            # builds ./chainseal
make test       # unit tests, CLI tests, test vectors, Python cross-check
make sanitize   # the same under AddressSanitizer and UndefinedBehaviorSanitizer
make tsan       # the threaded paths under ThreadSanitizer
make bench      # latency, throughput, build time against n, toy attack
sh demo.sh      # time-lock the EIP-155 example transaction, open it both ways
```

The tool picks the fastest SHA-256 backend at run time:

- `armv8-sha2` on Apple silicon and other ARMv8 cores;
- `x86-sha-ni` on x86 CPUs with the SHA extensions;
- `portable` otherwise.

Set `CHAINSEAL_BACKEND` to force one. `chainseal selftest` checks every backend against plain SHA-256.

## Use

```sh
# Sender: build a puzzle ahead of time. 64 chains of 2^28 steps is about
# 6.6 minutes of sequential work on an Apple M4, and about 40 s to build there.
chainseal gen -n 64 -m 2^28 -o tx.secret

# When the message is ready, encrypt it under the stored puzzle.
chainseal encrypt -s tx.secret -i tx.bin -o tx.env

# Fast path: the sender publishes the key and anyone opens the envelope at once.
chainseal key tx.secret               # prints 64 hex digits
chainseal open tx.env -k <key> -o tx.bin

# Slow path: anyone solves the puzzle. Ctrl-C saves progress to tx.env.ckpt,
# and running the command again resumes from there.
chainseal open tx.env --solve -o tx.bin
chainseal solve a.env b.env c.env     # several puzzles at once, one core each
```

Instead of `-m`, you can give `-d 10m` to choose `m` for a target delay. By default, the delay is measured against this machine's speed for one chain; `--step-ns` sets another solver speed. `chainseal info FILE` describes any chainseal file.

## How it works

The sender draws random links `x_1 … x_n` and runs `n` independent chains of `m` SHA-256 steps, one per link, all in parallel. Each step hashes the 32-byte state together with the puzzle's salt and the chain's index. That is still one SHA-256 compression, and it ties every step to one chain of one puzzle.

The puzzle publishes `x_1` in the clear. Each later link `x_{i+1}` is published masked with the end of chain `i`. The key is a hash of the end of chain `n`, and the puzzle carries a 32-byte commitment to the key.

A solver must run the chains one after another, because each chain's start is hidden under the end of the previous one. So building costs `n·m` steps spread over the sender's cores, and solving costs `n·m` steps in sequence. The message is encrypted with an HMAC-SHA256 keystream and authenticated with an HMAC-SHA256 tag over the whole envelope.

Sizes:

| Item | Size |
|---|---|
| Puzzle | `68 + 12n` bytes with 12-byte links: 836 B for n = 64, 6,212 B for n = 512 |
| Envelope | the puzzle + 60 bytes + the message |
| Secret, a puzzle kept with its key | the puzzle + 40 bytes |
| Checkpoint | 84 bytes |

## Measurements

These are from `chainseal bench all` and `demo.sh`. The logs are in [bench-results/](bench-results/).

| Machine | One chain | All cores | Build/solve ratio |
|---|---|---|---|
| Apple M4 (MacBook Air, 10 cores) | 23.1 ns/step | 465 M steps/s | about 11 |

The build/solve ratio is how much faster the sender builds a puzzle than a single-core solver opens it, once `n` is at least the number of cores.

## Threat model

**What chainseal is meant to give.**

- *Confidentiality until the work is done.* Nobody learns anything about the message until they have computed `n·m` chain steps in sequence, or the sender reveals the key.
- *Integrity, until the key is known.* Any change to an envelope's puzzle, nonce, ciphertext or tag makes opening fail. Once the key is public, revealed or solved, anyone can seal a different message under the same puzzle. So the puzzle and its commitment do not identify a message: refer to an envelope by a hash of all its bytes.
- *A checkable fast path.* A revealed key is checked against the commitment before it is used.

**What the delay rests on.**

- Nobody computes `m` chained SHA-256 steps much faster than `m·ℓ`, where `ℓ` is the fastest attainable latency of one compression on the best hardware. The delay is a wall-clock estimate, so a faster solver opens the envelope sooner. Set `m` against the fastest attacker you assume, not against your own machine.
- The links are wide enough that guessing the last one is hopeless. With 12-byte links, an attacker computing `10^21` steps per second has a chance of about `2^-45` of opening a 60-second puzzle with `m = 2^25` (SPEC.md section 8; `chainseal bench attack` checks the formula at toy sizes).
- The sender's random number generator is sound.

**What it does not do.**

- *No proof that a puzzle is well formed.* A malformed puzzle wastes the solver's time, and the solver finds out only when the final key fails the commitment check.
- *No control over when the clock starts.* The delay runs from the moment a puzzle becomes public. A secret file must stay private until its first envelope is published.
- *No speedup for honest solvers.* Solving one puzzle cannot use more than one core. Many puzzles can be solved at once, one core each.
- *No hiding of metadata.* The message length and the parameters are public.
- *No side-channel hardening* beyond constant-time comparison of tags and commitments.
- *No answer to the network questions*: who solves puzzles, who pays for solving, and how spam is limited.

## Layout

| Path | Contents |
|---|---|
| `SPEC.md` | the normative format |
| `src/sha256.c` | portable SHA-256, HMAC-SHA256, labelled hashes |
| `src/chain.c` | the chain step: ARMv8, x86 SHA-NI and portable backends |
| `src/chainseal.c` | puzzles, solving, checkpoints, secrets, envelopes |
| `src/rng.c` | OS randomness, plus a seeded generator for test vectors only |
| `src/cli.c`, `src/bench.c`, `src/vectors.c`, `src/util.c` | the command-line tool |
| `tests/` | unit tests, CLI tests, cross-tests, `vectors.json` |
| `ref/chainseal_ref.py` | an independent Python implementation, written from SPEC.md alone |
