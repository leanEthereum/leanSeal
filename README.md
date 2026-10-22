# chainseal

chainseal encrypts a message so that anyone can read it after a fixed amount of sequential SHA-256 work, and the sender can let everyone read it at once by publishing a key. It uses nothing but SHA-256.

It implements the chained-hash time-lock puzzle of Mahmoody, Moran and Vadhan (CRYPTO 2011, section 3.1, the variant in which each link is a hash iterated many times), instantiated with SHA-256 for encrypted mempools as Vitalik Buterin proposed. [SPEC.md](SPEC.md) defines the format, and [the guide](https://quangvdao.github.io/chainseal/) explains the idea, the parameters and the measurements.

Authors: Vitalik Buterin, Quang Dao and Justin Drake.

**Status: proof of concept.** The format is versioned and fully specified. It has test vectors and a second implementation, in Python, that shares no code with the Rust one. An AI model audited an earlier C implementation in several rounds; the reports and the fixes are in [audit/](audit/). The Rust implementation replaced it, reproduces its test vectors and command-line behaviour, was reviewed against it, and has fuzzed decoders. No human cryptographer has reviewed it. Do not protect anything valuable with it.

## Build and test

You need Rust 1.80 or later and a POSIX system. For the full test suite you also need `make`, `sh` and `python3`, version 3.11 or later. The demo also uses `xxd` and `perl`. Everything here was run on macOS on an Apple M4, and the tests also pass on Linux x86-64 (Ubuntu 24.04, AMD EPYC 9554P). Continuous integration runs them on Linux x86-64, Linux aarch64 and macOS on Apple silicon.

```sh
make            # cargo build --release: target/release/chainseal
make test       # cargo tests, CLI tests, test vectors, Python cross-check
make bench      # latency, throughput, build time against n, toy attack
sh demo.sh      # time-lock the EIP-155 example transaction, open it both ways
```

The tool has three SHA-256 backends. It uses an accelerated one when the CPU supports it, and the portable one otherwise:

- `armv8-sha2`, for ARMv8 CPUs with the SHA-2 instructions. It is built on every aarch64 target, and the tool uses it only if the CPU reports those instructions at run time.
- `x86-sha-ni`, for x86-64 CPUs with the SHA extensions, detected with CPUID. It was run and timed on an AMD EPYC 9554P (Zen 4): 37.4 ns/step for one chain, against 23.3 on the M4.
- `portable`, everywhere.

Set `CHAINSEAL_BACKEND` to force one. The tool refuses a backend that this build or this CPU does not have. `chainseal selftest` checks every available backend against plain SHA-256. The accelerated backends are the only `unsafe` code in the crate.

The decoders are fuzzed with cargo-fuzz (`cd fuzz && cargo +nightly fuzz run puzzle`, and likewise `envelope`, `secret` and `checkpoint`); `tests/decode_props.rs` runs the same checks on every `cargo test`.

## Use

```sh
# Sender: build a puzzle ahead of time. 64 chains of 2^28 steps is about
# 6.7 minutes of sequential work on an Apple M4, and about 43 s to build there.
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

The crate is also a library. It is not on crates.io; depend on it with `chainseal = { git = "https://github.com/quangvdao/chainseal" }`.

```rust
use chainseal::backend::Backend;
use chainseal::{generate, seal, Envelope, GenOptions};

fn main() -> Result<(), chainseal::Error> {
    // Sender: build a puzzle (4 chains of 2^20 steps) and seal a message.
    let opts = GenOptions { threads: chainseal::cpu_count(), backend: None, progress: None };
    let (puzzle, key) = generate(4, 1 << 20, 16, &opts)?;
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| chainseal::Error::Rng)?;
    let bytes = seal(&puzzle, &key, &nonce, b"hello")?;

    // Anyone: solve the puzzle in sequence, then open the envelope.
    let env = Envelope::decode(&bytes)?;
    let mut cursor = env.puzzle.cursor();
    let solved = env.puzzle.solve(&mut cursor, Backend::best()?, 0, |_| false)?;
    assert_eq!(env.open(&solved)?, b"hello");
    Ok(())
}
```

## How it works

The sender draws random links `x_1 … x_n` and runs `n` independent chains of `m` SHA-256 steps, one per link, all in parallel. Each step hashes the 32-byte state together with the puzzle's salt and the chain's index. That is still one SHA-256 compression, and it ties every step to one chain of one puzzle.

The puzzle publishes `x_1` in the clear. Each later link `x_{i+1}` is published masked with a hash of the end of chain `i`. The key is a hash of the ends of all `n` chains, taken in order, and the puzzle carries a 32-byte commitment to the key.

A solver that follows these dependencies must run the chains one after another, because each chain's start is hidden under the end of the previous one. So building costs `n·m` steps spread over the sender's cores, and honest solving costs `n·m` steps in sequence. A solver can skip chains by guessing a hidden link, or the key itself; that is why links are 16 bytes wide and the key is 32 (see the threat model below). The message is encrypted with an HMAC-SHA256 keystream and authenticated with an HMAC-SHA256 tag over the whole envelope.

Sizes:

| Item | Size |
|---|---|
| Puzzle | `68 + 16n` bytes with 16-byte links: 1,092 B for n = 64, 8,260 B for n = 512 |
| Envelope | the puzzle + 60 bytes + the message |
| Secret, a puzzle kept with its key | the puzzle + 40 bytes |
| Checkpoint | 116 bytes |

## Measurements

These are from `chainseal bench all` and `demo.sh` on an Apple M4 (MacBook Air, 10 cores). The logs are in [bench-results/](bench-results/), which also has an x86 run on a 4-vCPU AMD EPYC 9554P VM (`x86-epyc-9554p.txt`): 37.4 ns/step for one chain, 173 M steps/s on all four vCPUs.

| Quantity | Value |
|---|---|
| One chain | 23.3 ns/step (median of 5 runs), 23.2 ns/step (best) |
| All cores, independent chains | 474 M steps/s |
| Build speedup over one solver | 9.2 to 9.5 for n = 16 to 64, 10.3 to 11.4 from n = 128 up |
| Demo: n = 512, m = 2^25 (17.2 G steps) | built in 37.8 s, opened with the key in 8 ms, solved without it in 6 min 43 s |

The build speedup is how much faster the sender builds a puzzle than a single-core solver opens it. It approaches the all-core rate over the one-chain rate, about 11 here. Each core computes two chains at once, so the builder hands out chains in pairs, and it needs `n` to be several times the number of cores to keep every core busy until the end.

## Threat model

**What chainseal is meant to give.**

- *Confidentiality until the work is done.* An honest solver needs `n·m` chain steps in sequence. The design assumes that nobody can open an envelope much sooner, as set out below. In the random-oracle model the round count is proved (SPEC.md section 8); that rounds take as long as assumed, and the sharper bound on link guessing, are assumptions.
- *Integrity, until the key is known.* Any change to an envelope's puzzle, nonce, ciphertext or tag makes opening fail. Once the key is public, revealed or solved, anyone can seal a different message under the same puzzle. So the puzzle and its commitment do not identify a message: refer to an envelope by a hash of all its bytes.
- *A checkable fast path.* A revealed key is checked against the commitment before it is used.

**What the delay rests on.**

- Nobody computes `m` chained SHA-256 steps much faster than `m·ℓ`, where `ℓ` is the fastest attainable latency of one compression on the best hardware. The delay is a wall-clock estimate, so a faster solver opens the envelope sooner. Set `m` against the fastest attacker you assume, not against your own machine.
- Guessing does not pay. A solver can guess a hidden link and run the later chains from the guess before the earlier ones end. Since the key needs every chain's end, a guess is confirmed only when the solver's own chains reach it, so a right guess saves time but opens nothing by itself, and each guess costs at least one chain of steps, or its saving if that is less. With 16-byte links, an attacker computing `10^21` steps per second has a chance of about `2^-77` of saving even one chain of a 60-second puzzle with `m = 2^25`, and a chance of about `Q/(min(d,m)·2^128)` of saving `d` steps with `Q` steps of work (SPEC.md section 8; `chainseal bench attack` checks the formula at toy sizes). Saving more than half the work needs more than one right guess, or tables over every value of a link. Guessing the 32-byte key is right with chance `2^-256` per guess. Nothing here proves that no other strategy does better. A puzzle with `n = 1` has no hidden link, and its delay rests on the one chain alone.
- In the random-oracle model, Mahmoody, Moran and Vadhan prove asymptotically that their construction needs about `n·m` sequential rounds. chainseal keeps their dependency structure. SPEC.md section 8 proves a concrete bound for chainseal in the random-oracle model: finishing even one round early needs a right guess of some link, with chance about `Q/2^(8b)` for `Q` queries. The sharper bound for link guessing above is believed, not proved, and there is no analysis against quantum attackers.
- The sender's random number generator is sound.

**What it does not do.**

- *No proof that a puzzle is well formed.* A malformed puzzle wastes the solver's time, and the solver finds out only when the final key fails the commitment check.
- *No control over when the clock starts.* The delay runs from the moment a puzzle becomes public. A secret file must stay private until its first envelope is published.
- *No parallel honest solving.* The honest solver uses one core per puzzle. More cores help only to solve several puzzles at once.
- *No hiding of metadata.* The message length and the parameters are public.
- *No side-channel hardening* beyond constant-time comparison of tags and commitments. Keys are wiped from memory on the main paths, but not everywhere.
- *No crash-durable checkpoints.* A checkpoint is replaced atomically, but its directory is not synced, so a power failure can lose the latest one.
- *No answer to the network questions*: who solves puzzles, who pays for solving, and how spam is limited.

## Layout

| Path | Contents |
|---|---|
| `SPEC.md` | the normative format |
| `src/hash.rs` | portable SHA-256, HMAC-SHA256, labelled hashes |
| `src/backend/` | the chain step: ARMv8, x86 SHA-NI and portable backends |
| `src/puzzle.rs`, `src/envelope.rs` | puzzles, solving, checkpoints, secrets, envelopes |
| `src/runtime.rs` | parallel generation and solving of several puzzles |
| `src/rng.rs` | a seeded generator for test vectors only (OS randomness comes from `getrandom`) |
| `src/main.rs`, `src/benchmark.rs`, `src/vectors.rs`, `src/signal.rs` | the command-line tool |
| `tests/` | library and CLI tests, decoder property tests, shell CLI tests, cross-tests, `vectors.json` |
| `fuzz/` | cargo-fuzz targets for the four decoders |
| `ref/chainseal_ref.py` | a separate Python implementation that shares no code with the Rust one |
| `bench-results/` | benchmark and demo logs |
| `audit/` | the audit reports on the earlier C implementation and what was fixed |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
