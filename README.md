# leanSeal

[![CI](https://github.com/leanEthereum/leanSeal/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/leanEthereum/leanSeal/actions/workflows/ci.yml)

leanSeal encrypts a message so that anyone can read it after a fixed amount of sequential SHA-256 work, and the sender can let everyone read it at once by publishing a key. It uses nothing but SHA-256.

It implements the chained-hash time-lock puzzle of Mahmoody, Moran and Vadhan (CRYPTO 2011, section 3.1, the variant in which each link is a hash iterated many times), instantiated with SHA-256 for encrypted mempools as Vitalik Buterin proposed. [SPEC.md](SPEC.md) defines the format, and [the guide](https://leanethereum.github.io/leanSeal/guide.html) explains the idea, proves the delay theorem, and covers the parameters, the measurements and the deployment, with a parameter calculator.

Authors: Vitalik Buterin, Quang Dao and Justin Drake.

**Status: proof of concept.** The format is versioned and fully specified. It has test vectors and a second implementation, in Python, that shares no code with the Rust one. An AI model audited an earlier C implementation in several rounds; the reports and the fixes are in [audit/](audit/). The Rust implementation replaced it, reproduces its test vectors and command-line behaviour, was reviewed against it, and has fuzzed decoders. No human cryptographer has reviewed it. Do not protect anything valuable with it.

leanSeal was developed under the name chainseal. The audit reports in [audit/](audit/) and the logs in [bench-results/](bench-results/) predate the rename and use the old name, labels and magic bytes; the format itself was renamed before any release, so v1 uses the `leanseal/v1/` labels and the `LS` magic bytes throughout.

## Build and test

You need Rust 1.80 or later and a POSIX system. For the full test suite you also need `make`, `sh` and `python3`, version 3.11 or later. The demo also uses `xxd` and `perl`. Everything here was run on macOS on an Apple M4, and the tests also pass on Linux x86-64 (Ubuntu 24.04, AMD EPYC 9554P). Continuous integration runs them on Linux x86-64, Linux aarch64 and macOS on Apple silicon.

```sh
make            # cargo build --release: target/release/leanseal
make test       # cargo tests, CLI tests, test vectors, Python cross-check
make bench      # latency, throughput, build time against n, toy attack
sh demo.sh      # time-lock the EIP-155 example transaction, open it both ways
```

The tool has three SHA-256 backends. It uses an accelerated one when the CPU supports it, and the portable one otherwise:

- `armv8-sha2`, for ARMv8 CPUs with the SHA-2 instructions. It is built on every aarch64 target, and the tool uses it only if the CPU reports those instructions at run time.
- `x86-sha-ni`, for x86-64 CPUs with the SHA extensions, detected with CPUID. It was run and timed on an AMD EPYC 9554P (Zen 4): 37.4 ns/step for one chain, against 23.3 on the M4.
- `portable`, everywhere.

Set `LEANSEAL_BACKEND` to force one. The tool refuses a backend that this build or this CPU does not have. `leanseal selftest` checks every available backend against plain SHA-256. The accelerated backends are the only `unsafe` code in the crate.

The decoders are fuzzed with cargo-fuzz (`cd fuzz && cargo +nightly fuzz run puzzle`, and likewise `envelope`, `secret` and `checkpoint`); `tests/decode_props.rs` runs the same checks on every `cargo test`.

## Use

`make` leaves the tool at `target/release/leanseal`. The examples below assume it is on your `PATH`; `cargo install --path .` puts it in `~/.cargo/bin`.

```sh
# Sender: build a puzzle ahead of time. 16 chains of 2^30 steps is about
# 6.6 minutes of sequential work on an Apple M4, and about 40 s to build there.
leanseal gen -n 16 -m 2^30 -o tx.secret

# When the message is ready, encrypt it under the stored puzzle.
leanseal encrypt -s tx.secret -i tx.bin -o tx.env

# Fast path: the sender publishes the key and anyone opens the envelope at once.
leanseal key tx.secret               # prints 64 hex digits
leanseal open tx.env -k <key> -o tx.bin

# Slow path: anyone solves the puzzle. Ctrl-C saves progress to tx.env.ckpt,
# and running the command again resumes from there.
leanseal open tx.env --solve -o tx.bin
leanseal solve a.env b.env c.env     # several puzzles at once, one core each
```

Instead of `-m`, you can give `-d 10m` to choose `m` for a target delay. By default, the delay is measured against this machine's speed for one chain; `--step-ns` sets another solver speed. `leanseal info FILE` describes any leanseal file.

The crate is also a library. It is not on crates.io; depend on it with `leanseal = { git = "https://github.com/leanEthereum/leanSeal" }`. The example below draws its nonce with `getrandom`, so it also needs `getrandom = "0.2"`. Every envelope sealed under one key needs a fresh nonce.

```rust
use leanseal::backend::Backend;
use leanseal::{generate, seal, Envelope, GenOptions};

fn main() -> Result<(), leanseal::Error> {
    // Sender: build a puzzle (4 chains of 2^20 steps) and seal a message.
    let opts = GenOptions { threads: leanseal::cpu_count(), backend: None, progress: None };
    let (puzzle, key) = generate(4, 1 << 20, 24, &opts)?;
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| leanseal::Error::Rng)?;
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

A solver that follows these dependencies must run the chains one after another, because each chain's start is hidden under the end of the previous one. So building costs `n·m` steps spread over the sender's cores, and honest solving costs `n·m` steps in sequence. A solver could skip chains only by guessing a hidden link or the key, so links are 24 bytes wide by default and the key 32 (see the threat model below). The message is encrypted with an HMAC-SHA256 keystream and authenticated with an HMAC-SHA256 tag over the whole envelope.

Sizes:

| Item | Size |
|---|---|
| Puzzle | `68 + n·b` bytes: 452 B for n = 16 with the default 24-byte links |
| Envelope | the puzzle + 60 bytes + the message |
| Secret, a puzzle kept with its key | the puzzle + 40 bytes |
| Checkpoint | 116 bytes |

## Measurements

These are from `leanseal bench latency`, `leanseal bench throughput`, `leanseal gen` and `demo.sh` on a MacBook Air (Apple M4, 10 cores, fanless) and a MacBook Pro (Apple M4 Max, 16 cores), with 32-byte links; the link width changes only the puzzle's size, and with the default 24-byte links the M4 Max built the reference puzzle in 30.0 s. The logs are in [bench-results/](bench-results/), which also has an x86 run on a 4-vCPU AMD EPYC 9554P VM (`x86-epyc-9554p.txt`): 37.4 ns/step for one chain, 173 M steps/s on all four vCPUs. The M4 Air was in use during its runs, so its build times are somewhat pessimistic.

| Quantity | M4 Air | M4 Max |
|---|---|---|
| One chain | 23.2 ns/step (median of 5 runs) | 24.1 ns/step |
| All cores, independent chains | 461 M steps/s | 867 M steps/s |
| Build n = 16, m = 2^30 (17.2 G steps) | 42.1 s | 30.1 s |
| Build n = 32, m = 2^29 | 42.9 s | 19.8 s |
| Five n = 16 puzzles at once | 37.5 s each | |
| Demo: open with the key / solve without it | 12 ms / 6 min 42 s | |

Each core computes two chains at once at about 1.5 times the rate of one. The builder hands out chains in pairs when there are more chains than cores, and one per core otherwise. `bench/metal/` measures the chain step on Apple GPUs; its results are in `bench-results/` as well.

## Threat model

**What leanSeal is meant to give.**

- *Confidentiality until the work is done.* An honest solver needs `n·m` chain steps in sequence. In the random-oracle model, no classical attacker derives the key even one round sooner except with negligible probability (SPEC.md section 8). That a round takes as long as assumed is an assumption about hardware.
- *Integrity, until the key is known.* Any change to an envelope's puzzle, nonce, ciphertext or tag makes opening fail. Once the key is public, revealed or solved, anyone can seal a different message under the same puzzle. So the puzzle and its commitment do not identify a message: refer to an envelope by a hash of all its bytes.
- *A checkable fast path.* A revealed key is checked against the commitment before it is used.

**What the delay rests on.**

- SHA-256 and its compression function behave as random oracles. Under this model, SPEC.md section 8 proves that a classical attacker making `Q_pre` queries before the puzzle exists and `Q_on` after derives the key even one round before the honest solver with probability at most `Q_on/2^(8b) + Q_pre/2^(128+8b) + (QP + P² + 1)/2^256`, where `Q = Q_pre + Q_on` and `P = n(m + 3) + 1`. With the default 24-byte links and a fleet making `R = 10^21` queries per second, about the Bitcoin network, for the whole delay `T` (`Q_on = RT`), this is about `2^-116` for a one-minute puzzle and `2^-97` for a one-year one (`2^-146` and `2^-108` with 32-byte links). The proof is written out but not machine-checked or independently reviewed.
- Nobody computes one chained SHA-256 step much faster than `ℓ`, the fastest attainable latency of one compression on the best hardware. The delay is `n·m·ℓ` seconds, so a faster solver opens the envelope sooner. Set `m` against the fastest attacker you assume, not against your own machine.
- Shorter links weaken the first term of the bound: with 16-byte links it is about `2^-52` for a minute and `2^-33` for a year. leanSeal relies only on this proved bound, so use links of 24 bytes or more; the tool warns when `-b` is below 24. A puzzle with `n = 1` has no hidden link, and its delay rests on the one chain alone.
- There is no analysis of leanSeal's encoding against quantum attackers.
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
| `ref/leanseal_ref.py` | a separate Python implementation that shares no code with the Rust one |
| `bench-results/` | benchmark and demo logs |
| `bench/metal/` | a separate Metal benchmark of the chain step on Apple GPUs |
| `audit/` | the audit reports on the earlier C implementation and what was fixed |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
