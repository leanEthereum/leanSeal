# Using leanSeal

This guide covers building and testing leanSeal, the command-line tool, the Rust library and the layout of the repository. For what leanSeal is and why, start with the [README](../README.md).

## Build and test

### Prerequisites

- Rust 1.80 or later, on a POSIX system.
- For the full test suite: `make`, `sh` and Python 3.11 or later.
- For `demo.sh`: `xxd` and `perl`.

Continuous integration runs the tests on Linux x86-64, Linux aarch64 and macOS on Apple silicon.

### Make targets

```sh
make            # cargo build --release: target/release/leanseal
make test       # cargo tests, CLI tests, test vectors, Python cross-check
make bench      # latency, throughput, build time against n, toy attack
make paper      # build the paper and copy it to docs/leanseal.pdf (needs latexmk)
sh demo.sh      # time-lock the EIP-155 example transaction, open it both ways
```

`demo.sh` uses 16 chains of 2^22 steps by default, which solve in about 1.5 s. Run `sh demo.sh CHAINS STEPS` for other parameters.

### Fuzzing

The four decoders are fuzzed with cargo-fuzz:

```sh
cd fuzz && cargo +nightly fuzz run puzzle    # likewise: envelope, secret, checkpoint
```

`tests/decode_props.rs` runs the same checks on every `cargo test`.

## SHA-256 backends

The tool selects an accelerated backend when the CPU supports one, and the portable backend otherwise.

| Backend | Hardware | Detection |
|---|---|---|
| `armv8-sha2` | ARMv8 CPUs with the SHA-2 instructions | Built on every aarch64 target; used only if the CPU reports the instructions at run time |
| `x86-sha-ni` | x86-64 CPUs with the SHA extensions | CPUID |
| `portable` | Any CPU | Always available |

To force a backend, set `LEANSEAL_BACKEND=portable`, `armv8-sha2` or `x86-sha-ni`. The tool refuses a backend that the build or the CPU does not support. `leanseal selftest` checks every available backend against plain SHA-256. The accelerated backends are the only `unsafe` code in the crate.

## Command-line tool

`make` leaves the tool at `target/release/leanseal`. The examples assume that it is on your `PATH`; `cargo install --path .` installs it in `~/.cargo/bin`. Run `leanseal help` for the full option list.

### Sender

```sh
# Build a puzzle in advance. 16 chains of 2^29 steps give a 30-second delay
# against an attacker at 3.5 ns per step; on an Apple M4 this takes about 21 s
# on all cores, and about 3.3 minutes to solve on one core.
leanseal gen -n 16 -m 2^29 -o tx.secret

# Or choose m for a target delay against a stated solver speed.
leanseal gen -d 30s --step-ns 3.5 -o tx.secret

# When the message is ready, encrypt it under the stored puzzle.
leanseal encrypt -s tx.secret -i tx.bin -o tx.env

# Publish the key to let everyone open the envelope at once.
leanseal key tx.secret               # prints 64 hex digits
```

`-d` accepts a number of seconds or a suffixed duration such as `90`, `30s`, `10m` or `2h`. Without `--step-ns`, the delay is measured against this machine's speed for one chain, which is far slower than the assumed attacker. Set `--step-ns` to the fastest solver you want to resist.

### Receiver

```sh
# Fast path: open with the published key.
leanseal open tx.env -k <key> -o tx.bin

# Fallback: solve the puzzle. Ctrl-C saves progress to tx.env.ckpt, and
# running the command again resumes from there.
leanseal open tx.env --solve -o tx.bin

# Solve several puzzles at once, one core each.
leanseal solve a.env b.env c.env
```

`-k` takes the key as 64 hex digits, as a file holding them, or as `-` to read it from standard input. Other local users can read a command's arguments while it runs, so pass a key that is not yet published in a file or on standard input:

```sh
leanseal key tx.secret | leanseal open tx.env -k - -o tx.bin
```

`leanseal info FILE` describes any leanSeal file: a puzzle, an envelope, a secret or a checkpoint.

### Puzzle options

| Option | Meaning | Default |
|---|---|---|
| `-n`, `--chains N` | Number of chains | 16 |
| `-m`, `--steps M` | Hash steps per chain, for example `2^29` | none; give `-m` or `-d` |
| `-d`, `--delay T` | Choose `m` for a delay of `T` | |
| `--step-ns L` | Solver speed for `-d`, in ns per step | this machine |
| `-b`, `--link-bytes B` | Link width in bytes | 24 |
| `-j`, `--threads J` | Build threads | all cores |

The tool warns when `-b` is below 24; see the [security model](security.md#link-width).

## Rust library

The crate is not on crates.io. Depend on it from Git:

```toml
[dependencies]
leanseal = { git = "https://github.com/leanEthereum/leanSeal" }
getrandom = "0.2"   # used below to draw the nonce
```

Every envelope sealed under one key needs a fresh nonce.

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

## File sizes

| Item | Size |
|---|---|
| Puzzle | `68 + n·b` bytes: 452 B for `n = 16` with 24-byte links, 92 B for `n = 1` |
| Envelope | the puzzle + 60 bytes + the message |
| Secret (a puzzle kept with its key) | the puzzle + 40 bytes |
| Checkpoint | 116 bytes |

## Repository layout

| Path | Contents |
|---|---|
| `SPEC.md` | The normative format |
| `src/hash.rs` | Portable SHA-256, HMAC-SHA256 and labelled hashes |
| `src/backend/` | The chain step: ARMv8, x86 SHA-NI and portable backends |
| `src/puzzle.rs`, `src/envelope.rs` | Puzzles, solving, checkpoints, secrets and envelopes |
| `src/runtime.rs` | Parallel generation and solving of several puzzles |
| `src/rng.rs` | A seeded generator for test vectors only; OS randomness comes from `getrandom` |
| `src/main.rs`, `src/benchmark.rs`, `src/vectors.rs`, `src/signal.rs` | The command-line tool |
| `tests/` | Library and CLI tests, decoder property tests, shell tests, cross-tests and `vectors.json` |
| `fuzz/` | cargo-fuzz targets for the four decoders |
| `ref/leanseal_ref.py` | An independent Python implementation that shares no code with the Rust one |
| `bench/`, `bench-results/` | Benchmark scripts, a Metal benchmark for Apple GPUs, and their logs |
| `paper/` | LaTeX source of the paper |
| `poc/` | The encrypted-mempool prototype: Solidity contracts and Rust daemons |
| `docs/` | The project site, the paper PDF and these documents |
| `audit/` | AI audit reports on the C and Rust implementations, the paper and the proof of concept, and the fixes |

leanSeal was developed under the name chainseal. The first nine reports in `audit/` and the logs in `bench-results/` predate the rename and use the old name, labels and magic bytes. The format was renamed before any release, so v1 uses the `leanseal/v1/` labels and the `LS` magic bytes throughout.
