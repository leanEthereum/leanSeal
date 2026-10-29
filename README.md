# leanSeal

[![CI](https://github.com/leanEthereum/leanSeal/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/leanEthereum/leanSeal/actions/workflows/ci.yml)

leanSeal is time-lock encryption built from SHA-256 alone. A sender encrypts a message under a key and attaches a puzzle. The sender can publish the key at any time; anyone else can recover it by performing a fixed amount of sequential hashing. leanSeal needs no trusted setup, no committee and no cryptographic assumption beyond SHA-256.

Authors: Vitalik Buterin, Quang Dao and Justin Drake.

> **Status: research proof of concept.** The format is specified and tested. Do not use leanSeal to protect anything of value.

## What leanSeal is for

leanSeal is designed as a decryption fallback for **encrypted mempools**. In an encrypted mempool, block builders order transactions before they can read them, so they cannot front-run or sandwich a transaction based on its contents. Once the order is fixed, the transactions must be decrypted. Current designs give this job to one of three parties:

| Who decrypts | What it costs |
|---|---|
| A threshold committee | Privacy depends on the members not colluding; liveness depends on enough of them being online. |
| A trusted execution environment | Privacy depends on the hardware vendor and on side-channel resistance. |
| The sender | The sender sees the order first and can withhold its key if the order is unfavorable. |

leanSeal keeps the sender as the normal decryption path and adds a puzzle as a fallback that needs no third party. After ordering, the sender reveals its key, nodes check it against a commitment, and the transaction decrypts in milliseconds; no puzzle is solved. If the sender withholds its key, anyone can solve the puzzle to recover it.

leanSeal also fits applications that can wait for every commitment to open, such as sealed-bid auctions. It is used there like a *timed commitment*, but without a proof, checked at submission, that the forced opening will succeed.

### What the fallback guarantees

- **Disclosure for honestly built puzzles.** A withheld transaction becomes public even if its sender goes offline or changes its mind.
- **Not execution.** A transaction recovered minutes later may have expired or may revert. Withholding can still delay or cancel execution, so a protocol needs a deposit forfeited on a missed reveal, as with plain commit–reveal.
- **Not puzzle validity.** No efficient check is known that a puzzle opens to its key, and a malformed puzzle costs less to make than a well-formed one, so a strategic sender can keep its option to withhold. The paper adds a bond, forfeited when a forced opening is shown on chain to fail, if necessary by a bisection game, and outlines that game; the proof of concept implements neither.
- **Not lasting confidentiality.** A puzzle opens whether or not its transaction is included, so excluded transactions become readable too. leanSeal protects against front-running; it does not provide the long-term confidentiality that shielded transfers need.

[The paper](docs/leanseal.pdf) analyses these points, and what the puzzle adds over commit–reveal with the same deposit, in Section 6, which also specifies a sealed-bid batch auction and compares it with commit–reveal.

## How it works

leanSeal implements the chained-hash puzzle of Mahmoody, Moran and Vadhan (CRYPTO 2011).

1. The sender draws `n` random links and runs `n` hash chains of `m` SHA-256 steps, one per link, in parallel.
2. The puzzle publishes the first link and hides each later link under a hash of the previous chain's end. The key is a hash of every chain's end, and the puzzle carries a commitment to the key.
3. Without the key, a solver learns each link only by finishing the previous chain, so it must run all `n·m` steps in sequence, however much hardware it has.

The sender therefore waits `m` steps on `n` cores, and everyone else waits `n·m` steps. The message is encrypted and authenticated with HMAC-SHA256 under the key.

## Reference parameters and performance

The figures below are for the reference puzzle: a 30-second lock with `n = 16` chains of `m = 2^29` steps and 24-byte links. Measured figures come from a MacBook Air with an Apple M4 (10 CPU cores, fanless).

| Quantity | Value | Basis |
|---|---|---|
| Delay against the assumed attacker | 30 s | Assumes one chained SHA-256 every 3.5 ns, 3.7 times faster than the fastest published hardware design |
| Chance that an attacker with about the Bitcoin network's hash rate derives the key early | at most about 2<sup>−117</sup> | Proved in the random-oracle model |
| Building the puzzle, all CPU cores | about 21 s | Scaled from measurement; can be done before the transaction exists |
| Opening with the revealed key | 12 ms | Measured; command-line tool, end to end |
| Opening without the key, one CPU core | about 3 min 21 s | Scaled from measurement |
| Added to a transaction | 512 B, or 152 B with precomputed single-chain puzzles | Exact |

The build and solve times are half those measured for a one-minute puzzle, since both scale linearly with the delay. See [benchmarks](docs/benchmarks.md) for the measurements and [the security model](docs/security.md) for the assumptions.

## Quick start

You need Rust 1.80 or later. The full test suite also needs `make`, `sh` and Python 3.11 or later.

```sh
git clone https://github.com/leanEthereum/leanSeal && cd leanSeal
make          # builds target/release/leanseal
make test     # runs the Rust, command-line, test-vector and Python cross-tests
sh demo.sh    # seals a sample transaction and opens it with and without the key
```

Seal a message and open it both ways:

```sh
leanseal gen -d 30s --step-ns 3.5 -o tx.secret    # build a 30-second puzzle in advance
leanseal encrypt -s tx.secret -i tx.bin -o tx.env # seal the message under it
leanseal key tx.secret | leanseal open tx.env -k - -o out.bin   # fast path: the sender's key
leanseal open tx.env --solve -o out.bin           # fallback: solve the puzzle
```

The examples assume `target/release` is on your `PATH`. The [usage guide](docs/usage.md) covers every command, the Rust library and the hardware backends.

## Documentation

| Document | Contents |
|---|---|
| [Paper](docs/leanseal.pdf) ([source](paper/)) | The design as an encrypted-mempool fallback, the security proof, costs, trade-offs and comparison with other designs |
| [SPEC.md](SPEC.md) | The normative byte format, with test vectors |
| [Usage](docs/usage.md) | Building, testing, the command-line tool, the library and the repository layout |
| [Security model](docs/security.md) | What leanSeal guarantees, what the delay rests on and what it does not do |
| [Benchmarks](docs/benchmarks.md) | Measurements on Apple M4 laptops and an x86 server |
| [Prototype mempool](poc/README.md) | An encrypted mempool on an EVM chain: sealed submission, ordered execution and forced opening |
| [Project site](https://leanethereum.github.io/leanSeal/) | Overview |

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
