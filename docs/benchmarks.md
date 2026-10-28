# Benchmarks

These measurements come from `leanseal bench latency`, `leanseal bench throughput`, `leanseal gen` and `demo.sh`. The raw logs are in [bench-results/](../bench-results/).

## Machines

- MacBook Air, Apple M4: 10 CPU cores, fanless. It was in use during its runs, with background file indexing, so its build times are somewhat pessimistic.
- MacBook Pro, Apple M4 Max: 16 CPU cores.
- A 4-vCPU cloud VM on an AMD EPYC 9554P (Zen 4), for the x86 SHA-NI backend.

## Results

All puzzles below are one-minute locks (`n = 16`, `m = 2^30`, 17.2 G steps). The runs used 32-byte links. The link width changes only the puzzle's size, because every chain step hashes a full 32-byte state: with 24-byte links, the M4 Max built the same puzzle in 30.0 s.

| Quantity | M4 Air | M4 Max |
|---|---|---|
| One chain step, one core | 23.2 ns (median of 5 runs) | 24.1 ns |
| All cores, independent chains | 461 M steps/s | 867 M steps/s |
| Build `n = 16`, `m = 2^30` | 42.1 s | 30.1 s |
| Build `n = 32`, `m = 2^29` | 42.9 s | 19.8 s |
| Five `n = 16` puzzles built at once | 37.5 s each | |
| Open with the key, command-line tool end to end | 12 ms | |
| Solve without the key, one core | 6 min 42 s | |

On the x86 VM, one chain step takes 37.4 ns and all four vCPUs compute 173 M steps/s (`x86-epyc-9554p.txt`).

## The 30-second reference puzzle

The reference puzzle (`m = 2^29`) does half the chain work of the measured one-minute puzzle. Building and solving are linear in the chain work, so the reference figures are half the measured ones:

| Quantity | M4 Air | M4 Max |
|---|---|---|
| Build `n = 16`, `m = 2^29` | about 21 s | about 15 s |
| Solve without the key, one core | about 3 min 21 s | |

These are projections from the one-minute runs, not separate measurements.

## Notes

- Each core computes two chains at once, interleaved, at about 1.5 times the rate of one. The builder hands out chains in pairs when there are more chains than cores, and one per core otherwise.
- `bench/metal/` measures the chain step on Apple GPUs; its results are in `bench-results/`. The GPU reaches its rates only with tens of thousands of chains in flight, so it suits building a stock of puzzles, not one puzzle on demand. The tool does not yet build puzzles on a GPU.
- `bench/eth-sample.py` reproduces the mainnet transaction-size sample used in the paper.
