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

## Building on a GPU

`bench/metal/` measures the chain step on Apple GPUs, one chain per GPU thread, and checks its results against Python's SHA-256 before it reports a rate. The tool itself does not yet build puzzles on a GPU.

A GPU has many more lanes than a CPU but no SHA-256 instructions, so a lone chain is slow: 5.3 µs per step on the M4 Max, more than 200 times one CPU core. The GPU reaches its total rate only with tens of thousands of chains in flight, and a batch is ready only when its chains finish. More chains lower the cost per puzzle but make the whole batch wait longer. For 30-second puzzles (`m = 2^29`) on the M4 Max:

| Chains in flight | 16-chain puzzles | Time per chain step | Batch ready after | GPU time per puzzle |
|---|---|---|---|---|
| 4,096 | 256 | 5.2 µs | 46 min | 10.8 s |
| 16,384 | 1,024 | 7.6 µs | 68 min | 4.0 s |
| 65,536 | 4,096 | 23.4 µs | 3.5 h | 3.1 s |
| 262,144 | 16,384 | 87.5 µs | 13 h | 2.9 s |

The times per step come from 2-second runs (`m4-max-metal.txt`, the final sweep); the batch and per-puzzle times are projected from them, and no full batch was run. In 60- and 70-second runs the GPU held about 3.06 G steps/s for 30 s and then settled near 2.88 G steps/s, so long batches take about 6% longer. Beyond about 65,536 chains the cost per puzzle stops falling, and no batch is ready in less than about 47 minutes, the time of one lone chain. On the M4 Air the GPU reaches 0.71 G steps/s (`m4-air-metal.txt`). The GPU therefore suits building a stock of puzzles, not one puzzle on demand. For the same reason it does not help an attacker, who needs one fast chain.

## Notes

- Each core computes two chains at once, interleaved, at about 1.5 times the rate of one. The builder hands out chains in pairs when there are more chains than cores, and one per core otherwise.
- `bench/eth-sample.py` reproduces the mainnet transaction-size sample used in the paper.
