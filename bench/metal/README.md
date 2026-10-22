# Metal benchmark of the chain step

This program measures how fast an Apple GPU computes chainseal chain steps (SPEC.md, section 3):
`F_i(s) = SHA256(s ‖ salt ‖ be32(i))`, one SHA-256 compression per step. It answers two questions:

- **Sender throughput.** How many chained hashes per second the GPU computes across many independent chains.
- **One-chain latency.** How many nanoseconds one step takes when the GPU runs a single chain.

It is a stand-alone measurement tool. It is not part of the `chainseal` crate.

## Build

You need macOS with Xcode command-line tools (`swiftc`) and `python3` on `PATH`.

```sh
swiftc -O main.swift -o chainseal-metal     # or: make
```

## Run

```sh
./chainseal-metal verify                                  # check all kernels against Python hashlib
./chainseal-metal sweep --variant premx1 --tg 64 --secs 2 # throughput for 1 ... 262144 chains
./chainseal-metal tune --chains 65536                     # compare kernels and threadgroup sizes
./chainseal-metal sustain --variant premx1 --tg 64 --chains 1048576 --secs 60
./chainseal-metal source --variant premx1                 # print the generated Metal source
```

Every mode except `source` first runs the correctness check. If the GPU result differs from Python `hashlib`, the program prints the mismatch and exits without reporting a rate.

The correctness check uses a random salt, chain indices 1, 2, 7 and 65539, random start states and `m = 1000` steps. It splits the steps over four dispatches of 300, 300, 1 and 399 steps, committed back to back.

## How it works

- One GPU thread runs one chain. A kernel variant with suffix `x2` runs two chains per thread, interleaved.
- A thread loads its 8-word state, runs `K` steps with the state in registers, and writes the state back.
- The host repeats dispatches until the run time is reached. It keeps three command buffers in flight. It chooses `K` so that one dispatch takes about `--target-ms` of GPU time (default 100 ms), well below the GPU watchdog.
- The shader source is generated as a string by `main.swift` and compiled at run time with `makeLibrary(source:options:)`. The 64 rounds and the message schedule are fully unrolled. Rotations use `rotate()`.
- Words W13 to W15 are literals in the source, so the compiler folds them. The `pre` variants also take the salt-dependent parts of the message schedule (rounds 8 to 11 and words W16 to W31) from a table computed on the host. They compute the parts that depend on the chain index once per dispatch. The `plain` variants leave this to the compiler.
- The `prem` variants also compute Maj(a, b, c) as `b ^ ((a ^ b) & (b ^ c))`, reusing `b ^ c` from the previous round, which saves one operation per round.

## Output

`sweep` and `tune` print one row per configuration:

| Column | Meaning |
|---|---|
| `K` | steps per dispatch |
| `Mh/s` | chained hashes per second (10^6), all chains, from wall-clock time |
| `Mh/s-gpu` | the same, from the summed GPU time of the dispatches |
| `ns/step/ch` | wall-clock time of one step of one chain; for 1 chain this is the GPU latency per step |
| `ms/disp` | average GPU time of one dispatch |

`sustain` prints the rate in 5-second windows, then the rate in the first and last 10 seconds, so that you can see thermal throttling.
