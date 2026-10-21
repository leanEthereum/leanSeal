# Audit

An AI model, OpenAI's GPT-6 Astra at high reasoning effort, audited chainseal for security and correctness. It read the code and the documents and ran the tests. It reproduced most failures with scratch programs, and established the rest from the source or by arithmetic. It had no permission to change the code.

| Round | Commit | Report | Verdict |
|---|---|---|---|
| 1 | `dd063aa` | [round-1.md](round-1.md) | fix first: 4 blockers, 3 major, 5 minor |
| 2 | `6e764bd` | [round-2.md](round-2.md) | fix first: 9 of the 12 resolved, 3 partly; 4 new blockers, 4 new minor |
| 3 | `8e04201` | [round-3.md](round-3.md) | fix first: 6 of the 8 resolved, 2 partly; 1 new blocker, 3 new minor |
| 4 | `634982f` | [round-4.md](round-4.md) | fix first: R3-1 to R3-4 and R2-6 resolved, R2-1 partly; 1 new blocker, 1 nit |
| 5 | `2d804be` | [round-5.md](round-5.md) | ready: R4-1, R4-2 and R2-1 resolved; no new findings |

## What changed after round 1

| # | Finding | Change |
|---|---|---|
| 1 | Integrity was claimed without limit, but once the key is public anyone can seal a new message under the same puzzle. | README and SPEC section 8 now limit integrity to parties who do not know the key, and say that systems must refer to an envelope by a hash of all its bytes. SPEC section 8 separates the assumptions: HMAC-SHA256 as a PRF for secrecy and the tag, collision resistance for binding. |
| 2 | The delay and the `2^-45` figure were stated for every attack, but the analysis covers only guessing the last link. | README and SPEC section 8 now call `n·m` the honest solver's work, scope the figure to that one attack, say what it does not cover (other guesses, key search, `n = 1`, quantum attackers), and state that the MMV theorem is asymptotic and is not a proof for chainseal. |
| 3 | `chainseal info` accepted checkpoints that section 6 forbids. | A new `cs_checkpoint_peek` checks everything that does not need the puzzle; `info` and the decoder both use it. CLI tests cover a version-2 checkpoint. |
| 4 | Backend selection and forcing were overstated. | The ARMv8 backend now checks the CPU at run time on Linux, and the Makefile enables it for Linux aarch64. `CHAINSEAL_BACKEND` naming an unavailable backend is an error. The README says which backends were run. |
| 5 | The cancellation flag was not atomic. | It is a C11 `atomic_int`. |
| 6 | One failed puzzle in a batch discarded the keys and checkpoints of the others. | `solve` prints every key it found and returns failure if any puzzle failed. A checkpoint is deleted only after its key or plaintext has been written. A CLI test covers a batch with one bad puzzle. |
| 7 | The Python reference wrote secret files with default permissions. | It writes them through an exclusive temporary file with mode `0600`, then renames it. |
| 8 | A chain step and a start hash could hash the same bytes. | The start hash now includes the 32-byte puzzle context, so every labelled-hash input is at least 56 bytes and a chain-step input is exactly 52. This changes the format's values; the test vectors are regenerated. |
| 9 | Allowed parameters overflowed 64-bit step counters. | SPEC section 2 now requires `n·m ≤ 2^60`, and the code enforces it. Progress totals use floating point. |
| 10 | Non-finite delays and step times were accepted. | They are rejected, and the CLI tests cover `inf` and `nan`. |
| 11 | An `fsync` failure leaked a file descriptor. | `fsync` and `close` are now separate, and both always run. The README says checkpoints are not crash-durable. |
| 12 | Two CLI tests could fail by chance. | The tamper test flips a bit instead of writing a byte, and the interrupt test uses a solve that takes seconds on current CPUs, and fails with a clear message if the solve ends before the signal. |

Two test gaps the report named are closed: the C vector check feeds every invalid vector to the C decoders, and a new test mutates and truncates valid puzzles, secrets and checkpoints and checks that whatever decodes re-encodes to the same bytes. Others remain open: there are no fault-injection tests for thread creation or checkpoint writes, and nothing has run on Linux or x86 hardware.

## What changed after round 2

| # | Finding | Change |
|---|---|---|
| R2-1 | `open --solve -o FILE.ckpt` deleted its own output. | `open` refuses an output path that names the checkpoint file, before doing any work. A CLI test covers it. This check missed aliases on case-insensitive filesystems; see R3-1. |
| R2-2 | Checkpoint inspection accepted positions no valid puzzle can reach. | `cs_checkpoint_peek` also requires `i·j ≤ 2^60`. Unit and CLI tests cover `(4097, 2^48)` and the boundary `(4096, 2^48)`. |
| R2-3 | Comparisons with other attacks were stated without support. | README and SPEC now say that guessing the last link leaves the least work among link guesses, say why earlier links do no better, and state that no proof covers other strategies. Cross-puzzle reuse is qualified by fresh random salts. |
| R2-4 | The README said the latency median was over 9 runs. | It is over 5 runs, as the benchmark code does. |
| R2-5 | A huge finite step time overflowed and gave `m = 1`. | The delay is divided in an order that cannot overflow. A CLI test checks the result. |
| R2-6 | The interrupt tests depended on timing. | A real SIGINT now goes to a solve that cannot finish (its `m` is patched to 2^40). The checkpoint-and-resume tests use a test hook, `CHAINSEAL_TEST_STOP_AFTER`, that stops a solve after a set number of steps. The signal could still arrive too early; see R3-3. |
| R2-7 | Sanitizer builds on Linux aarch64 dropped the ARMv8 backend. | The architecture flag is in its own `ARCH` variable, which the sanitizer builds keep. |
| R2-8 | This file overstated the test coverage. | The paragraph above now says which gaps are closed and which remain. |

## What changed after round 3

| # | Finding | Change |
|---|---|---|
| R3-1 | On a case-insensitive filesystem, `-o ALIAS.ENV.CKPT` still deleted the output when no checkpoint existed yet. | After writing the output, `open` removes the checkpoint only if it is a different file from the output, compared by device and inode. This missed output sent to stdout; see R4-1. The early refusal stays. A CLI test covers the case alias when the filesystem is case-insensitive, as it is on macOS by default. |
| R3-2 | Subnormal times gave the wrong `m`. | The delay is divided by the step time before the units are converted, so an underflow can only happen when one step already covers the delay. CLI tests cover two subnormal pairs. |
| R3-3 | The SIGINT test could signal before the handler was installed, and then wait forever. | A second test hook, `CHAINSEAL_TEST_READY=FILE`, creates `FILE` once the handler is installed. The test waits for it before signalling, and a watchdog kills the solve after 60 s. |
| R3-4 | The test suite needed `perl`, which the README listed only for the demo. | The tests patch bytes with Python, which the suite already needs. |

## What changed after round 4

| # | Finding | Change |
|---|---|---|
| R4-1 | With stdout redirected onto the checkpoint (`>> FILE.ckpt`), `open` deleted the file holding the plaintext. | Both the early refusal and the final cleanup now compare the checkpoint with the output's file, and for stdout that is the file stdout is open on. `open` refuses before solving. A CLI test appends stdout to a valid checkpoint and checks the refusal and that the checkpoint is unchanged. |
| R4-2 | Cancelling the test watchdog left its `sleep` running. | The watchdog is one Python process, and an exit trap kills it and the solve if the test stops early. |
