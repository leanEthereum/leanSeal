# Audit

An AI model, OpenAI's GPT-6 Astra at high reasoning effort, audited chainseal for security and correctness. It read the code and the documents, ran the tests, and wrote scratch programs to reproduce each failure. It had no permission to change the code.

| Round | Commit | Report | Verdict |
|---|---|---|---|
| 1 | `dd063aa` | [round-1.md](round-1.md) | fix first: 4 blockers, 3 major, 5 minor |

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

Test gaps the report named are now covered: the C vector check feeds every invalid vector to the C decoders, and a new fuzz test mutates and truncates valid puzzles, secrets and checkpoints. The SHA-NI backend remains untested on real x86 hardware.
