# Audit

AI models audited leanSeal (first named chainseal) for security and correctness. OpenAI's GPT-6 Astra at high reasoning effort did rounds 1 to 9, 11 and 14, OpenAI's GPT-5.6 Sol rounds 10 and 13, and Anthropic's Claude Opus 5.5 round 12. Each read the code and the documents and ran the tests. They reproduced most failures with scratch programs, and established the rest from the source or by arithmetic. None had permission to change the code.

Rounds 1 to 9 audited the C implementation, whose last commit is `ffde496`. A Rust implementation has since replaced it; the review of the port and rounds 10 to 13, which cover the Rust and Python implementations, the paper and the proof of concept, are at the end of this file.

| Round | Commit | Report | Verdict |
|---|---|---|---|
| 1 | `dd063aa` | [round-1.md](round-1.md) | fix first: 4 blockers, 3 major, 5 minor |
| 2 | `6e764bd` | [round-2.md](round-2.md) | fix first: 9 of the 12 resolved, 3 partly; 4 new blockers, 4 new minor |
| 3 | `8e04201` | [round-3.md](round-3.md) | fix first: 6 of the 8 resolved, 2 partly; 1 new blocker, 3 new minor |
| 4 | `634982f` | [round-4.md](round-4.md) | fix first: R3-1 to R3-4 and R2-6 resolved, R2-1 partly; 1 new blocker, 1 nit |
| 5 | `2d804be` | [round-5.md](round-5.md) | ready: R4-1, R4-2 and R2-1 resolved; no new findings |
| 6 | `1893160` | [round-6.md](round-6.md) | fix first, after the key was changed to depend on every chain end: 1 new blocker, 1 new major |
| 7 | `2dd794c` | [round-7.md](round-7.md) | fix first: R6-2 resolved, R6-1 partly; 1 new blocker in the security argument, 1 minor, 1 nit |
| 8 | `c33fa59` | [round-8.md](round-8.md) | fix first: R7-2 and R7-3 resolved, R7-1 partly; 1 new blocker in the security argument, 2 minor |
| 9 | `e042e8c` | [round-9.md](round-9.md) | ready: R8-1 to R8-3 resolved; 2 new minor |

## What changed after round 1

| # | Finding | Change |
|---|---|---|
| 1 | Integrity was claimed without limit, but once the key is public anyone can seal a new message under the same puzzle. | README and SPEC section 8 now limit integrity to parties who do not know the key, and say that systems must refer to an envelope by a hash of all its bytes. SPEC section 8 separates the assumptions: HMAC-SHA256 as a PRF for secrecy and the tag, collision resistance for binding. |
| 2 | The delay and the `2^-45` figure were stated for every attack, but the analysis covers only guessing the last link. | README and SPEC section 8 now call `n·m` the honest solver's work, scope the figure to that one attack, say what it does not cover (other guesses, key search, `n = 1`, quantum attackers), and state that the MMV theorem is asymptotic and is not a proof for leanseal. |
| 3 | `leanseal info` accepted checkpoints that section 6 forbids. | A new `cs_checkpoint_peek` checks everything that does not need the puzzle; `info` and the decoder both use it. CLI tests cover a version-2 checkpoint. |
| 4 | Backend selection and forcing were overstated. | The ARMv8 backend now checks the CPU at run time on Linux, and the Makefile enables it for Linux aarch64. `LEANSEAL_BACKEND` naming an unavailable backend is an error. The README says which backends were run. |
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
| R2-6 | The interrupt tests depended on timing. | A real SIGINT now goes to a solve that cannot finish (its `m` is patched to 2^40). The checkpoint-and-resume tests use a test hook, `LEANSEAL_TEST_STOP_AFTER`, that stops a solve after a set number of steps. The signal could still arrive too early; see R3-3. |
| R2-7 | Sanitizer builds on Linux aarch64 dropped the ARMv8 backend. | The architecture flag is in its own `ARCH` variable, which the sanitizer builds keep. |
| R2-8 | This file overstated the test coverage. | The paragraph above now says which gaps are closed and which remain. |

## What changed after round 3

| # | Finding | Change |
|---|---|---|
| R3-1 | On a case-insensitive filesystem, `-o ALIAS.ENV.CKPT` still deleted the output when no checkpoint existed yet. | After writing the output, `open` removes the checkpoint only if it is a different file from the output, compared by device and inode. This missed output sent to stdout; see R4-1. The early refusal stays. A CLI test covers the case alias when the filesystem is case-insensitive, as it is on macOS by default. |
| R3-2 | Subnormal times gave the wrong `m`. | The delay is divided by the step time before the units are converted, so an underflow can only happen when one step already covers the delay. CLI tests cover two subnormal pairs. |
| R3-3 | The SIGINT test could signal before the handler was installed, and then wait forever. | A second test hook, `LEANSEAL_TEST_READY=FILE`, creates `FILE` once the handler is installed. The test waits for it before signalling, and a watchdog kills the solve after 60 s. |
| R3-4 | The test suite needed `perl`, which the README listed only for the demo. | The tests patch bytes with Python, which the suite already needs. |

## What changed after round 4

| # | Finding | Change |
|---|---|---|
| R4-1 | With stdout redirected onto the checkpoint (`>> FILE.ckpt`), `open` deleted the file holding the plaintext. | Both the early refusal and the final cleanup now compare the checkpoint with the output's file, and for stdout that is the file stdout is open on. `open` refuses before solving. A CLI test appends stdout to a valid checkpoint and checks the refusal and that the checkpoint is unchanged. |
| R4-2 | Cancelling the test watchdog left its `sleep` running. | The watchdog is one Python process, and an exit trap kills it and the solve if the test stops early. |

## What changed after round 6

Commit `1893160` changed the design: the key now hashes the ends of all chains in order, instead of the end of the last chain alone, so that a guess of the last link could no longer be checked against the commitment after one chain. Round 6 audited that change and found that with the raw mask the shortcut survived for `b = 32`; commit `2dd794c` closed it by hashing the mask (R6-1).

| # | Finding | Change |
|---|---|---|
| R6-1 | A link was masked with the first `b` bytes of the previous chain's end, so a right guess of the link revealed those bytes, and with `b = 32` the whole end. One guess could then skip a chain, contrary to SPEC and README. The documents also called one chain the cheapest useful saving, though a guess can save part of a chain. | Links are masked with `TH("leanseal/v1/mask", ctx ‖ y_i)[0:b]`, so a guess reveals part of a hash of the end and nothing about the end itself. SPEC sections 4, 5 and 8, the README and the C and Python code use the new mask; the vectors are regenerated. A unit test checks that with `b = 32` the mask does not stand in for `y_1`. The documents now say that savings of less than a chain follow the same formula, and use one chain only as the example. |
| R6-2 | A cursor returned by a successful `cs_solve` held `a_n` instead of `a_(n−1)`, so solving again from it, or from a checkpoint made from it, failed. | The final absorption uses a temporary copy, and the cursor keeps `a_(n−1)`. A unit test solves puzzles with `n` = 1, 2 and 3, then solves again from the returned cursor and from its checkpoint. |

## What changed after round 7

Round 7 audited `2dd794c`. It found no defect in the code; its blocker is in the security argument.

| # | Finding | Change |
|---|---|---|
| R7-1 | SPEC and README charged each guess the whole saving `d`, giving the bound `Q/(d·2^(8b))`. Runs from different guesses of one link can reach the same later link and then share all later steps. With 1- and 2-byte links, an attacker that tries every value of a link and merges runs that meet recovered the key in 100 of 100 puzzles under a budget for which the bound gave 3.5%. | SPEC section 8, the README and section 4 of the guide now charge each guess `min(d, m)` steps, its first chain, which runs from distinct guesses cannot share. The bound becomes `Q/(min(d,m)·2^(8b))`. The one-chain figures, `2^-45` and Table 2 of the guide, are unchanged. The guide's figure for opening half the delay early is replaced by the two-guess estimate, and the guide says the bound may be loose beyond one chain and that the merging attack shows why. |
| R7-2 | `docs/index.html` at `2dd794c` still described the raw mask. | The page is regenerated from the guide, which uses the hashed mask. |
| R7-3 | This file said `1893160` removed the last-link shortcut, though round 6 showed it had not for `b = 32`. | The round-6 paragraph above now says what `1893160` intended and what `2dd794c` fixed. |

## What changed after round 8

Round 8 audited `c33fa59` and found no attack that beats `Q/(min(d,m)·2^(8b))` by more than a constant factor. Its findings are in the argument and the guide.

| # | Finding | Change |
|---|---|---|
| R8-1 | The guide said that saving more than half needs two right guesses, so the chance is about the square of the one-chain figure. An attacker can instead prepare short starts for every value of a link, which needs no luck. With 2-byte links this beat the squared figure by a factor of about 3,200. The argument also charged each guess the whole saving, though an attack can combine several smaller gains. | The squared figure and the "below 10^-27" estimate are gone from the guide. The guide and SPEC now charge one run's gain `a` at least `min(a, m)` steps, say that this does not prove the bound because gains can combine, and give no separate bound for saving more than half. SPEC and README say what saving more than half needs, without a probability. |
| R8-2 | The guide said merging pays only when an attacker tries a sizable fraction of all link values, but sharing also grows with the number of chains each run covers. | The guide now says that sharing grows with both, and never reaches a run's first chain. |
| R8-3 | The guide gave the honest opener `N + n + 2` rounds, leaving out the mask and accumulator hashes. | It now gives `N + 3n + 1` hash calls, as SPEC does. |

## What changed after round 9

Round 9 audited `e042e8c`, with the new hardware section of the guide, and found no blocker or major finding.

| # | Finding | Change |
|---|---|---|
| R9-1 | Some sentences still moved from one guessed run's cost to the general bound. | The guide's claim box is labelled "not yet proved", the "Guess ahead" bullet states the bound as the claim about every attack, and "Status" names the two sharper formulas the audit defeated. SPEC introduces the `d`-steps-ahead sentence as the single-run case. |
| R9-2 | The circuit model mixed FO4 delays with logic levels and its endpoints could not be reproduced from the stated inputs. | The guide defines FO4, splits the 10–17 FO4 per round into the adder and the assumed rest, shows the arithmetic from 2.75–5.11 ns through 2.85–5.41 ns to 2.9–9.7 ns, and marks the one-FO4-per-level conversion of Intel's 13 levels as optimistic. |

## Review of the Rust port

The Rust implementation replaced the C one at `ffde496`. Its output, file formats and test vectors are byte for byte those of the C tool: `tests/vectors.json` is unchanged, and the Python reference still checks it. A review compared the port with the C code and found six places where the port handled an edge case worse than the C tool.

| # | Finding | Change |
|---|---|---|
| P-1 | When the operating system refused a thread, the port aborted, since the release build aborts on panic. A solve of several puzzles could lose up to 10 seconds of work. | Threads start through one helper that returns an error. Generation continues on the threads that started, with an identical result. A solve saves every checkpoint, as on SIGINT, and exits with "could not start N solver threads". A benchmark reports the error. Tests force the failure after k threads. |
| P-2 | An argument that was not UTF-8 made the tool panic. | Paths stay operating-system strings up to the file system. A text or number option that is not UTF-8 is a usage error, and so is a non-UTF-8 `LEANSEAL_BACKEND`. |
| P-3 | Keys and secret chain values were not overwritten after use, as the C tool did. | The clear links, the chain ends, the encryption and MAC keys and a solve's state are zeroed when dropped, without `unsafe`. |
| P-4 | A bad option printed only the usage hint. | The tool prints getopt-style messages first, such as `invalid option` and `option '--st' is ambiguous`, listing the candidates. |
| P-5 | `bench all` stopped at the first failed section. | It reports the failure, runs the remaining sections and exits 1 at the end. |
| P-6 | `selftest` continued after a backend mismatch. | It stops at the first mismatch and exits 1. |

Three differences from the C tool are deliberate. A broken pipe is reported as an error with exit status 1, where the C tool was killed by SIGPIPE. A key file with a NUL byte is rejected. A number with a leading vertical tab, or the exponent in `2^-00`, is rejected.

Beyond the C tool's tests, a property test decodes 480,000 mutated encodings of puzzles, checkpoints and envelopes, and `cargo-fuzz` ran four targets under AddressSanitizer for about 108 million inputs with no failure. The library forbids `unsafe`; it appears only in the two hardware backends, which call the SHA-256 instructions.

## Rounds 10 to 14

| Round | Commit | Scope | Report | Verdict |
|---|---|---|---|---|
| 10 | `7b04dd7` | the whole repository | [round-10.md](round-10.md) | not production-ready: 1 high if deployed, 2 medium, 3 low |
| 11 | `a90416a` | the Rust and Python implementations | [round-11.md](round-11.md) | fix first: 1 major, 4 minor |
| 12 | `a90416a` | the proof of concept | [round-12.md](round-12.md) | fix first: 1 major, 3 minor |
| 13 | `b1bdcd6` | the paper and the whole repository | [round-13.md](round-13.md) | changes before a release: 1 major, 2 low; no error in the construction or the proof |
| 14 | `d125bd9` and an uncommitted revision | the paper's answer to an outside critique | [round-14.md](round-14.md) | approved on the third pass; 9 major and 4 minor, then 4 major and 3 minor, then 2 minor |

Round 10 found no break of the construction, no mismatch between the specification and the Rust implementation, and no error in the proved bound. Its findings are in the proof of concept, the erasure of secrets, one sentence of the paper and CI.

| # | Finding | Change |
|---|---|---|
| R10-1 | `sealnet` took private keys on the command line, where shell history and process listings expose them. | Every role reads its key from `--key-file`, which must not be readable by group or others; the bytes are zeroed after parsing. `demo.sh` writes the keys into a private temporary directory and removes it on exit. |
| R10-2 | The node's signer depends on crypto-bigint 0.5, subject to the timing advisory RUSTSEC-2026-0387. | Not fixed: alloy 2.5.0, the latest release, still uses k256 0.13 and with it crypto-bigint 0.5. The PoC README names the advisory under its limits, and CI audits the node with this one advisory ignored by ID. |
| R10-3 | The inbox accepted submissions before its target allowlist was fixed, and ran calls to any target while it was not. | `submit` reverts with `NotRestricted` until `restrictTo` has run, and an account call to a target off the list fails. No unrestricted path remains. |
| R10-4 | HMAC left its key copies, pads and SHA-256 state unerased, and CLI keys and plaintexts were zeroed only on the success path. | HMAC keeps its buffers in zeroing wrappers, and SHA-256 state is zeroed when dropped. CLI keys and plaintexts are held in a wrapper that zeroes them on every return path. `docs/security.md` says which copies remain. |
| R10-5 | Assumption A3 stated the `2^52` margin for the bound in general, though it holds only for the reference puzzle. | A3 and the sentence that uses it now say "the reference puzzle". |
| R10-6 | CI ran only the core crate. | CI now checks the contracts' format and tests, builds, lints and tests the node, and audits both dependency trees. A weekly workflow fuzzes the four decoders under AddressSanitizer for ten minutes each. |

| # | Finding | Change |
|---|---|---|
| R11-1 | On a case-insensitive file system, `--secret-out` could name the new envelope file in another case, and the secret replaced the envelope, in both the Rust CLI and the Python reference. | Both check again once the envelope exists, by file identity, and refuse before writing the secret. CLI and cross tests cover the alias when the file system is case-insensitive. |
| R11-2 | `solve` with stdout appended to the checkpoint deleted the file holding the key. | `solve` refuses that before solving, as `open` does, and never deletes a checkpoint that stdout points at. A CLI test checks the refusal and that the checkpoint is unchanged. |
| R11-3 | After a solve finished, SIGINT and SIGTERM no longer stopped a process blocked on its output. | Once solving ends, both signals take their default action again. |
| R11-4 | The Python alias test failed on a parameter check before reaching the alias check. | It passes valid parameters and checks for the alias error message. |
| R11-5 | The damaged-checkpoint test sometimes wrote the byte that was already there. | It flips a bit, so the checkpoint always changes. |

| # | Finding | Change |
|---|---|---|
| R12-1 | A builder that kept an honest sender's pending reveal out of the window held the key while the ticket missed, and could trade around the ticket when a forced opening queued it later. | A missed ticket never runs: `forceOpen` publishes the key and pays the bounty, and the call stays cancelled. The README and the paper state the remaining censorship assumption: the window must exceed the number of consecutive blocks one builder controls. |
| R12-2 | The demo token's `mint` was public, so anyone could freeze the pool or drain it. | Only the deployer can mint. |
| R12-3 | The keeper's default batch could exceed the 128 KiB transaction size limit and was then retried unchanged. | Batches stay under 120 KiB of calldata, unrevealed tickets get empty bytes, and the keeper halves the batch after a refusal or a revert. |
| R12-4 | `sealnet send` reported a reveal without checking that it succeeded. | `send` fails if the reveal reverted, and does not reveal once the window has passed, since the key would become public in a failed transaction. |

The contracts' 32 tests and the node's tests pass, and the demo runs end to end: the plaintext swap loses 9.25%, the sealed swap executes at the fair price, and the withheld key is published while the swap does not run.

Round 13 audited the fixes of rounds 10 to 12 together with the paper. It found the construction, the format, the three implementations and the proof consistent, and recomputed every bound in the paper.

| # | Finding | Change |
|---|---|---|
| R13-1 | `encrypt --secret-out` published the envelope before saving the secret, so a secret that could not be saved left an envelope that only solving could open. | Both CLIs save the secret first, check again for an alias, and only then write the envelope. On an alias they remove the secret they created, leaving neither file. The alias tests now require that no file is left, and new tests check that a secret path in a missing directory leaves no envelope. |
| R13-2 | `sealnet send --expiry` added the offset to the block number with wrapping arithmetic. | The sum is checked, and the offset is rejected before the puzzle is built. A unit test covers `u64::MAX`. |
| R13-3 | The paper compared queries, each one compression, with Bitcoin hashes, each two. | The paper says so, and gives the bound in compressions: one bit worse, `2^-116` for 30 seconds. The abstract, introduction, README and security guide say "about" the Bitcoin network's hash rate. |

Round 14 reviewed a revision of the paper that answers an outside critique, before it was committed, in three passes. The revision is the commit that adds this report.

| Pass | Findings | Change |
|---|---|---|
| 1 | Theorem 2 let the attacker compute without limit outside the oracles, where HMAC is. | The theorem bounds that computation by `t`, and `δ` is a PRF advantage for that time; the appendix gives the reduction's simulation cost. |
| 1 | The bisection game, its deadlines and the solvers' pay were not specified, and designation did not stop a sender from paying itself. | The paper outlines the game: the initial state comes from the puzzle, the claimant posts the final state, each challenger plays its own game, and every move has a deadline. Solvers come from a staked registry, are paid for a timely outcome, and the penalty is stated net of every payment the sender's coalition can recover. |
| 1 | The auction lacked a bid format, a clearing rule, admission limits and an exposure rule, and a late key let a sender induce a full solve for the deposit alone. | The auction specifies supply per batch, a validity predicate, limits on work and length, exposure tied to finality, exclusion of invalid bids and a uniform-price clearing rule. The denial-of-service text prices a solve against the net deposit. |
| 1 | The abstract said the auction removes the option to withhold; the commit–reveal baseline used the whole escrow; the hiding summary dropped `q`; exactly 2.5 times faster does not open before 12 s; other documents were stale. | The abstract and introduction say what the bond does and does not do; the baseline is a deposit `d + B`; the summary keeps the nonce and `P'` terms; the example is 11.2 s at 1.3 ns; SPEC, the security guide, the README and the shipped PDF are updated. |
| 2 | The solver deadline ended before a claim could stand; a failing tag was not a payable outcome; the last step compared a hash the challenger never posts; keys could be revealed before the bids were final; admission did not fix the work or the link width; the theorem summaries misplaced the factor two. | The deadline is for submission, and a timely claim keeps the assignment; a failing tag is payable; the last step compares only with the claimant's hash; reveals start at finality; admission requires `nm = 2^33`, `n ≤ 16` and `b = 24`; SPEC gives the bound in full. Settlement takes at most 10, 20 or 158 minutes from assignment. |
| 3 | The compression count needed a bid length; the table did not say when the settlement clock starts. | Bids are 96 bytes, checked in at most 17 compressions; the table measures from the first assignment. |

The game remains an outline: its encodings, gas costs and behavior under censored moves are open (paper, Section 8). The proof of concept implements neither the bond nor the game.
