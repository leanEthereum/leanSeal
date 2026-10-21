# chainseal v1 — round 2 audit

Audited `6e764bd233e9c22a9492625902d4f52326b5fb98`, including the changes since `dd063aa`, on 2026-10-21. **Fix first:** nine round-1 findings are resolved and three are partly resolved. The revised start hash and work limit agree across C, Python, SPEC and the regenerated vectors; all three requested test targets pass on Apple M4. However, a new cleanup regression can delete successfully written plaintext, checkpoint inspection still accepts globally impossible positions, and several security and measurement claims remain false or overstated. Thus the requested claim that this is a correct, complete PoC with every documented claim true is not yet justified. The severity convention below follows the brief: a false README/SPEC claim or format-conformance failure is a blocker even if its practical impact is limited. This audit changes only this report; it does not repair the implementation.

## Disposition of the 12 round-1 findings

“Resolved” refers to the original failure, not to every possible defect in the surrounding feature. New regressions and remaining qualifications follow the table.

| # | Round-1 finding | Status | Evidence at this commit |
|---|---|---|---|
| 1 | Unqualified integrity after key recovery | resolved | Repeated the case-2 replacement-message forgery: C and Python still accept it, as they should; README:87 and SPEC:183–185 now explain the key-publication exception, whole-envelope binding and separate cryptographic assumptions. |
| 2 | Universal sequential-work / opening-probability claims | partly resolved | Honest work, the named attack, `n=1`, quantum limitations and the absence of a concrete theorem are now distinguished; the numerical calculation is correct, but the remaining “only known,” “most work” and “far less likely” assertions fail as explained in finding R2-3. |
| 3 | Invalid checkpoints accepted by `info` | partly resolved | The original version-2/reserved-byte/zero-index/maximum-`j` input now exits 1; the new validator nevertheless accepts `i=4097,j=2^48`, impossible under the new work limit (R2-2). |
| 4 | Backend availability and forcing | resolved | On M4, unavailable `x86-sha-ni` and an unknown name now exit 2; `portable` succeeds. Linux aarch64 gets a build flag and an `AT_HWCAP` SHA2 check; real Linux/x86 execution is explicitly disclaimed. See R2-7 for sanitizer-build coverage. |
| 5 | Non-atomic cancellation flag | resolved | Repeated the injected second-`pthread_create` failure under TSan: the first worker stops, the command exits 1, and there is no race report. `g_stop` is now atomic; native `atomic_int` is lock-free on the audited M4. |
| 6 | Successful batch results discarded | resolved | Repeated the valid-plus-bad-commitment batch with an existing valid checkpoint: exit 1, the correct successful key is printed, then its checkpoint is removed. Failed plaintext writes and failed tags retain an existing checkpoint. The new cleanup alias regression is R2-1. |
| 7 | Public Python secret files | resolved | Under umask `022`, new and replacement secrets are `0600`; a destination symlink is replaced without modifying its target. Injected Python `fsync` failure closes the descriptor, preserves the old destination and removes the temporary file. |
| 8 | Chain-step / start-hash input overlap | resolved | C and Python starts agree for every `b=1..32`; the old `b=13` byte-equality construction no longer works. Minimum start input is 56 bytes, versus the chain step's 52. |
| 9 | Work-count overflow | resolved | C/Python reject `(n,m)=(2^20,2^48)` and `(4097,2^48)`, accept `(4096,2^48)` and `(2^20,2^40)`, and reject `(2^20,2^40+1)`. Per-puzzle counts are bounded by `2^60`; batch presentation totals now use floating point. |
| 10 | Non-finite timing inputs | resolved | Old `60/inf`, `inf/inf`, `nan/25`, `60/nan` delay/step-time cases and overflowing duration suffix `1e308h` all exit 2. A distinct finite-intermediate overflow remains (R2-5). |
| 11 | Descriptor leak on failed `fsync` | resolved | Repeated the C `fsync=EIO` injection: `write_file` returns failure and `fcntl` confirms the descriptor is closed. The original error is preserved; README:104 now disclaims directory crash durability. |
| 12 | Chance-dependent CLI tests | partly resolved | XOR guarantees a changed tag. Both interruption tests still depend on sleeping 0.5 seconds before signalling a fixed amount of work; increasing the work reduces but does not eliminate the timing assumption (R2-6). |

## New findings and remaining defects

### R2-1. blocker — Checkpoint cleanup deletes the requested plaintext output

**Location:** `src/cli.c:525–526` (`cmd_open`).

**Failure scenario, reproduced:** save a valid vector envelope as `alias.env`, with no existing checkpoint, then run:

```sh
chainseal open alias.env --solve -q -o alias.env.ckpt
```

The command solves and authenticates successfully, writes the plaintext to the requested output, unlinks that same pathname as checkpoint cleanup, and exits **0**. The output no longer exists. The delayed deletion introduced to fix round-1 finding 6 creates this regression; ordinary output files and successful batch stdout do not reveal it.

**Suggested fix:** prevent checkpoint cleanup from removing the plaintext destination. Reject conflicting paths before doing work, or make cleanup explicitly aware of the final output path, including equivalent spellings through `.`/parent-directory aliases. Add a CLI regression asserting both successful status and retained plaintext for this case.

### R2-2. blocker — Checkpoint inspection overlooks the joint work bound

**Locations:** `src/chainseal.c:320–326`; `src/cli.c:580–588`; `SPEC.md:35`; `audit/README.md:15`.

**Failure scenario, reproduced:** take any 84-byte valid checkpoint, keep its magic/version/reserved bytes, and encode `i=4097` at offset 40 and `j=2^48` at offset 44. `chainseal info` exits 0 and describes it as a checkpoint. Both individual bounds pass `cs_checkpoint_peek`.

Any corresponding puzzle would require `n>=4097` and `m>=2^48`, hence `n*m>2^60`; no valid puzzle can have this position. This can be rejected without knowing the puzzle, contrary to the change log's claim that the function checks everything independent of the puzzle. The ordinary decoder against a valid puzzle still rejects the position; this is an inspection/conformance defect, not an authentication bypass.

**Suggested fix:** after validating nonzero `i`, reject `j > CS_MAX_WORK / i` as well as the individual bounds. Test both this impossible position and the boundary `i=4096,j=2^48`. Explain that matching the ID and checking the particular puzzle's tighter bounds still require the puzzle.

### R2-3. blocker — The remaining attack comparisons are false

**Locations:** `README.md:58,93`; `SPEC.md:180`; related precomputation wording at `SPEC.md:58` and change-log claim at `audit/README.md:14`.

**Concrete counterexamples:**

- “The only known way to skip work is to guess a hidden link” omits guessing the 32-byte key and checking its commitment, an attack that SPEC:180 itself acknowledges. A correct key guess skips all chains; guessing the last link still performs one. Thus “the attack that skips the most work” is also not literally correct without restricting the comparison to hidden-link guesses.
- For any puzzle with `n>=3`, guess `x_(n-1)` and run the last two chains. Guessing the actual link has probability `2^(-8b)`, exactly as for `x_n`; it costs `2m` rather than `m` steps. Where two chains fit within the available time, a fixed aggregate step budget gives roughly half as many trials, not a cryptographically “far less likely” attack. This applies at recommended `b=12` too. It does not break the default parameters, but it disproves the comparative claim and prevents interpreting the one-attack estimate as a justified estimate for all remaining attacks.
- The unqualified statement that salt/index “rules out reusing precomputed chain segments” needs a freshness qualification. With the same salt and index, the step function is identical across puzzles, including puzzles with different `n`, `m` or `b`. Adding `ctx` to the start does not add it to each step. Fresh independent random salts make reuse across unrelated puzzles unlikely; they do not make it impossible, nor rule out targeted precomputation after publication.

The last-link arithmetic remains correct in its intended blind-guess model: at `R=10^21,T=60,m=2^25`, `log2(R*T/(m*2^(8b)))` is `-29.3326194`, `-37.3326194`, and `-45.3326194` for `b=10,11,12`. Eleven bytes is the minimum integer width meeting the quoted `2^-32` target for that attack. This is not a new practical attack or evidence that the numerical arithmetic is wrong.

**Suggested fix:** say “among blind hidden-link guesses, guessing the last link minimizes the number of remaining chains.” Remove the unsupported comparison with all other shortcuts; retain the explicit limitation to that attack and the absence of a concrete security theorem. Qualify cross-puzzle precomputation isolation by fresh, independent salts. An overall bound would need to account for earlier-link guesses and other events rather than dismissing them.

### R2-4. blocker — The claimed number of latency samples is wrong

**Locations:** `README.md:75`; `src/bench.c:53–56`.

**Failure scenario, established from the benchmark source:** the README attributes its one-chain median to nine runs of `chainseal bench all`. The benchmark collects **five** samples in `r[5]`, sorts five values and prints `r[2]`. The archived `23.27` median and `23.07` best explain the rounded `23.3` and `23.1`, but do not support “median of 9 runs.” The benchmark at the original audited commit also used five.

**Suggested fix:** change the sample count to five, or supply and accurately identify a separate nine-sample measurement. This is a documentary blocker under the brief's every-claim-true criterion, not a cryptographic weakness.

### R2-5. minor — Finite timing inputs can still collapse the requested work

**Location:** `src/cli.c:124–126`.

**Failure scenario, reproduced:**

```sh
chainseal gen -q -n 64 -d 1e308 --step-ns 1e308 -o overflow.sec
```

Both arguments are finite and accepted. The command succeeds with encoded `m=1`. In real arithmetic the requested formula gives `ceil(1e308/(64*1e308*1e-9)) = 15,625,000`, with total work `10^9`, inside the permitted range. The intermediate `64*1e308` overflows to infinity before multiplication by `1e-9`; division yields zero, which is silently clamped to one. These are extreme, physically unrealistic latency inputs, but they expose the remaining unchecked-intermediate error in the timing conversion.

**Suggested fix:** compute with a numerically safe ordering/scaling and validate intermediate results, or reject values outside a documented supported numeric range. Add a finite-overflow case beside the `inf`/`nan` tests.

### R2-6. minor — Interrupt tests remain dependent on scheduling and CPU speed

**Locations:** `tests/cli.sh:74–83,93–96`; `audit/README.md:24`.

**Failure scenario, established from the test:** let the child finish its fixed `2^27` steps before the parent executes `kill`, either on faster hardware or because the parent is descheduled after starting it. The first test fails despite correct solving; the second can fail at `kill` or the subsequent missing-checkpoint `mv`. The comment that finishing first requires a core six times faster than M4 ignores arbitrary scheduling delay. Only the first interrupt has the new explicit diagnostic.

The two tests passed here. The change log accurately describes increased work and a diagnostic, but that is only a mitigation of the original finding.

**Suggested fix:** coordinate interruption with an observable running state and enough controlled work, preferably a bounded test hook that waits for the signal. Retain a timeout for hangs. Do not make successful signal delivery depend on a fixed sleep being shorter than a benchmark prediction.

### R2-7. minor — Linux ARM sanitizer builds omit the new accelerated backend

**Locations:** `Makefile:7–8,41,47`; `src/chain.c:54`; `README.md:16,23`.

**Failure scenario, established by make expansion and compiler preprocessing:** on Linux aarch64 the normal recipe appends `-march=armv8-a+crypto` to `CFLAGS`. Both sanitizer targets pass `CFLAGS=...` on the recursive make command line, which overrides that ordinary assignment/append. With a baseline compiler whose default target lacks SHA2, `__ARM_FEATURE_SHA2` is then absent and the ARM backend is compiled out. Sanitizers can pass while testing only the portable backend on a SHA2-capable Linux ARM machine.

I reproduced the recipe difference using a scratch `uname` shim reporting Linux/aarch64, and checked that baseline `clang -target aarch64-linux-gnu` lacks the SHA2 macro while adding `-march=armv8-a+crypto` defines it. This is a build-plan/preprocessor check, not a real Linux execution result. Apple M4 sanitizer runs do include ARM and are unaffected.

**Suggested fix:** preserve required architecture flags independently of overridable optimization/sanitizer flags, ideally isolating accelerated functions with appropriate targeting. Assert the expected available backends in a Linux ARM CI job so silent loss of coverage is visible.

### R2-8. minor — The audit change log overstates test coverage

**Locations:** `audit/README.md:3,26`; `tests/test.c:431–489`; `tests/cli.sh:68–72`.

**Failure scenario, established by comparing the round-1 gaps with the new suite:** “Test gaps the report named are now covered” is broader than the changes. There are still no committed fault-injection tests for partial thread creation or failed checkpoint writes, no maximum-work counter regression, no Python secret-mode assertion, and no real Linux/ARM-dispatch or x86 run. The mixed-batch test checks the emitted key but starts without checkpoints for those tiny jobs, so its absent-checkpoint assertion does not establish correct cleanup of a pre-existing checkpoint. The new output-alias defect and impossible-position case also escape the suite.

The new decoder test is useful: it seeds puzzle, secret and checkpoint decoders with their own valid encodings, truncates and appends bytes, mutates fields, and checks that accepted objects re-encode identically. That is a canonical-decoding property, not an independent oracle that every accepted byte string satisfies every SPEC constraint. The C invalid-vector check now genuinely invokes the relevant decoders/open routine and propagates unexpected acceptance to command failure. Both are substantive improvements, but neither establishes comprehensive malformed-input coverage. Likewise, round-1 findings included mathematical and source-level counterexamples; the statement that scratch programs reproduced “each failure” overstates the evidence recorded in that report.

**Suggested fix:** say which gaps were closed and which remain, distinguish source/arithmetic evidence from execution, and add targeted regressions for the failure paths. Do not describe passing mutation/canonicality checks as exhaustive decoding validation.

## Verification, format agreement and claim reconciliation

All builds and executable probes were made from copies under `/tmp/chainseal-audit2.KvFR4v`, leaving the reviewed source untouched. Environment: Apple M4, arm64 Darwin 27, Apple clang 21.0.0. The report includes the relevant inputs and reasoning; its findings do not depend on retaining scratch files.

| Check run | Result and limits |
|---|---|
| `make test` | Passed: 1,779 unit checks, ARMv8/portable self-tests, 200 shared-code SHA-NI emulation cases, exact vector regeneration, CLI tests, Python's 7 valid/51 invalid vectors, and bidirectional cross-language tests. |
| `make sanitize` | Passed the same target under ASan/UBSan on M4, including ARM and portable backends. |
| `make tsan` | Passed 1,779 unit checks with the target's 2,000 fuzz iterations and the CLI suite. Separately reran the original partial-thread-creation failure under TSan successfully. |
| x86 compile | `clang -target x86_64-apple-macos11 -std=gnu11 -O3 -Wall -Wextra -Wshadow -c src/chain.c` succeeded. This compiles the real intrinsics; it does not execute them. |
| Targeted probes | Repeated the forgery, malformed checkpoint, forced-backend, mixed-result/resume, file-mode, hash-domain, parameter-bound, non-finite-input and descriptor-failure checks described above; also tested output/tag failure retention and Python failed-write cleanup. |

The following parts check out:

- **Changed format:** `ctx` is exactly version, `b`, zero reserved bytes, `n`, `m`, salt, in the specified encodings. Both implementations use it in the start, key and commitment hashes. Generation and resumed solving use the same revised start function. C and Python enforce `n*m<=2^60`; C's division guard occurs after checking nonzero `n`, avoiding multiplication overflow. The accepted boundary values were checked without evaluating astronomical chains. The new vector values are consistent across implementations. This intentionally changes old v1 values without changing the version byte; it is not backward compatibility with round-1 artifacts.
- **Domain separation:** minimum unpadded SHA-256 input lengths for start/key/commit/enc/mac/puzzle-id are respectively **56/81/84/65/65/92 bytes**. The chain input is 52. HMAC's shortest inner input here is `64+8=72` bytes, and its outer input is 96; all its keys are 32 bytes, so the long-key preprocessing hash is not invoked. SPEC §3's format-specific length claim is therefore true. Distinct length-prefixed labels and unambiguous parameter encodings separate the labelled hashes. This length argument is not a proof that SHA-256 behaves as independent random oracles.
- **Encryption and parsing:** the context/key commitment, nonce-derived distinct subkeys and whole-envelope HMAC coverage remain consistent. Commitment/tag checks precede plaintext release. Message-length and allocation bounds, exact-length decoding and constant-time comparisons remain intact. No new input-driven memory-safety defect was found. Nonce reuse exposes plaintext XOR as documented; random nonce and salt uniqueness are probabilistic. Full 32-byte commitments have the stated generic birthday-collision scale. The external envelope-binding requirement and reuse/publication-clock warning are appropriate.
- **Concurrency and files:** successful worker results are consumed after joins; the new `solved` marker distinguishes completed successes from unstarted jobs. The cancellation flag fixes the reproduced race. Signal-handler atomic stores are appropriate on the audited lock-free target; an explicit lock-free requirement would strengthen portability assurance. C's failed-sync cleanup now closes the file, and Python uses exclusive private temporary files and atomic replacement. Neither supplies directory crash durability. Secret erasure is still partial, as README now says; the raw key-file buffer is additionally wiped in this revision.
- **SHA-NI and dispatch:** the SHA-NI arithmetic was extracted unchanged into `src/chain_shani.h`; the emulator includes that actual implementation, rather than a second transcription. The ABEF/CDGH conversion, alternating `sha256rnds2` calls, `msg1`/`msg2` schedule, feed-forward and conversion back to natural word order are consistent with the standard flow. CPUID checks SHA, SSSE3 and SSE4.1. The Linux ARM check uses `getauxval(AT_HWCAP)`/`HWCAP_SHA2`, the kernel's advertised feature mechanism ([kernel documentation](https://cdn.kernel.org/doc/html/latest/arch/arm64/elf_hwcaps.html)). **I believe the SHA-NI implementation is correct**, but neither emulation nor cross-compilation substitutes for running it on real hardware. Backend selection is a fixed preference for the available accelerated implementation, not a runtime measurement proving the README's literal “fastest” superlative on every CPU. Library `chain_best` still falls back for an invalid override; the header documents that behavior, while the CLI enforces the advertised refusal.

The README's size formulas and examples are correct: `68+n*b`, 836 and 6,212 bytes for the stated puzzles, envelope overhead 60, secret overhead 40, checkpoint 84. `64*2^28` and `512*2^25` both equal `17,179,869,184` steps. At 23.1 ns/step this is 396.855 seconds, or about 6.6 minutes; the archived 64-chain build throughput gives about 40.6 seconds. The separate new demo log supports 36.9 seconds building, 7 ms fast opening and 6 min 37 s solving. Archived speedups support 9.6, 9.9 and the stated 10.8–11.3 range; 465 M steps/s and the asymptotic ratio about 10.8 are rounded appropriately. R2-4 concerns the sample count, not these numerical values. SPEC §9's parameter rule and cost/size estimates are appropriate within §2's limits and the stated latency assumptions; they are approximations excluding small setup/encryption costs, not guaranteed wall-clock delay.

The MMV dependency structure remains recognizable, and the revised discussion correctly separates its asymptotic random-oracle theorem from a concrete guarantee for this instantiation. The toy attack benchmark checks one guessing strategy; it cannot establish that no faster strategy exists. The documented non-goals—no well-formedness proof, no control of publication time, no metadata hiding, no extra side-channel hardening and no network policy—match the implementation. Build/test dependencies and the disclosed absence of real Linux/x86 testing are substantially accurate, subject to R2-7 and the fixed backend-preference caveat. The layout descriptions match the files, with SHA-NI's shared implementation now in an additional header. Claims about private communications, model identity/reasoning effort and the absence of human review are author-supplied provenance, not independently verifiable from source. The present audit supplies the second report referenced by README; the audit index should subsequently be updated by the maintainer, outside this audit's authorized write scope.

VERDICT: fix-first
