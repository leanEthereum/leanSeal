# chainseal v1 — round 3 audit

Audited `8e042018bab645e3b82797d55d33df52d1dc0249` on 2026-10-21. **Fix first:** six of the eight round-2 findings are resolved and two are partly resolved; of the three outstanding round-1 findings, 2 and 3 are resolved and 12 is partly resolved. The security wording, checkpoint bound, benchmark sample count and Linux ARM build flags are corrected, and all three requested test targets pass on Apple M4. However, the output-deletion bug survives the new path check on a case-insensitive filesystem when the checkpoint does not yet exist. There are also minor numerical, test-synchronization and dependency-documentation issues. Consequently, the PoC still cannot be described as correct with every documented claim true. The existing disclosures about security assumptions, production hardening and untested hardware are not new blockers; the author list and forthcoming guide are accepted as author-supplied, as requested. Only this report was changed.

## Disposition of findings in scope

“Resolved” concerns the original failure; separate defects in the same feature are identified below. The last three rows track the round-1 findings explicitly and overlap the round-2 rows.

| Finding | Status | Evidence at this commit |
|---|---|---|
| R2-1 — Plaintext deleted by checkpoint cleanup | partly resolved | Exact-path, `./`, absolute, parent-directory and directory-symlink aliases now exit 2. With no checkpoint present, `-o ALIAS.ENV.CKPT` on the audited case-insensitive filesystem still exits 0 and deletes its plaintext (R3-1). |
| R2-2 — Globally impossible checkpoint position | resolved | Repeated `info` on `i=4097,j=2^48`: exit 1; `i=4096,j=2^48`: exit 0. The unit tests exercise both, and the CLI test exercises rejection. Zero `i` and excessive `j` are also rejected. |
| R2-3 — Unsupported attack comparisons | resolved | README:60,95 and SPEC:58,180 now acknowledge key guessing, restrict the least-work comparison to hidden-link guesses, give earlier guesses the same success probability per guess, and qualify cross-puzzle reuse by fresh random salts. The earlier counterexamples are now consistent with the text. |
| R2-4 — Wrong latency sample count | resolved | README:77 now says five runs, matching `r[5]`, the five iterations and median `r[2]` in `src/bench.c:53–56`; the archived median/best values still round to 23.3/23.1 ns. |
| R2-5 — Huge finite timing input gives `m=1` | resolved | Reran `gen -n 64 -d 1e308 --step-ns 1e308`: exit 0 with encoded `m=15625000`, as required. The new `1e300/1e307` CLI test gives `m=2`. A separate subnormal-input defect is R3-2. |
| R2-6 — Timing-dependent interrupt tests | partly resolved | Resume tests now stop deterministically through the hook, and the real-signal puzzle cannot finish within the normal test interval. The real-signal test still sends SIGINT after an unsynchronized sleep; delayed child startup loses that signal and leaves the test waiting (R3-3). |
| R2-7 — Sanitizers omit Linux ARM backend | resolved | Repeated Linux/aarch64 make expansion with the normal, ASan/UBSan and TSan `CFLAGS`: all three recipes retain `-march=armv8-a+crypto` through `ARCH`. This is build-plan evidence, not a real Linux execution. |
| R2-8 — Overstated audit/test coverage | resolved | `audit/README.md:3,27` now distinguishes execution from source/arithmetic evidence, describes the two closed gaps precisely, and explicitly retains fault-injection and real-platform gaps. It no longer claims that all named gaps are covered. |
| Round 1, #2 — Universal work/probability claims | resolved | The numerical bound remains explicitly attack-specific; honest work, `n=1`, key guessing, the asymptotic MMV result and absence of a concrete/quantum theorem are distinguished. Recomputed the quoted probability exponents below. |
| Round 1, #3 — Malformed checkpoints accepted by `info` | resolved | The original combined version-2/reserved-byte/zero-index/`j=2^64-1` reproduction exits 1, and the new joint-bound reproduction is also rejected. Puzzle-specific ID and position checks remain in the full decoder. |
| Round 1, #12 — Chance-dependent CLI tests | partly resolved | Tampering is guaranteed by XOR, and checkpoint/resume no longer relies on finishing slowly enough. The remaining real-SIGINT startup race is R3-3. |

## New findings and remaining defects

### R3-1. blocker — Missing-file path comparison overlooks case-insensitive aliases

**Locations:** `src/util.c:101–119`; `src/cli.c:515–516,532–533`; `audit/README.md:33`.

**Failure scenario, reproduced on the audited Mac filesystem:** take case 2's valid envelope from `tests/vectors.json`, save it as `alias.env`, and ensure there is no checkpoint. Run:

```sh
chainseal open alias.env --solve -q -o ALIAS.ENV.CKPT
```

The command exits **0**, but neither spelling of the output exists afterward. The filesystem was independently confirmed to resolve case variants to the same entry. With `--no-checkpoint`, the identical output request succeeds and retains exactly the expected plaintext.

`same_path` compares device/inode identities only when **both** names already exist. When the checkpoint is absent, it resolves the parent directories but keeps the final components verbatim, then uses case-sensitive `strcmp`. It therefore reports that `ALIAS.ENV.CKPT` and `alias.env.ckpt` differ. `write_file` creates the plaintext under the first spelling; `unlink(s.ckpt)` then deletes that same entry under the second spelling. This is ordinary filesystem behavior on the tested platform, not a concurrent attacker or a hypothetical filesystem race.

The fix does handle identical names and normalized parent paths. With a valid checkpoint already present, the inode comparison also catches the case variant and preserves the checkpoint. The committed test uses an existing checkpoint and its exact spelling, so it misses the failing state. The change log's claim that `open` refuses an output naming the checkpoint is consequently still too broad.

**Suggested fix:** make cleanup incapable of unlinking the output it just wrote. For example, revalidate filesystem identity after successful atomic output publication and preserve the output if it is the checkpoint entry; retain the early rejection where it can be established reliably. Alternatively, use filesystem-aware alias detection that also works before the final entry exists. Add a missing-checkpoint case-variant regression on case-insensitive filesystems alongside existing-file and parent-alias cases. Do not rely solely on lowercasing strings, which is not a general model of filesystem name equivalence.

### R3-2. minor — Subnormal timing values still silently produce the wrong work count

**Locations:** `src/cli.c:124–126`; `src/util.c:168–178`; `audit/README.md:37`.

**Failure scenario, reproduced:**

```sh
chainseal gen -q -n 1 -d 5e-324 --step-ns 3e-315 -o subnormal.sec
```

The command accepts both positive finite values, exits 0 and writes `m=1`. The requested formula requires `m=2`: even using the actual parsed binary64 values rather than the decimal strings, the ratio before `ceil` is approximately `1.6468854859`. Multiplying the step time by `1e-9` rounds the denominator to the smallest positive binary64 number, equal to the parsed delay, so the implemented ratio becomes exactly 1.

The revised expression fixes the original large-denominator overflow, but it still needs a policy for underflow. Another accepted finite pair, `-n 64 -d 1e-320 --step-ns 1e-320`, is rejected as out of range because the denominator becomes zero, although its mathematical work count fits the format. These are physically unrealistic timing inputs; this is a minor numeric-boundary defect, consistent with the severity used in prior rounds, not a practical default-parameter attack or undefined integer conversion.

**Suggested fix:** reject unsupported subnormal/underflowing timing inputs explicitly, or use a scaled calculation that preserves the intended ratio before rounding. Document the supported numeric range and add an arithmetic regression. The existing enormous-value test demonstrates the particular overflow fix, not correctness for every positive finite input.

### R3-3. minor — The real-SIGINT test can signal before the handler is installed and hang

**Locations:** `tests/cli.sh:74–83`; `src/cli.c:392–396`; `audit/README.md:38`.

**Failure scenario, reproduced with controlled startup delay:** run the test's background-solve/sleep/SIGINT sequence, but invoke the real binary through this scratch wrapper:

```sh
#!/bin/sh
sleep 1
exec /absolute/path/to/chainseal "$@"
```

The parent still sleeps 0.5 seconds and successfully sends SIGINT to the child PID. In this noninteractive background-shell execution, SIGINT is initially ignored; `chainseal` replaces that disposition only on entering `solve_all`. The early signal is lost. Two seconds later, the child is still computing the patched `m=2^40` puzzle, and the test's unbounded `wait` has no reason to return promptly. A later SIGTERM, after handler installation, stops the child with exit 130; the reproduction used that to clean up.

The wrapper models delayed startup and makes the ordering deterministic; no production source or committed test was modified. Scheduler delays or slow startup can expose the same ordering. Making the workload enormous removes the old finish-before-signal case but does not synchronize handler readiness, and now makes a lost signal especially expensive. Normal runs of all three test targets passed here.

**Suggested fix:** wait for an explicit ready/progress indication established after signal-handler installation before sending SIGINT. Add a bounded timeout and cleanup that terminates the child on test failure. Keep the deterministic hook for resume assertions; it works for that purpose, but it does not validate delivery of a real signal.

### R3-4. minor — The full test suite now requires Perl, which is documented only for the demo

**Locations:** `tests/cli.sh:76,96`; `README.md:13`.

**Failure scenario, established from the commands:** on an otherwise suitable build/test host with Python but no `perl`, the CLI suite fails at its new `perl -e` invocation rather than reaching the signal test. The same script is used by `make test`, `make sanitize` and `make tsan`. Previously Perl was used by the demo; these new invocations make it a test-suite dependency as well. The README specifically lists Python for the full suite and mentions Perl with the demo, leaving that new requirement unclear.

**Suggested fix:** list Perl as a full-suite dependency, or perform the binary patches with the already-required Python. This is a dependency-documentation gap, not a cryptographic or runtime blocker.

## Verification and regression review

All builds and scratch programs were confined to `/tmp/chainseal-audit3.vYRAbY`, using copies of the reviewed sources. Environment: Apple M4, arm64 Darwin, Apple clang 21.0.0. The source checkout remained unchanged apart from this report. Scratch paths are evidence locations, not prerequisites for understanding the reproductions above.

| Check | Result |
|---|---|
| `make test` | Passed: 1,781 unit checks, ARMv8 and portable backends, 200/200 shared-code SHA-NI emulation cases, backend/round-trip self-tests, exact vector regeneration, CLI tests, Python's 7 valid and 51 invalid vectors, and cross-language tests. |
| `make sanitize` | Passed the same suite under ASan/UBSan on M4. |
| `make tsan` | Passed its 1,781 unit checks with 2,000 fuzz iterations and the CLI suite, including the new hook. |
| x86 compilation | `clang -target x86_64-apple-macos11 -std=gnu11 -O3 -Wall -Wextra -Wshadow -c src/chain.c` succeeded. No real x86 instructions were executed. |
| Linux ARM make regression | Under a scratch `uname` shim reporting Linux/aarch64, normal, ASan/UBSan and TSan recipes all include the architecture flag despite command-line `CFLAGS`. No Linux runtime claim is inferred. |
| Hook and resume | Two fresh invocations with `CHAINSEAL_TEST_STOP_AFTER=2^21` advanced a `4*2^22`-step puzzle to totals `2^21` and `2^22`, both exiting 130 with decodable checkpoints. An invocation without the hook then returned the correct secret-file key and removed the checkpoint. Invalid hook values `bad`, `-1`, `inf` and `2^64` exit 2. |

The new hook is initialized before worker creation and read without subsequent writes. It requests cancellation through the existing atomic flag, so it introduces no new inter-thread race in the reviewed path. Its threshold counts work performed since the loaded checkpoint, not lifetime work. It is approximate at progress-callback granularity; in a batch, the first job reaching its threshold requests cancellation of all jobs. It does not manufacture a successful key or bypass the final commitment check. These are appropriate semantics for the single-job regression tests. Its explicit test environment variable is not a new security boundary against someone already controlling the process environment.

The new checkpoint division guard is safe: short-circuit evaluation rejects zero/out-of-range `i` before division. Together with the individual bounds it rejects exactly the new globally impossible positions at issue. For `j=0`, valid `n=i,m=1` remains possible; otherwise `n=i,m=max(1,j)` shows that the accepted joint bounds are compatible with some parameter set. The full decoder still checks the actual puzzle ID and its tighter `n,m` bounds. There is no new wire-format change, and the C/Python/vector agreement established in round 2 remains intact.

`same_path` is memory-bounded and handles the tested absolute, relative, `..` and directory-symlink spellings, and existing-file identities. Its missing-entry fallback is the substantive problem in R3-1. Rejecting aliases before solving is otherwise a reasonable improvement. I found no new decoder memory-safety defect, key/tag verification bypass or cryptographic change in this patch.

The rewritten tests make substantive improvements: real signal handling is tested separately from deterministic checkpoint/resume, the joint checkpoint limit has rejection and boundary coverage in unit tests, the original numeric overflow has a focused CLI case, and the exact output/checkpoint conflict is rejected without deleting the existing checkpoint. Their limitations are the cases above. The already-disclosed absence of fault injection and real Linux/x86 execution remains a limitation, not evidence that those paths fail. SHA-NI arithmetic is unchanged from the previously reviewed shared implementation; I continue to believe it is correct, with actual hardware execution still outstanding.

## Documentation and numerical claims

The revised README/SPEC attack discussion resolves the specific logical overclaims from rounds 1 and 2. The scope is now blind hidden-link guessing: an earlier hidden-link guess has the same chance of being the actual link but leaves more chains, while a key guess is a separate strategy. The text explicitly declines to prove optimality. SPEC §8's assumptions should be read as assumptions, together with its explicit absence of a concrete theorem, not as a new universal lower bound. Fresh random salts qualify cross-puzzle reuse; the text no longer claims deterministic isolation for repeated salts. Author names, attribution and the future guide link were not treated as findings.

The quantitative checks still agree:

- For `R=10^21,T=60,m=2^25`, the last-link estimate has base-2 logarithms `-29.3326194`, `-37.3326194`, `-45.3326194` at `b=10,11,12`. Thus the quoted approximately `2^-45` and minimum `b=11` for `2^-32` remain correct for the named model, not a bound on every attack.
- The six labelled-hash minimum input lengths remain 56, 81, 84, 65, 65 and 92 bytes; the chain step is 52 bytes, and the HMAC inputs in this format are at least 72. The domain-separation correction and context binding remain unchanged and consistent.
- Puzzle sizes remain `68+n*b`, giving 836 and 6,212 bytes at the stated defaults; envelope, secret and checkpoint sizes remain correct. The `2^60` joint work bound still protects the counters.
- The five-sample benchmark code and archived `23.27`/`23.07` ns values support the corrected latency row. The archived throughput/speedup figures and demo log support the rounded 465 M steps/s, 9.6/9.9/10.8–11.3 speedups, 36.9-second build, 7-ms fast open and 6-min-37-s solve. Both example work totals are `17,179,869,184` steps; the approximately 6.6-minute solve and 40-second build estimates remain consistent with those measurements.

The replacement of “fastest” with an available accelerated-backend preference is accurate. The integrity boundary after key disclosure, whole-envelope binding, nonce-reuse warning, publication clock and stated non-goals remain appropriate. No new blocker is assigned for the openly stated lack of a concrete security proof, quantum analysis, crash-durable directory updates, complete erasure or real-platform testing. The audit change log now accurately narrows its coverage claim, but its R2-1 completion claim fails on the reproduced missing-file alias; R2-6 still needs the startup qualification. The historic “after round 1” entries describe that earlier stage and are superseded by the later changes. The README's two completed rounds and the audit index describe the pre-round-3 state; a maintainer can update them after accepting this report, outside this audit's write scope.

VERDICT: fix-first
