# chainseal v1 — round 4 audit

Audited `634982f74a5bbd098efea136091326ebda4fc867` on 2026-10-21, restricted to the requested changes and outstanding findings. **Fix first:** R3-1 through R3-4 and R2-6 are resolved, but R2-1 remains partly resolved because the changed checkpoint-removal condition explicitly exempts stdout from its output-identity check. With stdout redirected to a valid checkpoint, opening succeeds and then deletes the file receiving the plaintext. The original case-insensitive pathname reproduction is fixed, the timing conversions now pass the previous boundary cases, and the signal test passes with delayed startup. All three requested test targets pass on Apple M4. There is also a nonblocking watchdog cleanup nit. The changed documentation is accurate except for the unqualified output-preservation claim described below; no previously resolved, unrelated findings or openly documented limitations are reopened. Only this report was changed.

## Disposition of findings in scope

| Finding | Status | Evidence at this commit |
|---|---|---|
| R3-1 — Case-variant output deleted when no checkpoint exists | resolved | On the audited case-insensitive filesystem, `open alias.env --solve -q -o ALIAS.ENV.CKPT` now exits 0 and retains the exact vector plaintext. Exact-path conflicts and an existing checkpoint reached through a case variant still exit 2 without deleting the checkpoint. |
| R3-2 — Incorrect work count for subnormal times | resolved | Reran `-n 1 -d 5e-324 --step-ns 3e-315`: encoded `m=2`. The new `1e-320/1e-314` case gives `m=1000`; the previously rejected `-n 64 -d 1e-320 --step-ns 1e-320` now gives `m=15625000`. |
| R3-3 — SIGINT before handler installation | resolved | Ran the unchanged full CLI suite through a wrapper that sleeps one second before executing the binary. It passes: the ready-file handshake replaces the old 0.5-second assumption. A separate child that deliberately ignores SIGINT is killed by the watchdog, and the suite reports failure after about 60 seconds. |
| R3-4 — Undocumented Perl test dependency | resolved | Both binary patches now use the Python `poke` helper. There is no Perl invocation in `tests/cli.sh`; the existing Python prerequisite covers the new helper, while the demo's Perl requirement remains documented. |
| R2-1 — Checkpoint cleanup deletes plaintext output | partly resolved | Explicit output-path conflicts, including the missing-file case variant, are handled. The changed cleanup expression still unlinks a checkpoint that is also the stdout destination (R4-1). Distinct-file resumed output succeeds and removes its old checkpoint; failed output writes and failed tags retain it. |
| R2-6 — Timing-dependent interrupt/resume tests | resolved | The deterministic stop/resume hook remains in use, and real SIGINT now waits for handler readiness with bounded failure handling. Both the delayed-startup reproduction and the injected ignored-signal case behave as intended. R4-2 concerns cleanup of the watchdog's sleeper, not signal correctness. |

## New findings and remaining defects

### R4-1. blocker — The changed cleanup check still deletes output sent through stdout

**Locations:** `src/cli.c:524–525,541–544`; `audit/README.md:47`.

**Failure scenario, reproduced:** save a valid envelope and its valid partial checkpoint from vector case index 2 as `stdout.env` and `stdout.env.ckpt`. Then run:

```sh
chainseal open stdout.env --solve -q >> stdout.env.ckpt
```

The command reports that it is resuming, appends the recovered plaintext to stdout, exits **0**, and leaves **no `stdout.env.ckpt` file**. The append redirection is material: it preserves the valid checkpoint until the command reads it. Ordinary truncating `>` redirection instead produces an invalid empty checkpoint and is rejected before solving.

A second reproduction passed an existing checkpoint opened with `r+b` as the process's stdout descriptor, positioned at offset zero. The command again exited 0 and removed the pathname; reading the still-open descriptor confirmed that the plaintext had been written at its beginning. Thus this is actual output deletion, not merely an unsuccessful solve or missing write.

The new condition is:

```c
(!strcmp(out, "-") || !same_path(out, s.ckpt))
```

For default stdout or `-o -`, the first operand is true, so no identity comparison happens. The earlier conflict check also skips stdout. The post-write pathname check correctly fixes R3-1, but the broader change-log statement that cleanup removes the checkpoint only when it is a different file from the output is false for this branch.

This stdout behavior predates the patch; it is a remaining case of the still-open R2-1 finding in the checkpoint-removal code changed by this commit, not a newly introduced cryptographic regression.

**Suggested fix:** include the stdout descriptor in conflict detection, using `fstat(fileno(stdout))` and the checkpoint's device/inode identity. Reject the conflict before solving, so periodic checkpoint replacement cannot invalidate the output descriptor either, and ensure final cleanup never removes the output destination. Add a regression with a valid existing checkpoint and nontruncating stdout redirection, asserting either an early refusal with the file intact or successful retained output. Normal stdout pipes and unrelated redirected files should continue to work.

### R4-2. nit — Cancelling the watchdog leaves its sleep child behind

**Location:** `tests/cli.sh:86–87,96–97`.

**Failure scenario, reproduced:** start the watchdog exactly as the test does, identify its `sleep 60` child, then execute the test's `kill "$WATCHDOG"` and `wait "$WATCHDOG"` cleanup. On the audited shell, the watchdog subshell exits but its sleep child remains alive, reparented to PID 1. The reproduction confirmed this with the known child PID and then terminated that owned child.

The remaining child is only a sleeper and exits when its original timer expires; it does not retain the shell's later `kill` command. This is a bounded test-process cleanup issue, not a reason for `fix-first` and not a failure of the watchdog's timeout behavior.

**Suggested fix:** make the watchdog a single cancellable process, for example a small Python timer that performs the eventual signal itself, or explicitly track and reap its sleeper. Arrange cleanup on early test exits as well.

## Verification and regression review

All builds, logs and scratch probes were confined to `/tmp/chainseal-audit4.nRsU6Z`, using copies of the reviewed source. The repository source and committed tests were not edited. Environment: Apple M4, arm64 macOS, Apple clang 21.0.0.

| Check | Result and scope |
|---|---|
| `make test` | Passed: 1,781 unit checks, ARMv8/portable backend tests, 200/200 shared-code SHA-NI emulation cases, self-tests, exact vector regeneration, CLI tests, Python's 7 valid/51 invalid vectors, and cross-language tests. |
| `make sanitize` | Passed the same target under ASan/UBSan. |
| `make tsan` | Passed its 1,781 unit checks with 2,000 fuzz iterations and the CLI suite. |
| Delayed startup | The unchanged `tests/cli.sh` passed through `sleep 1; exec /absolute/path/to/chainseal "$@"`, the same startup delay used in round 3. No assertion or timeout was weakened. |
| Watchdog failure path | A separate wrapper substituted only the `solve -q endless` test child with a process that published the ready marker and ignored SIGINT. The unchanged suite killed it and failed with “interrupted solve exited 137, wanted 130” after 60.64 seconds. This expected failure verifies the watchdog; it is not a failing standard test target. |
| Output handling | Case-variant output with no checkpoint is retained byte-for-byte; existing-checkpoint aliases are rejected without modification; a distinct output file is retained and the old checkpoint removed. Failed destination creation exits 1 and failed authentication exits 3, both preserving an existing checkpoint. The remaining stdout case is R4-1. |

The changed delay expression divides the two parsed times before applying the nanosecond conversion. The two committed subnormal tests now check the intended outcomes, and the audit independently read `m` from the encoded secret files. The original large-value pairs also remain correct: `n=64,delay=1e308,step_ns=1e308` gives `15625000`, and `1e300/1e307` gives `2`. An extreme ratio that underflows (`5e-324/1e308`, with `n=1`) correctly clamps to one step; the opposite overflowing ratio is rejected with a range error. For the permitted `n`, intermediate overflow implies a work count far above the permitted maximum; ratio underflow implies that one step already exceeds the requested delay. I found no new dynamic-range defect in this conversion. This is ordinary floating-point parameter selection, not a claim of arbitrary-precision arithmetic.

`CHAINSEAL_TEST_READY` is initialized before worker creation and used by the main thread. The ready entry is created after the SIGINT and SIGTERM handlers are installed. A signal arriving immediately after publication can therefore set the atomic cancellation flag even before worker creation; the solve later observes it through the existing progress callback and saves a checkpoint. The test removes stale markers before launching the child, waits for a new one and checks both exit 130 and a nonempty checkpoint. The injected delayed startup confirms that it no longer signals merely because a fixed startup interval elapsed. The hook is explicitly test-controlled; no new production security boundary is claimed for arbitrary paths supplied through that environment variable.

The `poke` helper preserves the intended binary edits: `>Q` writes `m=2^40` at envelope offset `8+12`, and `>IQ` writes `i=4097,j=2^48` at checkpoint offset 40. Python's `struct.pack` supplies explicit big-endian widths, and its exceptions produce a nonzero command result. The case-alias test uses a fresh test directory and detects whether that filesystem is case-insensitive before exercising the alias; on this Mac it runs and checks the actual plaintext bytes. It covers the round-3 reproduction rather than merely checking an exit status. It does not exercise stdout identity, which is why R4-1 escapes the suite.

## Changed documentation

- README's replacement of “two rounds” with “several rounds” is accurate and avoids becoming stale with this report. Its other status claims are unchanged and were not reopened.
- The new round-3 index row accurately records six of eight round-2 findings resolved, two partly resolved, and one blocker plus three minor findings reported in that round.
- The notes added to R2-1 and R2-6 accurately describe what remained wrong at that historical stage and point to the corresponding round-3 findings.
- The R3-2 row correctly describes the reordered calculation and the two new subnormal tests. The R3-3 row correctly describes readiness publication and the 60-second watchdog, verified both with delayed startup and an unresponsive test child. The R3-4 row correctly describes removal of Perl from the CLI tests.
- The R3-1 row accurately describes the new pathname-alias protection and its regression test, but its statement about removing a checkpoint only when it differs from the output needs R4-1's correction for stdout. That is the outstanding substantive claim failure in the changed documentation.

The audit makes no new claims about untested Linux/x86 execution or the previously disclosed cryptographic and hardening limitations. The outstanding blocker is confined to output/checkpoint identity handling; the signal and numerical fixes reviewed here resolve their reported failures.

VERDICT: fix-first
