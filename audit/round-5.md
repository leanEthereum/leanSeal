# chainseal v1 — round 5 audit

Audited `2d804be9ea5d729c871f56fb7a56bf41ad4f23a1` on 2026-10-21, limited to the changes and outstanding findings requested for this round. **Ready:** R4-1, R4-2 and R2-1 are resolved. Both stdout/checkpoint reproductions now fail safely before solving, ordinary stdout still works, and the watchdog no longer leaves a separate sleeper. All three requested test targets pass on Apple M4. I found no new defect in the reviewed changes, and the changed attribution and audit-history claims are supported by the source, reproductions and cited paper. This closes the findings in scope; it does not expand the project's stated security guarantees or platform coverage. Only this report was changed.

## Disposition of findings in scope

| Finding | Status | Evidence at this commit |
|---|---|---|
| R4-1 — Stdout redirected onto the checkpoint is deleted | resolved | With a valid partial checkpoint, both `open ... --solve >> FILE.ckpt` and an existing checkpoint opened `r+b` as stdout exit **2**, leaving every checkpoint byte unchanged. A hard-link alias used as stdout is also rejected. |
| R4-2 — Watchdog cancellation leaves its sleep child | resolved | The watchdog is now a single Python process with no child process. Cancelling and waiting for it leaves neither the watchdog nor a sleeper. An injected early solver exit also terminates the watchdog and removes the test directory. |
| R2-1 — Checkpoint cleanup deletes plaintext output | resolved | The stdout cases above are protected, exact-path conflicts remain rejected, and the case-variant output with no pre-existing checkpoint remains on disk with the correct plaintext. Ordinary pipe, terminal and unrelated-file stdout all return the correct bytes and remove the distinct old checkpoint. Failed output creation preserves it. |

## New findings

None in the reviewed changes. No blockers or majors remain open within this round's scope.

## Reproductions and regression review

All builds and scratch programs were run from copies under `/tmp/chainseal-audit5.RfICpm`; the repository source and committed tests were not modified. Environment: Apple M4, arm64 macOS, Apple clang 21.0.0.

### Output identity and cleanup

`is_output` at `src/util.c:122–125` delegates named outputs to the existing pathname comparison. For `-`, it instead compares `fstat(STDOUT_FILENO)` with `stat(checkpoint)` using both device and inode. Short-circuit evaluation prevents use of either uninitialized `struct stat` after a failed lookup. The helper does not write, close or reposition stdout.

Both calls in `cmd_open` use the same helper: the early check at `src/cli.c:524` rejects a conflict before `solve_all`, and the final check at line 544 prevents checkpoint deletion when the successfully written output is that file. The early descriptor check also prevents periodic checkpoint replacement from invalidating an aliased stdout destination during a long solve. The post-write pathname check retains the case-insensitive missing-file protection from round 4. I found no new memory-safety or concurrency issue in these changes.

The targeted probes used vector case index 2's envelope and valid partial checkpoint. Each stdout test began with a fresh copy of that checkpoint:

| Output configuration | Result |
|---|---|
| Shell append redirection, `open probe.env --solve -q >> probe.env.ckpt` | Exit 2; checkpoint exists and is byte-for-byte unchanged. |
| Checkpoint opened `r+b`, positioned at offset zero, supplied as stdout | Exit 2; checkpoint exists and is byte-for-byte unchanged. |
| A hard link to the checkpoint, opened for append as stdout | Exit 2; checkpoint unchanged. |
| A pipe receiving stdout | Exit 0; captured bytes equal the vector plaintext; old checkpoint removed. |
| An unrelated file receiving stdout | Exit 0; file bytes equal the vector plaintext; old checkpoint removed. |
| A terminal receiving stdout | Exit 0; bytes read through a raw pseudo-terminal equal the vector plaintext; old checkpoint removed. |
| Explicit `-o probe.env.ckpt` with no checkpoint yet | Exit 2; no output/checkpoint created. |
| `-o PROBE.ENV.CKPT` with no checkpoint yet, on this case-insensitive filesystem | Exit 0; output retained and equal to the vector plaintext. |
| A destination in a nonexistent directory | Exit 1; existing checkpoint unchanged. |

The committed stdout regression at `tests/cli.sh:123–127` checks the actual former failure: append redirection keeps the checkpoint valid until the process reads it, and the test asserts both the refusal status and unchanged bytes. It therefore tests more than the presence of an error message. The separate audit probe covers the requested `r+b` descriptor case as well.

### Watchdog and exit traps

The watchdog at `tests/cli.sh:86–89` sleeps inside the Python process itself and then signals the solver PID. It does not spawn an external `sleep`. Normal completion terminates and waits for that process before restoring the original directory-cleanup trap (`tests/cli.sh:100–102`). The temporary trap at line 91 also terminates the watchdog and solver on an early test exit.

Three checks exercised this behavior:

- **Successful cancellation:** a reproduction of the new watchdog lifecycle confirmed that it had no child processes; termination and `wait` reaped the watchdog, with no surviving timer process.
- **Early test failure:** a scratch wrapper made only the `solve -q endless` child create the ready marker and exit immediately. The unchanged CLI script failed at signal delivery, terminated its watchdog, and removed its temporary directory. No standard assertion was weakened to make this fault case pass.
- **Timeout:** a separate wrapper made only that child publish readiness and ignore SIGINT. The unchanged suite killed it and failed with “interrupted solve exited 137, wanted 130” after **60.63 seconds**. That expected failure verifies the watchdog; it is not a failing standard test target.

No new signal-handling or cleanup defect was found in these changed paths. The readiness and stop/resume mechanisms are unchanged from the previously reviewed fixes.

## Standard checks

| Check | Result |
|---|---|
| `make test` | Passed: 1,781 unit checks; ARMv8 and portable backends; 200/200 SHA-NI emulation cases; self-tests; exact vector regeneration; CLI tests; Python's 7 valid/51 invalid vectors; cross-language tests. |
| `make sanitize` | Passed the same target under ASan/UBSan. |
| `make tsan` | Passed its 1,781 unit checks with 2,000 fuzz iterations and the CLI suite. |

These executions do not add real Linux or x86 hardware coverage; the existing disclosures remain applicable and are not reopened as findings.

## Changed wording

The revised README and SPEC attribution correctly identifies the iterated variant as already present in **MMV §3.1**, rather than suggesting that composing oracle calls was a later addition. That section defines repeated composition of the oracle, substitutes it into the chained puzzle, and explains how it increases computation without increasing the puzzle description size. Describing chainseal as an SHA-256 instantiation of that variant is consistent with the dependency structure and the project's separately stated limits on its concrete security claims. [Mahmoody–Moran–Vadhan, *Time-Lock Puzzles in the Random Oracle Model*, §3.1](https://dash.harvard.edu/bitstreams/7312037c-92f2-6bd4-e053-0100007fdf3b/download).

The changed audit-history wording also checks out:

- The round-4 index row matches that report: R3-1 through R3-4 and R2-6 resolved, R2-1 partly resolved, one blocker and one nit.
- The note added to R3-1 accurately records the earlier stdout omission and points to R4-1.
- The R4-1 change entry accurately describes the descriptor-aware checks, early refusal and committed append-redirection regression.
- The R4-2 change entry accurately describes the single-process watchdog and early-exit cleanup trap.

No new unsupported claim was found in the wording changed by this commit. Unchanged attribution details and previously resolved or expressly disclosed limitations were not reopened.

VERDICT: ready
