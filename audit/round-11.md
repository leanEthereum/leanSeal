# Round 11: the Rust and Python implementations

Audited commit `a90416a` (`a90416aeb4e2878cb637ae3439a143a5bc775e68`) on 2026-10-28 by OpenAI's GPT-6 Astra at high reasoning effort; the changes it led to are in [README.md](README.md). **Fix first:** both CLIs can replace an envelope with its secret through a fresh filesystem alias; two additional CLI defects and two test defects were reproduced.

## Findings, most severe first

### 1. major — Fresh case aliases let the secret replace the envelope

**Locations:** `src/main.rs:584`, `src/main.rs:610`, `src/main.rs:612`, `src/runtime.rs:135`, `src/runtime.rs:157`; `ref/leanseal_ref.py:294`, `ref/leanseal_ref.py:497`, `ref/leanseal_ref.py:505`.

**Failure scenario, reproduced:** On the audited case-insensitive filesystem, encrypting with fresh destinations `case.env` and `CASE.env` passes the envelope/secret separation check. Neither file exists during preflight, and the fallback compares their names case-sensitively. Both implementations write the envelope first, then replace it with the secret.

Rust and Python both returned success. The intended envelope started with `LSSK`, contained the key, and was the same file as the secret destination. Its permissions remained `0600`, but publishing the path designated as the envelope would publish the key. The ciphertext was overwritten.

Reproduction: `/tmp/leanseal-audit.lzilv7/reproduce_alias.py`; results: `reproduce-alias.log` in that directory.

**Fix:** Keep the early check and repeat the filesystem identity check after the envelope exists, before writing the secret. Refuse aliases recognized by the filesystem, including case aliases.

### 2. minor — `solve` deletes its redirected key output

**Locations:** `src/main.rs:794`, `src/main.rs:802`, `src/main.rs:807`.

**Failure scenario, reproduced:** After creating an envelope and a valid checkpoint, run:

```sh
leanseal solve -q env >>env.ckpt
```

The command resumes successfully, appends the recovered key to `env.ckpt`, then deletes that file during checkpoint cleanup. It exits zero despite removing its output. The result and checkpoint are lost, potentially requiring another full solve.

Unlike `open`, `solve` does not compare stdout with checkpoint files. The reproduction used a one-step puzzle and `LEANSEAL_TEST_STOP_AFTER=1` to create its checkpoint.

Evidence: `/tmp/leanseal-audit.boCj9N/cli_repro.log`.

**Fix:** Reject stdout that aliases any checkpoint before solving. Check again during cleanup so that a file holding output is never removed.

### 3. minor — Completed solves leave blocked output immune to SIGINT and SIGTERM

**Locations:** `src/main.rs:664`, `src/main.rs:665`, `src/main.rs:899`; `src/runtime.rs:84`.

**Failure scenario, reproduced:** Encrypt a 1 MiB message under a one-step puzzle, then launch `leanseal open large.env --solve -q` with stdout connected to an unread pipe.

Solving finishes, but plaintext output blocks when the pipe fills. Neither SIGINT nor SIGTERM terminates the process. Their handlers only set the solver’s cancellation flag, which is no longer observed after solving. SIGKILL was required. A blocked `solve` key write has the same problem.

Evidence: `/tmp/leanseal-audit.boCj9N/cli_repro.log`.

**Fix:** Scope the signal handlers to solving and restore ordinary termination behavior afterward. Ensure blocked output remains interruptible; checking a flag only before writing is insufficient.

### 4. minor — The Python alias regression test never reaches the alias check

**Locations:** `tests/cross.sh:27`, `tests/cross.sh:30`.

**Failure scenario, reproduced:** The negative encryption command omits mandatory `--link-bytes`. Python rejects it during argument parsing, before checking the output destinations.

Removing only the same-file guard from a scratch copy still left the unchanged cross-test passing with `cross tests: ok`. A correctly formed command against that modified reference then successfully overwrote the envelope with `LSSK`.

Evidence: `/tmp/leanseal-audit.lzilv7/cross-missing-link.stderr`, `cross-guard-mutation.log`, and `cross-guard-mutation-explicit.log`.

**Fix:** Supply `--link-bytes` and verify the intended same-file rejection diagnostic, as well as the absence of output.

### 5. minor — The damaged-checkpoint test sometimes leaves the checkpoint unchanged

**Locations:** `tests/cli.sh:138`, `tests/cli.sh:139`, `tests/cli.sh:141`.

**Failure scenario, reproduced:** The test writes `0xFF` at checkpoint offset 60 and expects solving to fail. If that byte already equals `0xFF`, the checkpoint remains valid and the assertion incorrectly fails.

A deterministic valid checkpoint with `n=1`, `m=1`, `b=24`, salt equal to big-endian integer 156, and an all-zero link has the required byte. Applying the test’s mutation changed nothing, and Rust resumed successfully with exit zero. The original randomized test encounters this condition with approximately 1-in-256 probability.

Reproduction: `/tmp/leanseal-audit.WFvQ38/repro_checkpoint_test.py`; results: `checkpoint-test.log` in that directory.

**Fix:** XOR a bit of the existing byte, using the script’s existing `flip` helper, so the checkpoint always changes.

## What was checked

The worktree remained unchanged, with no commits. Final `git status --porcelain=v1` was empty, `git diff --exit-code` succeeded, and HEAD remained the audited commit. `audit/README.md` supplied historical context; `poc/` and `paper/` were excluded.

Commands and results:

| Check | Result |
|---|---|
| `CARGO_TARGET_DIR=/tmp/leanseal-audit.WFvQ38/target cargo test --all-targets` | All 25 tests passed, including decoder mutations and thread-spawn failure tests. |
| `cargo clippy --all-targets --locked -- -D warnings`, with the same target directory | Passed. |
| `cargo fmt --check` | Passed. |
| `cargo package --locked`, with a scratch target directory | Packaged 34 files and successfully verified the build. |
| `cargo test --release --locked` from the extracted package | All 25 tests passed. |
| `sh tests/cli.sh BINARY` | Passed with both the debug binary and packaged release binary. |
| `sh tests/cross.sh BINARY` | Passed with the packaged release binary, subject to finding 4. |
| `python3 ref/leanseal_ref.py check tests/vectors.json` | Eight cases and 51 invalid inputs, zero failures. |
| `python3 /tmp/leanseal-audit.WFvQ38/differential.py` | 160 generated cases, 3,776 checkpoint positions, and 101,246 Rust/Python decode, authentication and resume decisions agreed. |
| `python3 /tmp/leanseal-audit.WFvQ38/large_boundary.py` | Three synthetic checkpoint resumes passed at the maximum counters. |
| `cargo +nightly fuzz run TARGET -- -max_total_time=10` for all four targets | 10,519,703 executions in total, with no crashes or invariant failures. Sources, corpus and artifacts were copied into scratch storage. |

Source inspection and independent probes established the following:

- **Format conformance:** Rust and Python agree with the specified integer encodings, labels, hash inputs, masks, accumulator, key and commitment derivation, envelope layout and limits. Both enforce magic, version, reserved bytes, lengths, parameter bounds and trailing-byte rejection. No structural decoder discrepancy was found. Mutation testing supplements this inspection; it is not exhaustive enumeration of every encoding.
- **Solver and builder:** Independent generation comparisons covered every `b` from 1 through 32, including `n=1` and `m=1`. Checkpoint tests covered chain boundaries, completed cursors and commitment failures. Synthetic resumes exercised `m=2^48`, `n=2^20` and `n·m=2^60`; they tested boundary arithmetic without claiming to execute that much work.
- **Cryptography:** An independent probe matched Python `hashlib` and `hmac` on 1,025 SHA-256/HMAC cases. Another 180 chain results matched for the portable and ARM backends. Encryption authenticates the complete specified prefix and releases plaintext only after commitment and tag checks.
- **Comparison and randomness:** Optimized ARM64 assembly for the 32-byte comparison used fixed loads and reductions without conditional branches. Salt, link and nonce generation use OS randomness and propagate errors. RNG failure handling was established from source, without OS fault injection.
- **Erasure:** Guarded library buffers erase owned secrets on drop. Erasure remains incomplete for some temporaries and CLI error paths, consistent with the limitation stated in `docs/security.md`.
- **CLI:** Existing tests and source checks covered exclusive temporary creation, private secret/checkpoint permissions, atomic replacement, existing symlink and hard-link aliases, checkpoint resume, output-error retention, cancellation during solving and thread-spawn failures. Explicit delay calibration, huge and subnormal values passed. Calibration without `--step-ns` also produced the expected ceiling-based step count.
- **CI and packaging:** CI requests hardware agreement on x86 and ARM, portable CLI/cross tests, packaged-crate tests and an MSRV build. Packaging worked locally. Findings 4 and 5 weaken the shell tests despite their passing runs.
- **Security statements:** SPEC section 8 and `docs/security.md` agree on the stated theorem’s bound, round counts, `n=1` exception, precomputation term and encryption-proof limitation. Their publication-time, malformed-puzzle, key-reuse and post-disclosure authentication statements match the code.

The x86 backend and Rust 1.80 toolchain were not executed locally. The theorem’s full proof was not independently audited; this review checked the requested statements and their consistency with the implementation.

VERDICT: fix-first