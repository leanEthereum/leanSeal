# chainseal v1 security and correctness audit

Audited commit `dd063aa3308721c0129eec61e98c4bcb1db6c71c` on 2026-10-21. **Fix first:** the core C and Python cryptographic operations agree with the specified wire format, and the normal test, ASan/UBSan, and TSan targets all pass on Apple M4, but chainseal cannot yet be described as a correct, complete PoC with every README/SPEC claim true. The main problems are an unconditional integrity claim that fails once the key becomes public, an attack-specific probability estimate presented too broadly, a nonconforming checkpoint inspection path, and overstated backend selection promises. Additional confirmed defects include a solver cancellation data race, discarded successful results in mixed-result batches, and public permissions on Python secret files. I believe the x86 SHA-NI arithmetic is correct after source review, cross-compilation, and scalar instruction emulation; it remains untested on real SHA-NI hardware. Only this audit file was changed. Findings use the requested severity convention: a false substantive README/SPEC claim or normative conformance failure is a blocker even where its repair is documentation-only.

## Findings, most severe first

### 1. blocker — Integrity does not survive public key recovery without an externally fixed envelope

**Locations:** `README.md:84`; `SPEC.md:165–180`; `src/chainseal.c:376–420`.

**Failure scenario, reproduced:** take case 2 in `tests/vectors.json`. An attacker who obtains its key through the advertised solve/reveal mechanism keeps its puzzle, commitment, and nonce, replaces the message with `ATTACKER REPLACEMENT`, and computes the corresponding ciphertext and tag. The unmodified C command `open forged.env -k KEY` exits 0 and outputs that replacement. The Python reference accepts it too. No SHA-256 collision, alternate key, malformed puzzle, or nonce guessing is required. Changing an existing ciphertext and recomputing its tag works equally well.

The README says an envelope opens only to what the sender sealed and that any modification makes opening fail. The commitment fixes a key for a given context; it does not authenticate the sender or fix a unique ciphertext. HMAC authenticates against parties without its secret key, and that key intentionally becomes public here. Even before recovery, wholesale replacement by an attacker-generated puzzle/envelope is not prevented by any sender identity check. These are protocol boundaries, not bugs in the HMAC implementation. [RFC 2104 describes the shared-secret authentication model](https://www.rfc-editor.org/rfc/rfc2104.html).

**Suggested fix:** state that integrity against outsiders lasts while the key is unknown, and that the recipient must authenticate/fix the exact envelope before release if it must remain bound to the sender's original message. Specify the external signature, authenticated publication, or previously authenticated digest required for that stronger property. Distinguish binding of one fixed envelope to a key/plaintext from authentication of later received replacements. Also separate SHA-256 collision resistance for commitment binding from the PRF/MAC assumptions used for keystream confidentiality and tag unforgeability; collision resistance alone is not the complete security assumption for this composition.

### 2. blocker — The universal sequential-work and opening-probability claims exceed the stated attack analysis

**Locations:** `README.md:58,83,90,97`; `SPEC.md:35,87,175–176`; `src/bench.c:148–182`.

**Concrete counterexamples:**

- With legal `b=1`, an attacker evaluates all 256 candidates for `x_n` on parallel workers and tests their final keys. It needs only one chain's sequential depth, regardless of `n`. With fewer guesses it still has a nonzero chance of succeeding early. Thus “cannot start” and “nobody ... until ... n·m ... in sequence” require a computational/probabilistic qualification. For `n=1`, the last link is already public; its uncertainty is not `8b` bits at all.
- For legal `b=32, m=2^48`, an attacker can instead guess a uniform 32-byte **key** and check its commitment. Guessing the actual key succeeds with probability exactly `2^-256` and takes a constant number of compressions (the commitment input takes two), rather than `m` chain steps. At that same compression budget, `R*T/(m*2^(8b))` is approximately `2^-303`, so it cannot be an upper bound on *all* ways of opening the puzzle. This is a counterexample to the bound, not a practical attack against the default parameters.
- Once enough sequential time for honest solving has elapsed, success is 1, irrespective of the much smaller last-link-search estimate. Aggregate throughput `R` alone does not specify an attacker's sequential latency or establish a time cutoff before that point.

For distinct, blind final-link guesses with an initially hidden uniform `x_n`, ignoring negligible hash-merger/alternate-key events, the intended estimate is sound: at most `floor(R*T/m)` such trials, with probability bounded by `min(1, floor(R*T/m)/2^(8b))`. The numbers in the documents are **correct for this attack**: with `R=10^21`, `T=60`, `m=2^25`, the base-2 logarithms are `-29.3326194` for `b=10`, `-37.3326194` for `b=11`, and `-45.3326194` for `b=12`. Eleven bytes is therefore the minimum integer width meeting `2^-32` under that estimate.

[MMV §3.1](https://dash.harvard.edu/bitstreams/7312037c-92f2-6bd4-e053-0100007fdf3b/download) gives a classical random-oracle asymptotic result with a polynomial total-query restriction and negligible failure probability. Chainseal preserves its hidden-link dependency pattern and composed-query idea, but uses separate link/state widths, salt/index-specific chains, a derived key, and a public commitment. The cited result is not itself a concrete security theorem for this entire instantiation. The toy benchmark measures the frequency of one particular final-link search; it does not test the optimality of that attack or prove a universal bound. Indeed its archived toy budgets exceed the honest solver's total work.

**Suggested fix:** describe `n*m` as honest solving work and conditional sequential depth, restrict the numerical estimate explicitly to the named classical guessing attack, and state the query/latency assumptions and exceptional events. Explicitly exclude quantum guarantees unless separately analyzed. If a global concrete bound is intended, supply an analysis covering other link guesses, intermediate-state hits, key search, collisions, precomputation, and the actual time cutoff. Keep the correct numerical examples, with this scope attached.

### 3. blocker — `info` accepts checkpoint headers forbidden by section 6

**Locations:** `src/cli.c:571–576`; `SPEC.md:93,142–150`.

**Failure scenario, reproduced:** start with a valid 84-byte checkpoint, set byte 4 to version 2, byte 5 to 1, set `i=0`, and set `j=2^64-1`. `chainseal info FILE` exits 0 and describes it as a checkpoint. It checks only size and magic. The ordinary C checkpoint decoder and the Python decoder correctly reject it.

This is a strict-format conformance failure in the inspection command, not a way to bypass solve/open authentication. `info` lacks a puzzle with which to validate the ID or puzzle-specific position bounds, but it can and must reject unsupported versions, reserved bytes, zero/out-of-global-range indices, and globally impossible step counts.

**Suggested fix:** share a structural checkpoint-header validator with `cs_checkpoint_decode`; clearly label puzzle-dependent checks as unverified when inspecting a checkpoint alone. Add CLI negative cases, rather than only checking that valid output contains the word `checkpoint`.

### 4. blocker — Runtime backend selection and forcing are overstated

**Locations:** `README.md:22–28`; `src/chain.c:54–56,246–265`; `Makefile:1–4`.

**Failure scenarios, established by source and compiler checks:** a normal baseline `aarch64-linux-gnu` compile does not define `__ARM_FEATURE_SHA2`, so the ARM backend is absent even if the eventual CPU has SHA2. Compiling for `armv8-a+crypto` includes it, but the code then advertises it without a runtime CPU check. Such a binary is not a runtime-dispatched portable binary for arbitrary ARMv8 CPUs. This does not affect the tested Apple M4 build.

Separately, on the M4, `CHAINSEAL_BACKEND=x86-sha-ni chainseal gen -n 1 -m 1 ...` succeeds and reports `armv8-sha2`; unknown names also silently fall back. Thus the environment variable does not reliably “force one.” `selftest` tests only compiled, available backends, not all three implementations on every machine. Selection is a fixed preference order, not a runtime measurement of which backend is fastest.

**Suggested fix:** either document these build/availability restrictions and the fallback behavior accurately, or implement per-function ARM feature targeting plus platform runtime feature checks and reject unavailable/unknown forced backends. Say explicitly which backends were exercised. Do not count an M4 run with the x86 environment override as SHA-NI validation.

### 5. major — Cancellation uses a non-atomic object across solver threads

**Locations:** `src/cli.c:65–68,290–297,383–395`.

**Failure scenario, reproduced under TSan:** start two solve jobs, let the first worker reach its progress callback, and make the second `pthread_create` return `EAGAIN`. The main thread writes `g_stop=1` at line 394 while the worker reads it at line 297. A scratch wrapper that delayed and failed the second creation produced a TSan data-race report identifying precisely those two accesses. No production code was changed.

`volatile sig_atomic_t` is suitable for the limited signal-handler access pattern; it does not provide inter-thread synchronization. The same shared flag is also written by an asynchronously delivered signal handler while multiple workers may read it. The successful normal TSan target does not establish correctness of these failure/delivery paths.

**Suggested fix:** use a guaranteed lock-free C atomic for signal-safe stores and inter-thread loads on supported targets, or route signals to a dedicated `sigwait`/notification path that updates a proper atomic cancellation flag. Exercise partial thread creation and signal delivery during multiple simultaneous solves.

### 6. major — A failed or interrupted batch discards successful keys and their checkpoints

**Locations:** `src/cli.c:410–428,445–454`.

**Failure scenario, reproduced:** solve a valid puzzle and a structurally valid puzzle with one bit flipped in its commitment in the same invocation. The valid job finishes successfully; the other returns `CS_EPUZZLE`. `solve_all` deletes the successful job's checkpoint, then returns a nonzero aggregate status. `cmd_solve` tests that aggregate status before printing *any* keys, so stdout is empty. The valid job's key is then zeroed and freed. With long puzzles, this loses potentially substantial completed work. Interrupting a batch after some jobs finish has the same result.

The reproduction used vector case 2 as the valid puzzle, its checkpoint as the resume point, and a second copy with puzzle byte 36 XORed with 1. Exit status was 1, stdout was empty, and the successful checkpoint was gone.

**Suggested fix:** emit results for every started, completed `CS_OK` job regardless of other jobs' outcomes, while returning an aggregate failure status. Do not delete a successful checkpoint until its key has been durably handed off or successfully written; account for stdout failures as well. Distinguish unstarted/uninitialized jobs from successful jobs.

### 7. major — The Python CLI writes secret keys with public default permissions

**Locations:** `ref/chainseal_ref.py:268–270,447–448`; `SPEC.md:177`.

**Failure scenario, reproduced:** with ordinary umask `022`, run reference `encrypt ... --secret-out ref.sec` in a searchable shared directory. The resulting file is mode `0644`, including the plaintext session key. Other local users can bypass the delay entirely. `open(path, "wb")` also follows existing symlinks and preserves overly permissive permissions on existing files. The reference agrees with the cryptographic spec, but its runnable CLI does not enforce the secrecy boundary emphasized by the spec. The C tool correctly creates secret/checkpoint temporary files as `0600`.

**Suggested fix:** give the reference a private, exclusive temporary-file-and-replace path for secret outputs, with mode `0600`, or remove its use as a real encrypting CLI and prominently constrain it to disposable test data. Do not rely on the test script's private temporary directory to establish general secret-file safety.

### 8. minor — Raw chain-step and labelled start-hash domains overlap

**Locations:** `SPEC.md:13,41,65`; `src/chainseal.c:120–124`; `src/chain.c:21–25`.

**Concrete counterexample, reproduced:** let `b=13`, `i=1`, and

```text
salt = 00000000000001000000000000000000
x    = salt[7:16] || be32(1)
A    = 0x12 || "chainseal/v1/start" || salt || be32(1) || x
```

Then `len(A)=52` and `A[32:52]=salt || be32(1)`. Consequently `TH("chainseal/v1/start", salt || be32(1) || x)` equals `F_1(A[0:32])` because these are the **same SHA-256 input**, not because of a collision. The length prefix separates the six labelled hashes from one another, but not from the unlabelled chain function.

This is a domain-separation limitation, not a demonstrated shortcut for honestly randomized default puzzles: an actual chain must reach the specially structured state, and this example also uses a specially structured salt. The C and Python implementations agree on it.

**Suggested fix:** in a revised format, prefix raw chain steps with a reserved domain byte distinct from the label-length bytes; a 53-byte message still fits one SHA-256 padded block. Alternatively explicitly analyze and document overlapping domains rather than treating every use as an independent oracle. The current wire/version and backend padding would need coordinated updates if the function changes.

### 9. minor — Valid work counts overflow the progress counters

**Locations:** `src/chainseal.c:135,164,209–215`; `src/cli.c:274–282,359–375`; `SPEC.md:30–31`.

**Failure scenario, established arithmetically:** allowed `n=2^20, m=2^48` has `n*m=2^68`; the `uint64_t` total becomes zero. At the also-valid cursor `i=65537,j=0,m=2^48`, `cursor_done` wraps `2^64` to zero. Progress percentages, elapsed-work/rate estimates, and aggregate totals can therefore be wrong or divide by zero in floating point. Summing multiple individually representable puzzles can overflow too.

This does **not** shorten the cryptographic solve: the actual loops use bounded `i` and per-chain `j`, not the product. Encoded checkpoints remain capable of representing their positions.

**Suggested fix:** use checked wider arithmetic for exact totals, or floating-point totals explicitly limited to presentation with suitable zero/overflow handling. Preserve the specified parameter range unless the spec is intentionally revised. Add arithmetic-only tests at the valid maxima; no astronomical solve is needed.

### 10. minor — Non-finite timing arguments can silently remove the requested delay or trigger UB

**Locations:** `src/cli.c:97–100,119–124`; `src/util.c:146–156`; also `src/bench.c:205`.

**Failure scenarios, reproduced:** `gen -q -n 1 -d 60 --step-ns inf -o FILE` succeeds with encoded `m=1`. `gen -q -n 1 -d inf --step-ns inf -o FILE` reaches a NaN-to-`uint64_t` conversion; the scratch ASan/UBSan build aborts with `src/cli.c:124:24: runtime error: nan is outside the range of representable values of type 'unsigned long long'`. The ordinary sanitizer suite does not exercise these inputs. Non-finite benchmark durations can likewise reach time/integer conversions.

**Suggested fix:** require finite positive parsed values and finite intermediate results before division, `ceil`, or integer conversion; reject overflows and unusable underflows with a usage/range error.

### 11. minor — An `fsync` failure leaks the output descriptor

**Location:** `src/util.c:83–95`.

**Failure scenario, reproduced with failure injection:** if `fsync(fd)` returns `EIO`, short-circuit evaluation skips `close(fd)`. The error branch nevertheless sets `fd=-1`, preventing cleanup from closing it. A scratch wrapper confirmed `write_file=-1` while `fcntl(original_fd,F_GETFD)` still succeeded. Repeated periodic checkpoint failures can exhaust the process's descriptors and retain unlinked files until process exit.

**Suggested fix:** execute synchronization and closure separately, preserve the first error, and close every successfully opened descriptor on all paths. The current same-directory `O_EXCL` temporary file and rename correctly give atomic replacement during ordinary execution. They do not guarantee crash-durable directory entries without a parent-directory `fsync`; document that distinction or add directory synchronization if durable checkpoint publication is intended.

### 12. minor — CLI tests can fail without a product regression

**Locations:** `tests/cli.sh:41–42,59–75`.

**Failure scenarios, established from the test:** the tag-tampering test overwrites the last tag byte with `0x01`. If the valid random tag already ends in `0x01` (approximately 1/256 runs), nothing is changed and the test incorrectly expects authentication failure. The interrupt test sleeps a fixed second before sending SIGINT; on hardware completing its 60-million-step solve in less than a second, `kill` fails or the process has already returned success. The second interrupt has a similar fixed-time assumption.

**Suggested fix:** XOR a bit so tampering is guaranteed, and coordinate interruption with a running solver/observable checkpoint state or use a deliberately bounded test hook. Keep timeouts for hangs, but do not use machine speed as the assertion's premise.

## Checks and evidence

All builds and scratch probes were confined to `/tmp/chainseal-audit.KgSP4J`; source files in the audited checkout were not modified. Environment: Apple M4, arm64 Darwin 27, Apple clang 21.0.0. The scratch directory contains logs and reproductions, but the findings above include the necessary inputs and explanations so that this report does not depend on retaining that directory.

| Check | Result and scope |
|---|---|
| `make test` | Passed: 1,755 unit checks; ARMv8 and portable backend self-tests; byte-for-byte vector regeneration; CLI tests; Python validation of 7 valid cases and 50 invalid inputs; cross-language encryption/solving in both directions. |
| `make sanitize` | Passed the same suite under AddressSanitizer/UndefinedBehaviorSanitizer. The additional non-finite argument probe nevertheless exposed UB, as described above. |
| `make tsan` | Passed its unit tests and CLI tests. A separate injected second-thread creation failure exposed the cancellation race. |
| C negative vectors | A separate ctypes harness called the actual C puzzle, envelope/open, secret, and checkpoint decoders on all 50 published invalid cases. All were rejected. |
| Maximum encoded sizes | C accepted the structurally valid maximum envelope of `50,331,776` bytes: `n=2^20,b=32,L=2^24,m=2^48`. No enormous chain was evaluated. |
| `demo.sh` | Passed; both paths recovered the 110-byte transaction. The bytes match the [EIP-155 example](https://eips.ethereum.org/EIPS/eip-155). Fresh run: approximately 282 ms generation, 3.1 s solving, 7 ms fast open; these are local observations, not security bounds. |
| x86 compile | `clang -target x86_64-apple-macos11 -std=gnu11 -O3 -Wall -Wextra -Wshadow -c src/chain.c -o /tmp/chainseal-audit.KgSP4J/chain-x86.o` succeeded; output is an x86-64 Mach-O object. A Darwin target was used because its SDK is installed; this is not a Linux link/run test. |
| x86 instruction-flow emulation | A scratch copy retained the production SHA-NI macros/functions and replaced intrinsics with scalar implementations of their instruction semantics, disabling ARM selection. All 1,755 unit checks passed with the emulated SHA-NI and portable backends. This does not validate hardware execution, generated machine code at runtime, or real CPUID dispatch. |

### SHA-NI review conclusion

**I believe `src/chain.c:131–241` is correct.** I found no state-order, endianness, message-schedule, or feature-bit defect. This conclusion is supported by cross-compilation and instruction-flow emulation, not by execution on a SHA-capable x86 processor. Real-hardware self-tests, vectors, sanitizer tests, and cross-checks remain an important validation task before describing that backend as tested.

The review followed [Intel's SHA instruction flow](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html). In particular:

- Lines 168–172 map natural IV words to low-to-high lanes `[F,E,B,A]` and `[H,G,D,C]`, the instruction's ABEF/CDGH representations.
- Lines 143–149 add each four-word `K` group, execute two rounds into S1, select words 2/3 using shuffle `0x0E`, and execute two rounds into S0. No byte swap is required: inputs are already numeric SHA words.
- Lines 151–162 apply `msg1` in groups 1–12; `alignr(Mc,Mp,4)` supplies the four `W[t-7]` words; `msg2` in groups 3–14 finishes the next message group. Lines 180–195 cycle registers through all 64 rounds without consuming a partially scheduled group.
- Lines 197–200 add the IV and restore `[A,B,C,D]`, `[E,F,G,H]` for the next hash step. Every step resets the compression state to the IV.
- Lines 205–229 load the salt/index/padding in natural word order and correctly handle paired and odd lanes. Lines 233–238 check SSSE3, SSE4.1, and SHA at the appropriate CPUID leaves/bits. No AVX/OSXSAVE requirement is introduced by these XMM-only operations.

### Important gaps in the committed tests

- The C vector target regenerates and compares JSON; it does **not** feed the 50 invalid vectors into the C decoders. The Python checker does. The separate audit harness closed this gap for the reviewed commit, but the regression suite should retain it.
- Mutation fuzzing primarily mutates an envelope. Feeding those same bytes to other decoders usually exercises only their magic rejection. Random garbage with corrected magic usually fails very early too. Dedicated mutations of valid secret/checkpoint/puzzle seeds, truncations at every boundary, and large structurally valid inputs would exercise substantially more parsing logic.
- There is no real SHA-NI run, ARM feature-dispatch deployment matrix, full Linux run, resource-failure injection, mixed-success batch assertion, non-finite numeric input test, or maximum-work counter test. The reference secret-file mode is not checked.
- Generation's thread-count/backend determinism tests are useful. They do not exercise partial creation failure or the generation progress callback under a terminal. Checkpoint tests cover several mid-chain and end-chain stops, including final `j=m`; the CLI covers one interrupted solve and a mismatched puzzle ID. Multiple concurrent cancellation, periodic write failures, and tampered checkpoint *state* followed by the final commitment check are not directly covered.
- The toy guessing test/benchmark checks a chosen search strategy's outcomes. Neither establishes a lower bound for every solver. The archived `123/400` versus expected `100/400` is approximately 2.66 standard deviations and within its four-standard-deviation tolerance, not evidence of a violated probability bound.

## Things checked and found correct

- **Cryptographic bytes and parsing:** the six labelled-hash prefixes are distinct and prefix-free; their actual arguments have fixed or explicitly determined lengths. `ctx` exactly binds version, link width, reserved bytes, `n`, `m`, and salt. The fixed magic need not be duplicated inside that context. Puzzle links are intentionally absent from the key commitment, but the full envelope tag and checkpoint ID bind them. Consequently commitment checking alone is not a proof of puzzle well-formedness, as documented.
- **Core construction:** generation masks `x_(i+1)` with the first `b` bytes of `y_i`; solving unmasks in the correct direction and checks the final commitment. The raw step is precisely SHA-256 of 52 bytes, padded with `0x80000000` and a 416-bit length. ARMv8 and portable results agree with the independent Python/hashlib implementation. No practical shortcut for honestly randomized default parameters was found. Salt/index suffixes separate different chain indices and prevent generic segment reuse across fresh independent salts; this is probabilistic salt isolation, not an absolute uniqueness guarantee. Repeated salts with the same index permit work reuse, including across differing `n/m` settings, because those settings enter the final context rather than every step.
- **Envelope composition:** distinct labels derive encryption/MAC subkeys; counters are 64-bit big-endian and cannot wrap within a 16-MiB message. The tag covers every pre-tag byte, including all headers/reserved fields, the entire puzzle, nonce, length, and ciphertext. `cs_open` verifies commitment and tag before writing any plaintext. Comparison loops have no data-dependent early exit; Python uses `compare_digest`. Full 32-byte commitments provide a generic approximately `2^128` collision-work target, whereas a 16-byte commitment has approximately `2^64` birthday work. These figures do not by themselves prove every confidentiality/authentication claim.
- **Nonce/key reuse:** C's operational paths use OS randomness for salts, links, and nonces; deterministic generation is confined to testing/explicit low-level APIs. Distinct random nonces support reuse of a secret key under the stated cryptographic assumptions. Nonce collision risk is approximately `q(q-1)/2^129` for `q` encryptions. Repeating a nonce repeats the stream and exposes plaintext XOR. Reusing a puzzle also reuses its release time; the publication-clock warning in SPEC §8 is correct. The low-level C/Python seal functions accept supplied nonces and rely on their caller to honor this requirement.
- **Bounds and concurrency:** validated `n*b` and `n*32` are at most 32 MiB, and the maximum envelope fits even a 32-bit `size_t`. Bounds/remaining lengths precede ciphertext indexing and allocation; all four library decoders enforce exact lengths, magic, version, reserved bytes, and applicable parameter ranges. Generation assigns disjoint chain groups atomically, joins workers before consuming results, and correctly handles partial/no worker creation. Solve job data are read after joins or through atomics, apart from the cancellation flag finding. No input-driven buffer overrun was found in the reviewed decoders.
- **Checkpoints, storage, and erasure:** checkpoint IDs hash the canonical complete puzzle; cursor state, endianness, and `j=m` resume transitions agree in C/Python. Stored state is deliberately unauthenticated, so a modified checkpoint can waste work but still cannot bypass the final commitment check. C output replacement uses exclusive same-directory temporary files and rename; C secrets/checkpoints use owner-only creation permissions. `secure_zero` uses volatile stores, and key/subkey, generated-link, chain-end, and successful plaintext buffers are cleared on principal paths. Erasure is incomplete: for example `read_key` frees its raw key-file buffer without wiping it (`src/cli.c:464–469`), `chain_start` and SHA compression retain stack intermediates, and stopped solves return before the normal local cleanup. Python has no comprehensive secret-erasure guarantee. These are residual hardening limits, consistent with the explicit side-channel non-goal, not evidence of complete zeroization.

### README claim and number reconciliation

| README lines | Assessment |
|---|---|
| 3–7, 54–58 | The intended honest workflow and SHA-256-only cryptographic building blocks are implemented. OS entropy, threads, and operating-system APIs are also required. The connection to MMV is substantively faithful, with the qualifications in finding 2. The format is specified; uniform conformance and all security claims are not yet established. |
| 11–19 | Advertised test commands and demo work on the audited M4. Build requirements also include a supported POSIX/BSD/Linux environment, pthreads, and the platform RNG; a generic C11 compiler plus make is not sufficient on every OS. Tests/demo additionally use ordinary shell utilities; the demo uses `xxd` and Perl. |
| 22–28 | Backend computation is credible; availability/forcing/runtime claims need finding 4's correction. |
| 33–50 | `64*2^28 = 17,179,869,184` steps. At 23.1 ns, this is 396.855 seconds or 6.614 minutes. At the archived 64-chain throughput of 423.4 M steps/s, build time extrapolates to 40.576 seconds, consistent with “about 40 s.” Finite normal delay selection and the three opening modes work. Interrupt/resume works in the tested single-job path; batch failure handling and cancellation require fixes. |
| 60–67 | All size formulas and examples are correct: 836 and 6,212-byte puzzles, +60-byte envelope overhead, +40-byte secret overhead, and 84-byte checkpoints. |
| 71–77 | The archived latency median is 23.27 ns; 23.07 ns is its best sample, explaining the README's 23.1. All-core throughput is 465.3 M steps/s, giving an ideal ratio about 10.75. Actual archived build ratios approach 11 at larger `n`, but are 9.87 at `n=64` and 9.56 at `n=16`. “Once n is at least the number of cores” is an imprecise saturation rule: this backend schedules two-chain groups, and sufficient groups/load balancing are needed. Label best versus median and distinguish aggregate throughput from actual build ratios. The checked-in file contains benchmark output, not a separate demo log; the audit reran the demo successfully. |
| 83–91 | Commitment verification and hardware-latency caveats are correct. Integrity and universal delay language require findings 1–2. The `2^-45` arithmetic is correct for the specified classical final-link attack. |
| 95–100 | Well-formedness proofs, publication control, metadata hiding, extra side-channel hardening, and network scheduling/spam solutions are genuinely absent. “Cannot use more than one core” should describe the implemented honest dependency-following solver, not forbid speculative/exhaustive parallel attacks. |
| 104–113 | The source-layout descriptions match. Python is functionally independent of C, using its standard-library cryptographic implementations and separately written parsing. Source inspection cannot establish the historical assertion “written from SPEC.md alone,” or prove that no human has reviewed the project. The attribution to Vitalik's proposal lacks a precise primary citation in the repository and was not independently verified; add one before circulation. |

The current division between primitive hashing, chain backends, puzzle/envelope logic, and CLI/file operations is useful and does not warrant an architectural rewrite. Repair the concrete boundaries above and add focused regression checks. The absence of proof-of-well-formedness, network policy, or production hardening is not independently a blocker for the explicitly scoped PoC; the incorrect claims and confirmed operational defects are.

VERDICT: fix-first
