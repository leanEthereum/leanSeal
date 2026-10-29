# Round 13: the paper and the whole repository

Audited `b1bdcd6` (`b1bdcd628984637f8fc217a333ff470e121c95bc`) on 2026-10-28 by OpenAI's GPT-5.6 Sol, against research-paper correctness, repository correctness and production-release readiness. The report is reproduced as received, with its links to GitHub shortened to repository paths; the changes it led to are in [README.md](README.md).

**Recommendation:** request changes for a release; suitable to continue as an explicitly labeled research artifact.

## Executive assessment

The central construction, byte format, Rust implementation, Python reference, Solidity decoder/opener, and the classical random-oracle delay theorem are internally consistent at the audited revision. I found no mismatch that lets a malformed encoding bypass canonical decoding, no disagreement between the Rust and Python cryptographic computations, no invalid-key or invalid-tag acceptance path, and no evident gap in the stated classical theorem. The theorem's round count, path-value count, probability terms, parameter table, sizes, and headline arithmetic all recompute correctly under the paper's stated model.

The repository is nevertheless not ready to protect value. One confirmed release-blocking CLI defect can leave an envelope published after the command has failed and discarded its only fast-path key. The paper also lacks a reduction for the encryption layer, its exact encoding has no quantum proof, its sequentiality proof has not been machine-checked or reviewed by a human cryptographer, and the 3.5 ns attacker latency is a transparent but unvalidated hardware design point. The EVM component is appropriately labeled a research PoC and deliberately provides application-level position protection only for a tightly restricted guarded pool, not a general encrypted mempool.

### Findings

| Severity | Finding | Gate |
|---|---|---|
| **Major** | Fresh `encrypt --secret-out` commits the envelope before it preserves the secret; any later secret-write failure leaves the envelope and destroys the fast path | Blocks CLI/crate release |
| **Low** | `sealnet send --expiry` can wrap a `u64` block offset in release builds, contrary to the README's overflow claim | Fix before relying on the PoC tooling |
| **Low** | The paper compares Bitcoin SHA256d trials per second directly with single-compression random-oracle queries; the normalization is ambiguous by roughly a factor of two | Correct or qualify the concrete comparison |

No Blocker-level construction or proof defect was found. "No defect found" is not a claim of cryptographic assurance: the missing independent review and missing reductions remain explicit evidence gaps.

## Confirmed findings

### Major — a failed secret write leaves a published envelope and loses the fast-path key

**Evidence status:** reproduced in both the Rust CLI and independent Python reference. This is a release blocker, not a defect in the underlying puzzle or envelope format.

The fresh-puzzle form of `encrypt` produces two logically coupled outputs: an envelope and a secret containing the puzzle key. The Rust CLI writes the envelope at `src/main.rs:620-628`, then attempts `save_secret`. The Python reference has the same order at `ref/leanseal_ref.py:502-511`. Each individual file write is atomic, but the two-output operation is not failure-atomic.

Consequently, a missing directory, permission failure, full disk, rename failure, or the post-write case-alias check can occur after the envelope is already visible. The key then exists only in wiped process memory. The puzzle can eventually recover it, but that defeats the sender's fast path and can be operationally equivalent to key loss for a long-delay puzzle. With `-o -`, the envelope can already have been streamed to a downstream publisher before the secret failure is reported.

Reproduction from the repository root:

```sh
t=$(mktemp -d)
printf msg > "$t/msg"
target/release/leanseal encrypt -q -n 1 -m 1 \
  -i "$t/msg" -o "$t/rust.env" --secret-out "$t/missing/rust.sec"
```

Observed result:

```text
exit status: 1
rust.env: 155 bytes, begins LSEN
rust.sec: absent
diagnostic: .../missing/rust.sec: No such file or directory
```

The equivalent Python command also exited 1 while leaving a 155-byte `LSEN` envelope and no secret.

The case-insensitive-path regression tests currently require the leftover envelope rather than requiring cleanup: `tests/cli.sh:71-75` and `tests/cross.sh:32-39`. Those tests prevent the earlier, worse behavior—overwriting the envelope with a key-bearing secret—but they also codify the new incomplete outcome.

**Resolution condition:** preserve the secret before making the envelope visible, or stage and commit the pair as a coordinated operation. A practical ordering is: validate destinations; write the private secret first; recheck identity now that one destination exists; only then publish the envelope. If the post-create alias check fails and both final paths were initially absent, remove the newly created secret and leave no envelope. Add Rust and Python regressions for an invalid/unwritable secret destination, case aliases, stdout envelopes, and envelope-write failure. On every failure, either no envelope should be visible or a recoverable secret should remain.

### Low — the PoC sender wraps an explicit expiry offset

**Evidence status:** statically established. It affects the research node's CLI, not the core library or contracts.

`Args::num` accepts every `u64`, but `poc/node/src/main.rs:161` computes:

```rust
let expiry = p.get_block_number().await? + a.num("expiry", 100)?;
```

Release arithmetic wraps. At any positive head block, `--expiry 18446744073709551615` therefore produces an expiry in the past rather than an error. A sender can reveal successfully and recover its deposit, but the committed call will later fail its expiry check. This contradicts the broad statement that numeric overflow is rejected in `poc/README.md:77`.

**Resolution condition:** use `checked_add` and report that the expiry offset exceeds the representable block range; add a unit test covering `u64::MAX` at a nonzero head. The normal default and realistic offsets are unaffected.

### Low — Bitcoin hashrate and theorem queries use different units

**Evidence status:** arithmetic and terminology issue; the theorem itself remains correct for the explicitly chosen `R = 10^21` query/s budget.

The paper sets `Q_on = R T`, calls `R = 10^21` "roughly the whole Bitcoin network," and obtains about `2^-117` at `paper/sections/security.tex:35-36` and `paper/sections/security.tex:46`. The proof counts calls to a random oracle, while one leanSeal chain step is one SHA-256 compression.

Bitcoin's conventional network hashrate counts completed block-header SHA256d attempts. Bitcoin Core defines its block hash as double SHA-256 in `src/hash.h`, and `getnetworkhashps` reports estimated network "hashes per second" in `src/rpc/mining.cpp`. With the first header block precomputed as a midstate, a nonce trial still performs roughly two compression invocations: one for the remaining header block and one for the second SHA-256. It is therefore not literally the same unit as a single-compression query budget.

If the comparison is normalized as `R = 2 × 10^21` compression calls/s, the dominant 24-byte-link term changes from log2 probability `-117.33` to `-116.33`. This is only one bit and does not alter the design conclusion, but the paper presents a precise exponent.

**Resolution condition:** either define `R = 10^21` as an intentionally hypothetical random-oracle query budget and describe Bitcoin only as an order-of-magnitude analogy, or state a conversion from SHA256d trials to compression calls and recompute the displayed exponent. The comparison should also note that deployed mining ASICs are not necessarily repurposable for arbitrary salted chained inputs.

## Paper audit

### Construction and proof

The construction is a faithful strengthened instantiation of Mahmoody–Moran–Vadhan's chained random-oracle puzzle. Their Section 4 construction hides each next link under the previous oracle output and Section 4.1 replaces each oracle call by an iterated chain; leanSeal adds explicit domains, a fresh salt, per-chain indices, an accumulator over every chain end, a derived key, and a commitment. These additions prevent cross-domain input aliasing, make puzzle work puzzle-specific, and ensure a guessed later link does not eliminate the need for earlier chain ends.

The exact schedule recomputes:

- opener key round: `T_key = n(m + 2) + 1`;
- opener commitment-check round: `T_key + 1`;
- generator: `m + n + 3` rounds;
- path values: `P = nm + 3n + 1 = n(m + 3) + 1`.

The appendix's ideal/real coupling is coherent. In the ideal experiment, masked links and the commitment are uniform; legitimate queries reveal a path value only after all predecessors were available in earlier rounds. The Bad event covers path-value collisions and every non-legitimate hit on a real path input. Starts are charged to hidden-link entropy online and salt-plus-link entropy before publication; every other premature query must guess an unrevealed 256-bit predecessor. The resulting bound

```text
Q_on / 2^(8b) + Q_pre / 2^(128+8b) + (Q P + P^2 + 1) / 2^256
```

matches the proof's union bounds. The `n = 1` exception is correct because there is no hidden next link. The handling of `C` as independent in the ideal experiment is coupled back to `H_commit(ctx || K)` through the non-legitimate-query Bad event.

The citation to Pietrzak–Reyzin is appropriately phrased as following the *structure* of their proof, not as inheriting their theorem. I inspected the cited October 2026 version of "Optimal Proofs of Sequential Work": its Lemma 6 rules out random-oracle collisions/lucky guesses, and Lemma 9 turns a consistent dependency path into sequential time. Those are indeed the two proof motifs used here. The MMV attribution and the qualified Afshar et al. quantum statement are also accurate: the paper explicitly does not claim a quantum proof for leanSeal's exact encoding.

I found no proof error, but the confidence boundary matters:

- the proof has not been machine-checked;
- no human cryptographer is reported to have reviewed the proof, format, or code;
- the theorem proves early *key recovery*, not indistinguishability of encrypted envelopes;
- the theorem is classical and idealizes disjoint SHA-256 domains as independent random oracles.

### Concrete arithmetic

Independent recomputation confirms the displayed values under `R = 10^21`:

| Case | Recomputed log2 bound | Paper |
|---|---:|---:|
| 30 s, 16-byte links | -53.33 | about `2^-53` |
| 30 s, 24-byte links | -117.33 | about `2^-117` |
| 30 s, 32-byte links | -148.34 | about `2^-148` |
| one year, 24-byte links, `n = 33` | -97.33 | about `2^-97` |
| one year, 32-byte links, `n = 33` | -108.33 | about `2^-108` |

The reference parameters `n = 16`, `m = 2^29`, `ell = 3.5 ns` give 30.0648 seconds. The 452-byte puzzle, 512-byte addition for an empty/plain transaction envelope, and 152-byte one-chain addition follow the normative format exactly. The one-year need for at least 33 chains follows from `m <= 2^48`.

### Hardware and performance claims

The paper handles its weakest empirical premise responsibly. It calls 3.5 ns a model/design point, not a lower bound; distinguishes total fleet throughput `R` from feedback latency `ell`; states that the cited 7 nm core was synthesized rather than fabricated; and gives linear sensitivity if either estimate is wrong. The cited Baldanzi et al. paper supports the reported 67 cycles at 5.15 GHz and 7 nm synthesis basis.

The local benchmark logs substantiate the M4 and x86 numbers as measurements, and the documentation marks the 30-second times and large GPU batches as projections. I did not independently benchmark a custom ASIC or reproduce multi-minute production-sized measurements. The paper should therefore continue to describe 3.5 ns as a repricable assumption, never as a physical lower bound.

### Exposition and claim discipline

The paper is structurally strong: it introduces the application failure mode before the primitive, separates construction from deployment, gives the security model before concrete pricing, and returns to limitations in a dedicated section. The theorem's scope paragraph is especially valuable. The limits that most papers would bury—malformed puzzles, reveal optionality, excluded-transaction disclosure, sender cost, absent encryption reduction, classical-only proof, and hardware uncertainty—are prominent and repeated consistently in the README and security guide.

The title is broader than the PoC's actual application scope, but the abstract and body quickly make clear that leanSeal is a fallback disclosure mechanism and not binding execution. I do not treat that as a defect while the current caveats remain.

The rebuilt PDF has 26 pages, no undefined references or citations, and text identical to `docs/leanseal.pdf`. There are three minor overfull boxes in the comparison table and two underfull bibliography lines; they do not impair reading.

## Core Rust, reference implementation, and format audit

### Format and cryptographic behavior

The normative format is implemented consistently:

- all decoders enforce magic, version, zero reserved fields, parameter ranges, multiplication bounds, exact derived length, and no trailing bytes;
- commitment validation precedes fast-path use of a key;
- envelope authentication covers the complete header, puzzle, nonce, length, and ciphertext;
- tag verification occurs before plaintext release;
- nonces are drawn from the OS in production;
- key, plaintext, secret-file buffers, HMAC state, chain ends, and solve cursor secrets use explicit best-effort wiping;
- checkpoints bind to a full puzzle identifier and are correctly documented as unauthenticated, so corruption ends in a commitment failure rather than trusted state;
- the ARMv8, x86 SHA-NI, and portable backends agree with ordinary SHA-256 and with each other on available hardware.

The Rust library denies unsafe code globally. Unsafe blocks are confined to the architecture intrinsic modules, which perform runtime feature detection before use. I found no production `unwrap`, `expect`, or panic path in attacker-controlled decoding; the apparent occurrences are in `#[cfg(test)]` code. Allocation sizes are derived only after bounded parameter/length validation.

The home-grown encryption is straightforward encrypt-then-MAC and is consistent across Rust, Python, and Solidity. It is not standard AEAD, and the authors correctly decline to claim a full confidentiality reduction. Production use should either supply that reduction and independent review or replace the envelope layer with a well-reviewed standard construction compatible with the project's assumptions.

### Testing and independence

The Python implementation is meaningfully independent: it does not call Rust code and separately implements parsing, puzzle derivation, solving, sealing, and opening. Deterministic vectors expose intermediate starts, chain ends, accumulator states, key, commitment, encodings, and a checkpoint, so agreement is deeper than a final round trip. Cross-tests run both directions.

The Solidity implementation separately validates the byte format and opens vectors. The decoder mutation test exercises 480,000 derived malformed inputs on every normal test run. Historical audit evidence records 10.5 million local fuzz executions in round 11 and approximately 108 million earlier ASan inputs; the new weekly GitHub fuzz workflow has not yet recorded a run at this newly added head revision.

### API and abstraction review

The main abstractions are justified by real boundaries: `Puzzle` owns validated puzzle state; `Envelope` owns authenticated message framing; `Cursor` owns resumable sequential progress; `Backend` isolates runtime-selected chain execution; and `Secret`/`Wiped` centralize erasure. The duplicated Rust/Python/Solidity implementations are intentional independent oracles rather than abstraction drift.

`src/main.rs` is large and mixes parsing, command dispatch, file policy, benchmarks, and diagnostics, but I found no second concrete ambiguity beyond the two-output write ordering. Splitting it could improve maintainability, but it is not an acceptance gate. The PoC node is similarly monolithic but remains a clearly labeled demo. I found no production trait/helper layer whose only purpose is test support and no fabricated synchronized domain model.

## EVM proof-of-concept audit

The current PoC addresses the most serious issues recorded in audit rounds 10–12:

- senders must use the inbox's canonical EIP-7702 delegate at submission and execution;
- target restrictions are fixed before submissions begin;
- the guarded pool locks direct transactions while a ticket is queued;
- a censored/missed reveal is marked `Missed`, forfeits the net penalty, and **never executes later**;
- `forceOpen` only publishes the key and pays the bounty;
- execution is ordered by slot and cursor, state advances before external calls, reentrancy is serialized, and low gas preserves prior batch progress;
- keepers cap calldata, halve a rejected batch, and reconcile state after restart;
- demo token minting is owner-restricted.

The 32 contract tests cover format validation, wrong keys/tags, canonical delegation, target restrictions, pending-reveal front-running, censored reveals, queue ordering, reentrancy, gas exhaustion, batch progress, deposits, and the intentional cancellation-after-reveal weakness. The full demo also succeeded: the plaintext trade was sandwiched; the pending key attack against a sealed trade reverted while the pool was locked; the sealed trade executed at its committed position; and a withheld ticket was later solved, published, paid, and remained cancelled.

The PoC's documented limits are security properties, not minor operational TODOs:

- an honestly revealed sender can still cancel by moving funds, revoking approval, or changing delegation after recovering the deposit;
- no efficient check proves a submitted puzzle is solvable;
- one paid ticket per block can keep the guarded application locked;
- keepers have no protocol fee;
- reorg handling is restart/reconciliation, not finality;
- protection covers only allowlisted, non-adaptive guarded applications;
- a builder controlling the reveal window can censor a reveal and make the honest sender lose the net penalty;
- all batch plaintexts are known before execution, so arbitrary programmable targets would enable adaptive behavior unless the protocol supplies immediate top-of-block execution.

These limitations justify the README's "not ready for real funds" statement. The prototype demonstrates an application-level analogue of the ordering property; it is not a production implementation of LUCID or a general encrypted mempool.

### Dependency state

The core crate's `cargo audit --deny warnings` is clean. The PoC node's lockfile contains:

- `RUSTSEC-2026-0387` in `crypto-bigint 0.5.5`, reached through Alloy/k256 and explicitly ignored by CI because the latest Alloy release has not moved to the fixed line;
- unmaintained warnings for `derivative 2.2.0` and `paste 1.0.15`.

The timing advisory affects the local ECDSA signer, not the leanSeal primitive. The demo signs only Anvil's published keys, so the repository's scoped acceptance is reasonable. It is not acceptable for real-value deployment; upgrade Alloy/k256/crypto-bigint and reassess the full dependency tree first. The two unmaintained transitive warnings should be tracked even though they are not current vulnerabilities.

## Documentation audit

The documentation is unusually good for a research cryptography repository:

- the root README gives a usable conceptual model, status warning, quick start, measured-vs-modeled table, and document map;
- `SPEC.md` is genuinely normative and detailed enough for an independent implementation;
- `docs/security.md` separates primitive guarantees, mempool guarantees, assumptions, and exclusions;
- `docs/benchmarks.md` labels measured values, projections, machine context, and raw logs;
- `poc/README.md` describes the state machine and its adversarial limits instead of presenting only a happy path;
- audit history records prior findings and fixes.

Cross-document terminology and numerical values are consistent. The two corrections are the PoC expiry-overflow sentence and the Bitcoin-query unit qualification described above. The repository should retain the root research warning and the paper's explicit statement that no human cryptographer has reviewed the code or format.

## Validation performed

All validation used the clean detached worktree at the exact audited SHA. `HEAD` and `origin/main` matched at the end, `git diff --check` passed, and the worktree had no tracked changes.

| Check | Result |
|---|---|
| `make test` | Passed: 25 Rust tests, hardware self-test, exact vectors, CLI suite, 8 Python cases/51 invalid inputs, bidirectional cross-tests |
| `cargo fmt --check` | Passed |
| `cargo clippy --release --all-targets --locked -- -D warnings` | Passed |
| `cargo package --locked` and tests from extracted package | Passed; 34-file package, all packaged tests passed |
| Core `cargo audit --deny warnings` | Passed; 21 dependencies scanned |
| PoC node clippy/test | Passed; 1 unit test |
| PoC node `cargo audit` | Expected failure on `RUSTSEC-2026-0387`; passes with the documented ignore and reports two allowed unmaintained warnings |
| `forge fmt --check` | Passed |
| `forge test` | Passed: 32 tests (25 protocol, 7 crypto/format) |
| `PORT=18641 FORCE_WAIT=180 bash poc/demo.sh` | Passed end-to-end |
| Clean paper rebuild | Passed; 26 pages, no undefined citations/references |
| Generated PDF text vs `docs/leanseal.pdf` | Identical |
| GitHub checks at exact SHA | All completed successfully: macOS, x86 Linux, ARM Linux, MSRV, dependency audit, PoC, Pages deploy |

### Validation limits

- I did not run the new four-target, ten-minutes-each scheduled fuzz workflow at this exact SHA; it has no GitHub run yet. Normal mutation tests and historical fuzz evidence passed.
- I did not audit the implementations of SHA-256, Foundry, Alloy, or every transitive dependency beyond their use and advisory state here.
- I did not build or measure custom SHA-256 silicon.
- I did not model public-chain reorgs, builder censorship economics, or long-lived keeper incentives beyond code and tests.
- This remains an AI audit. It does not replace independent human cryptanalysis, formalization, or a production smart-contract audit.

## Release and research recommendations

### Before the next software release

1. Fix the two-output envelope/secret commit order in Rust and Python and invert the alias/failure tests so a failed command never leaves an unrecoverable envelope.
2. Add checked expiry arithmetic to `sealnet` and a boundary test.
3. Clarify or normalize the paper's Bitcoin SHA256d-to-compression comparison.
4. Let the scheduled ASan fuzz workflow complete on the corrected head.

### Before any claim of production readiness

1. Obtain independent human review of the construction, exact proof, envelope design, Rust unsafe backends, and Solidity contracts.
2. Write and review a confidentiality/integrity reduction for the complete envelope layer, including nonce collisions and multiple envelopes per puzzle, or adopt a standard reviewed AEAD/KDF construction.
3. Formally check the delay proof or at least produce a second independent proof with explicit oracle/domain modeling.
4. Replace the modeled 3.5 ns design point with conservative evidence from an implemented chain-specialized design, and document repricing policy.
5. Resolve the signer timing advisory and reassess all PoC dependencies.
6. Redesign the application/protocol layer if the goal is general encrypted-mempool execution rather than disclosure plus a deposit; the current guard/allowlist prototype cannot supply that property.

## Final verdict

**Research paper:** no construction or classical-proof error found; accept as a candid research artifact after the Low quantitative clarification.  
**Core primitive/library:** internally consistent and strongly tested, but do not release the affected CLI workflow until the Major two-output failure is fixed.  
**PoC:** valuable adversarial demonstration, correctly scoped as non-production; not suitable for real funds.  
**Production security:** insufficient evidence, even after the CLI fix, until the missing reductions, independent review, hardware validation, dependency remediation, and protocol-level execution questions are addressed.
