# Round 7: hashed link masks and finished cursors

Audited `2dd794ca7b78a4e829be44c034e08262d7a246a1` on 2026-10-21. **Fix first:** the new mask is implemented consistently in C and Python, the old raw-mask attacks fail, and the finished-cursor regression is fixed. All four requested checks pass. However, the broader guessing bound remains false: speculative runs that reach the same later link can share their remaining chain computations, defeating the assertion that every guess costs the full saving. A scratch attacker recovered correct keys under budgets substantially below that accounting, including 100/100 fresh puzzles under a fixed budget whose claimed probability bound is about 3.5%. This is a newly identified problem in the retained security argument, not a new defect in C's mask implementation. Only `audit/round-7.md` was changed in the worktree; all builds and scratch programs were under `/tmp/chainseal-round7.fwROc6`.

## Findings in scope

| Finding | Status | Evidence |
|---|---|---|
| R6-1: raw masks, minimum saving, and guessing explanation | **Partly resolved** | Both `b=32` attacks and all 256 `b=31` suffix candidates now fail in C and Python; SPEC correctly allows partial-chain savings, but the general `Q/(d·2^(8b))` claim fails under shared speculative suffix work (R7-1). |
| R6-2: completed cursor contains `a_n` | **Resolved** | All 36 original parameter combinations now retain `a_(n−1)` and return the same key on direct reuse and after C checkpoint encoding/decoding; Python resumes those checkpoints too. |

## New findings, most severe first

### R7-1. blocker — Merging speculative paths invalidates the per-guess work charge

**Locations:** `SPEC.md:192`; `README.md:95`; the revised mask equation at `SPEC.md:75`. The benchmark at `src/bench.c:148–193` exercises only a one-chain suffix and does not test this issue.

**What is wrong:** a speculative run is determined by its chain index and current link, not by its earlier history. Two different guesses can produce the same later `b`-byte link. From that point onward they need exactly the same chain queries, which an attacker can compute once. The accumulator does not prevent sharing those computations: the attacker retains the earlier ends for each path and evaluates the accumulator after the honest prefix identifies the correct path. Consequently, multiplying the number of starting guesses by the entire speculative advance overcounts the attacker's work. The assumption fails within the stated random-oracle model; no SHA-256 collision, mask inversion, repeated salt, or cross-puzzle reuse is needed.

**Concrete attack:** let `S = 2^(8b)`, choose `n = 2L`, and split at chain `k = L+1`.

1. Evaluate the public prefix, chains `1..L`, normally.
2. Concurrently, start the suffix from **all** `S` candidate values of `x_k`. At each suffix chain index, evaluate each distinct current link only once. Store its end and the next link obtained from `TH(mask, ctx || end)[0:b] XOR z_i`.
3. Deduplicate equal next links before evaluating the next chain. Preserve the stored predecessor records, so merging does not discard any earlier end.
4. When the prefix reveals the actual `x_k`, follow that root through the stored records, concatenate the true prefix and suffix ends, and derive/check the key normally.

All candidates are covered, so a completed attack succeeds with certainty. Its suffix depth is still `L` chains, but the number of distinct suffix chains evaluated can be much smaller than `S·L`. This uses one speculative starting position and saves less than half the total depth after overhead; it does not need to violate the separate half-depth observation to disprove the probability bound.

**Evidence — reproduced using the production chain and mask helpers:** the scratch attacker receives only the public puzzle. Generator links, ends, and key are not inputs to it. Its recovered key passes `cs_key_from_ends`, independently matches Python's accumulator derivation, and matches the generator's key as an external check.

| Parameters | Distinct suffix chain evaluations | Separate-run charge `S·L` | Actual total chain steps, including prefix |
|---|---:|---:|---:|
| `n=8192, m=64, b=1` | 5,893 | 1,048,576 | 639,296 |
| `n=65536, m=64, b=2` | 1,258,474 | 2,147,483,648 | 82,639,488 |

For the second case, even charging **all** SHA-256 compressions gives an upper budget of 87,935,532. A conservative parallel schedule takes at most 2,359,300 compression rounds, including start hashes, mask hashes, and then computing the entire accumulator serially. Honest chain work alone is 4,194,304 rounds. Thus a saving of `d = floor(n·m/3) = 1,398,101` is feasible even with this generous overhead. The purported bound with the larger compression budget is only `0.000959723`, while the attack recovered the correct key. These individual observations demonstrate the mechanism; the following fixed-budget experiment avoids treating an observed, puzzle-dependent cost as an a priori budget.

**Fixed-budget experiment:** 100 fresh OS-random puzzles with `n=8192, m=64, b=1`. The attacker aborts before a suffix layer would exceed a fixed total allowance of **1,572,864 compressions**, reserving work for the prefix and final accumulator/key/commitment. All 100 attacks completed and recovered the key; their charged costs ranged from 704,480 to 811,988 compressions. The schedule is bounded by 294,916 compression rounds, below `524,288 − 174,762`. With `d=174,762`, the claimed bound is `1,572,864/(d·256) = 0.035156384`. The program executes the queries serially to verify them; the stated parallel depth follows from the layer schedule, not from its local wall-clock runtime.

**Why this is more than a constant-factor accounting error:** ignoring negligible full-width coincidences, each layer maps its distinct links to uniformly random `b`-byte next links. If the current width is `r ≤ S`, its expected next width is `S·(1−(1−1/S)^r)`. In particular, the expected decrease is at least `r(r−1)/(3S)`. Writing `w=r−1`, Jensen's inequality gives `E[w_(t+1)] ≤ E[w_t] − E[w_t]^2/(3S)`, hence `E[w_t] ≤ 3S/(t+3)`. The expected number of suffix chain evaluations over `L` layers is therefore at most

```text
L + 3S · ln((L+2)/2),
```

rather than `S·L`. With `m=64`, a conservative expected compression budget for both halves and all final hashes is

```text
E_upper = (2L + 3S·ln((L+2)/2))·68 + 4L + 4.
```

Capping the attack at `2·ceil(E_upper)` retains success probability at least one half by Markov's inequality. For the allowed parameters `b=2, n=2^20, m=64`, that cap is 480,409,982 compressions; with `d=floor(n·m/3)`, the claimed bound is about `0.000327698`, over 1,500 times smaller than the success lower bound. This larger example is an analytical calculation, not an executed test. More generally the discrepancy grows with the number of layers and the link space, rather than being a fixed cost of start or mask hashes. The same reasoning applies to larger widths if sufficiently many candidates are affordable.

**Suggested fix:** restrict the numerical estimate to explicitly independent, unshared guessed runs, or replace it with an analysis that accounts for merging at short links and its parameter/budget dependence. The one-chain benchmark remains a valid check of its particular strategy; it cannot justify the general `d`-step bound. Do not infer a practical default-parameter break from these small-width experiments: enumerating `2^96` roots is outside the advertised `10^21`-steps/s, 60-second budget. Conversely, “no proof that no other strategy does better” does not repair a claimed upper bound once a concrete link-guessing strategy does better.

### R7-2. minor — The simultaneously updated HTML construction still uses the raw mask

**Locations:** `docs/index.html:286,291,294`, adjacent to the changed all-end key description at line 287.

**What is wrong:** this commit updates the HTML construction to hash all ends into the key but leaves generation, opening, and the diagram's accessible description using `y_i[0:b] XOR x_(i+1)`. That is no longer the construction in SPEC or either implementation and retains the round-6 raw-mask problem in the described scheme.

**Evidence:** the current HTML explicitly gives the raw-XOR equations, while `SPEC.md:75,98`, `src/chainseal.c:238–240,319–320`, and Python generation/solving use the labelled mask hash. Following the HTML unmasking rule does not recover the next link of the regenerated multi-chain vectors. This is an incidental consistency finding in another file changed by this commit, not a full audit of the HTML's other security claims.

**Suggested fix:** update both equations and the diagram description to hash `ctx || y_i` under the mask label before taking the first `b` bytes.

### R7-3. nit — The audit history attributes too much to the round-6 commit

**Location:** `audit/README.md:64`.

**What is wrong:** the introductory paragraph says commit `1893160` changed the key “so that a guess of the last link can no longer be checked against the commitment after one chain.” That describes the intended effect as an achieved property of that commit, despite round 6's `n=2,b=32` counterexample. The round-6 row at line 12 correctly records the audited commit and one blocker/one major; the change table at lines 68–69 accurately describes the concrete mask and cursor repairs.

**Evidence:** the committed round-6 report establishes the one-chain check at `1893160`; the round-7 rerun shows that it is the additional mask hashing in `2dd794c` that removes that counterexample.

**Suggested fix:** say that `1893160` *intended* to remove the last-link shortcut, and that round 6 found the raw-mask exception subsequently repaired here.

## Resolution evidence and security wording

**Old raw-mask attacks:** reran the round-6 `n=2,b=32`, `n=3,b=32`, and `n=2,b=31` constructions with `m=100`. Even given the correct guessed last link, C and Python reject the proposed end arrays in both full-width cases and all 256 suffix completions in the 31-byte case. Supplying the actual missing end makes both implementations accept. The link guess now yields mask-output bytes, not bytes of the preceding end. The additional hash therefore repairs the exact algebraic defect; the tests do not purport to exhaust a 256-bit preimage search.

**Finished cursors:** reran all combinations `n ∈ {1,2,4}`, `m ∈ {1,3,7}`, `b ∈ {1,12,31,32}`. Every successful cursor is `(n,m,y_n,a_(n−1))`; direct reuse, C encode/decode/resume, and Python checkpoint resumption all return the original key. The `CS_EPUZZLE` path also preserves the accumulator invariant when the commitment is changed. The new committed tests for `n=1,2,3` exercise direct and serialized reuse and would catch the previous bug.

**Other checkpoint positions:** all 392 independently constructed positions across those puzzles resume correctly in both languages, including every chain's `j=0` and `j=m`. All 308 positive-step callback stops match independently constructed checkpoint bytes exactly. The final temporary absorption does not disturb the pre-absorption stop boundary.

**Categorical statements:** for one blind hidden-link guess followed by ordinary forward computation, the hashed mask removes the width-dependent exception across the full `1 ≤ b ≤ 32` range. A correct guess alone does not supply earlier ends. With only one speculative starting position, the required chain evaluations split into two paths whose maximum length is at least `n·m/2`; saving more than half requires additional speculative starting positions with correct links, apart from separate full-width state/key guesses or collision events. Those restricted statements are sound. They are not unconditional theorems about every random-oracle algorithm, nor do they establish the cost or probability of obtaining the required correct links. In particular, R7-1 shares suffix work among many roots and can even determine a downstream link when all candidate paths coalesce before the honest prefix reaches it. The wording that all guesses remain blind until the solver's own prefix reaches them is too broad if applied to every later link.

“Reveals nothing about the end” should be read computationally: a known mask output supplies a predicate for testing proposed ends, although it supplies no raw end bytes and does not make inversion free. The new 82-byte mask input is domain-separated from the 81-byte accumulator and key inputs and the 52-byte chain step. It also differs from every other labelled hash by its length-prefixed label, including a start input that happens to have the same total length. The HMAC inputs used by this format do not overlap it. No new domain-overlap or accumulator shortcut was found.

SPEC now correctly says that savings smaller than one chain are possible. The original one-step speculation still works with the hashed mask and is no longer a counterexample to that wording. The arithmetic `2^-45.3326194` at `b=12` and the minimum `b=11` for the stated `2^-32` one-chain threshold are unchanged and correct for the independent one-chain strategy. **There is a remaining strategy that beats the general `Q/(d·2^(8b))` estimate by more than constant factors: the merging attack in R7-1.** It exploits short-link transitions inside one puzzle, so fresh salts do not prevent it. No practical improvement on the advertised default one-chain numerical attack was demonstrated here.

## Implementation and check results

The C helper hashes precisely `u8(17) || "chainseal/v1/mask" || ctx || y_i`. Generation and solving call it with the correct end and XOR the first `b` bytes with the appropriate link. The benchmark's honest prefix uses the same revised rule. Python independently performs the same operations with `hashlib`; its vector checker derives starts, ends, masks, accumulators, keys, and checkpoint values from input parameters and randomness rather than trusting asserted derived fields. Scratch comparisons tested 96 mask outputs across all 32 widths against a direct `hashlib.sha256` formula, including C input/output aliasing. All matched. The helper centralizes the format equation without adding an unnecessary abstraction.

The vector changes have the expected shape: parameters, random inputs, starts, ends, accumulators, key, and commitment are unchanged. Single-chain vectors are entirely unchanged because they contain no hidden link. Multi-chain puzzle links, puzzle IDs, secret/envelope bytes, and checkpoint IDs change. C regeneration matches the committed JSON byte for byte, and the independent Python checker accepts it. Separate mutations of an asserted accumulator, checkpoint accumulator, and key are rejected. No implementation, memory-safety, or concurrency regression was found in the requested changed paths.

| Check | Result |
|---|---|
| `make test` | Passed: 1,813 unit checks; 200 SHA-NI instruction-emulation runs; ARM/portable self-tests; vector regeneration; CLI tests; Python verification of 7 cases and 51 invalid inputs; bidirectional cross-tests. |
| `make sanitize` | Passed the complete test target under ASan/UBSan, with no diagnostic. |
| `make tsan` | Passed the unit and CLI targets with `halt_on_error=1`, with no diagnostic. |
| `./chainseal bench attack` | Passed: 4,992 successes in 20,000 trials, versus 5,000 expected and standard deviation 61.2; `b=1,n=4,m=16`, 64 guesses per puzzle; 4.23 seconds locally. |
| Scratch reproductions | Old raw-mask attacks rejected; 36 completed cursors reusable; 392 checkpoints and 308 callback stops agree; 96 mask checks pass; merging attack recovers keys, including 100/100 fixed-budget random trials. |

The benchmark still measures the simulated success frequency of guessing one final chain, not an actual concurrent early-opening latency or optimality against shared suffix computation. Its passing result is consistent with R7-1. The test platform was Darwin arm64, Apple M4, Apple clang 21.0.0. No unrequested production/quantum guarantee or real-x86 validation is assumed by this verdict.

VERDICT: fix-first
