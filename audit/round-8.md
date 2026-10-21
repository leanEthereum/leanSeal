# Round 8: first-chain accounting and the half-delay estimate

Audited `c33fa59b5446ac3d10cf57ad7e4c0279c0ec2a76` on 2026-10-21. **Fix first:** replacing `d` by `min(d,m)` covers the round-7 merging attack, and the raw-mask description and audit-history correction are resolved. I found no attack exceeding the revised **unsquared** bound by more than constant factors. However, the guide's asserted squared bound for savings greater than `N/2` is false: cheap partial-chain tables can provide the extra advances, while success depends on only one uncertain full-chain guess. A production-backed reproduction exceeds that squared estimate by about 3,214 times, without hash collisions or mask inversion. The per-guess explanation also fails to account for savings assembled from several partial advances. Table 1's arithmetic and the one-chain numerical examples check out at their displayed precision. `make test` passed. Only this report was changed in the worktree; builds, experiments and logs are under `/tmp/chainseal-round8.UYat9E`.

## Findings in scope

| Finding | Status | Evidence |
|---|---|---|
| R7-1: speculative merging defeats the guessing charge | **Partly resolved** | The original fixed-budget attack again succeeds on 100/100 puzzles, but the new linear bound is 96, hence vacuous and consistent; the general argument and squared refinement still fail under partial-chain speculation (R8-1). |
| R7-2: guide still describes the raw mask | **Resolved** | Generation, opening, SVG text and accessible description at `docs/index.html:286,291,294,310` now use a hash of the previous end. |
| R7-3: audit history attributes the repair to the wrong commit | **Resolved** | `audit/README.md:65` explicitly records the surviving `b=32` shortcut at `1893160` and its repair by mask hashing in `2dd794c`; the round-7 row records its actual verdict. |

## New findings, most severe first

### R8-1. blocker — Two correct speculative links do not justify squaring the full-chain guessing probability

**Locations:** `docs/index.html:372,374–375,424,428,442`; the per-guess inference in `SPEC.md:192`, `README.md:95` and its summary at `audit/README.md:78`.

**What is wrong:** the guide asserts that for every `d > N/2`, the first term `Q/(m·2^(8b))` becomes approximately its square. A second correct speculative link need not cost a full chain before it becomes useful. An attacker can enumerate short prefixes of chains, guaranteeing small advances at chosen positions, and combine those advances with one successful long speculative run. The total saving exceeds half even though the only uncertain event has probability `1/2^(8b)`. Counting two correct links is therefore not the same as counting two rare events each priced at `m` calls.

The accompanying argument also incorrectly moves from “one guessed run saves its own advance” to “every useful guess in an attack saving `d` costs `min(d,m)`.” Different correct guesses can contribute different, smaller advances. Their first-chain queries remain distinct; it is the proposed lower bound on how many of those queries each must perform that fails.

**Concrete attack:** choose `n=4`, write `S=2^(8b)`, and choose a short prefix length `delta`.

1. From the public puzzle, prepare the state after `delta` steps for **every** possible link at chain 2, and likewise at chain 4. These are two tables with `S` entries each. They require no knowledge of the true links.
2. Concurrently run chain 1 from its public link and chain 3 from one blind candidate `g` for `x_3`.
3. When chain 1 ends, unmask `x_2`, select its prepared state, and run only the remaining `m-delta` steps of chain 2. When the speculative chain 3 ends, do the analogous operation for chain 4 using its implied link.
4. Hash all four ends in order and check the commitment.

Conditional on `g=x_3`, every selected state and end is correct. Both two-chain paths finish in about `2m-delta` rounds, leaving room for all masks and the accumulator before `N/2=2m`. The probability of this sufficient event is exactly `1/S` for a uniformly chosen blind candidate. The other two correct link candidates are guaranteed to be in the tables; they do not require additional luck. The attack never substitutes a mask output for an end or omits an end from the accumulator.

**Evidence — executed against the unchanged C implementation:** `partial.c` exposes only partial iteration through the production chain backend. `partial_attack.py` builds both complete tables from public puzzle data, uses the production start/mask functions, and verifies the resulting key with `cs_key_from_ends` and independently with Python's accumulator derivation. With the correct candidate for `x_3`, both accept the original key; changing that candidate makes the commitment check fail. These are conditional correctness tests, not an empirical claim to have sampled a rare successful guess. The `1/S` success lower bound follows from the uniform hidden link and the attack's fixed candidate budget.

```text
n = 4, b = 2, S = 65,536, m = 16,777,216, delta = 64
N = 67,108,864
d = 33,554,464 > N/2
deadline N-d = 33,554,400
conservative parallel depth, including commitment = 33,554,384
```

Even charging every SHA-256 compression, rather than just each oracle call, a fixed upper budget is

```text
Q = 4m - 2delta + 2S(delta+2) + 20 = 75,759,508.
```

Here `2S(delta+2)` includes both tables and their two-compression start hashes; the remaining constant covers the two other starts, two masks, four accumulator hashes, key and commitment. The two main paths finish by `2m+4-delta`; computing the entire accumulator and final hashes afterward gives depth `2m+16-delta`. The tables are ready much earlier. Thus this schedule meets the guide's deadline even with a more expensive accounting unit. The scratch program evaluates queries serially to verify their values; the parallel depth is established by this dependency schedule.

The probabilities at that fixed budget are:

| Quantity | Value |
|---|---:|
| Attack success lower bound, `1/S` | `1.52587890625e-5` |
| Revised unsquared term, `Q/(mS)` | `6.89028711349e-5` |
| Claimed squared term | `4.74760565064e-9` |
| Generic term, `(Q^2+QN)/2^256` | `9.34747584466e-62` |

The squared estimate is too small by approximately **3,214 times**. This is not a fixed hash-overhead correction: when `m` is large compared with `S·delta`, the budget is about `4m`, the proposed square is about `16/S^2`, and success remains at least `1/S`. The discrepancy grows with the link space, with very large discrepancies available within the allowed parameter limits. No merging is needed for this counterexample; partial-chain reuse alone suffices.

**Suggested fix:** remove the universal squared refinement and the numerical guarantees inferred solely from it, or replace them with an analysis that prices all required advances, including short speculative prefixes, as a function of the requested deadline. Rewrite the per-guess argument to distinguish one guess's contribution from the attack's total saving. The unsquared expression survives these experiments, but this argument does not prove it. This finding is not a demonstrated practical break of the default 12-byte parameters, nor a demonstration that their particular `10^-27` threshold is numerically exceeded; it disproves the general premise used to assert that threshold.

### R8-2. minor — Useful merging does not require covering a sizable fraction of the link space

**Locations:** `docs/index.html:376,428`.

**What is wrong:** both passages restrict useful sharing to an attacker trying a sizable fraction of all `S` link values. Merging accumulates over many layers. A small root set can therefore obtain substantial sharing if it runs far enough.

**Evidence:** for `r` distinct current links, the random-oracle model gives expected next width `S·(1-(1-1/S)^r)`. The initial expected number of merged pairs is approximately `r(r-1)/(2S)`, and this opportunity recurs at every layer. The relevant scale for substantial cumulative merging includes the number of layers, roughly `L·r/S`, rather than just `r/S`.

The scratch `subset_merge.py` follows only 256 fixed candidate roots through 32,768 suffix chains of a public `n=65,536, m=64, b=2` puzzle. It evaluates **538,475** distinct chains instead of **8,388,608**, a **15.58-fold** saving, while covering only **1/256 of the link space** initially. This experiment measures sharing; it does not claim guaranteed key recovery from that subset. The first chain still costs one distinct evaluation per root, so it does not defeat the revised unsquared bound.

**Suggested fix:** describe the dependence on both root count and remaining layers. Retain the distinction between an improvement in evaluating a speculative suffix and a violation of the first-chain probability bound. No default-parameter attack follows merely from this correction.

### R8-3. minor — The guide's exact honest-round count omits masks and accumulation

**Location:** `docs/index.html:374`; compare `SPEC.md:39,98`.

**What is wrong:** the changed paragraph retains the claim that an honest opener needs `N+n+2` rounds, counting starts and two final hashes. The construction also requires `n-1` mask hashes and `n` accumulator hashes. This is a pre-existing sentence in the specifically requested paragraph, not a new code regression.

**Evidence:** a serial evaluation of the specified algorithm makes `N+3n+1` hash calls: `N` steps, `n` starts, `n-1` masks, `n` absorptions and two final hashes. Even if accumulation overlaps subsequent chain work, mask hashes still lie between chains; the stated count does not describe that schedule either. At `n=1`, the omitted absorption alone changes the count from `N+3` to `N+4` when checking the commitment. Compression counts differ further because the labelled hashes use two blocks.

**Suggested fix:** use the count already given in SPEC, distinguishing total calls from parallel depth, or say `N+O(n)` where the small overhead is intentionally ignored. This has negligible impact on the displayed long-chain timing estimates.

## Assessment of the revised security argument

**Original fixed-budget reproduction:** reran `merge_trials.py` on 100 fresh OS-random puzzles with `n=8192, m=64, b=1`, the original fixed cap of **1,572,864 compressions**, and `d=174,762`. All **100/100** attacks recovered the original key, independently checked through Python. Charged costs ranged from **702,576 to 836,400**. The conservative depth remains at most **294,916**, below `N-d=349,526`. The old expression is `0.035156384`; the revised expression is **96**, plus approximately `2.85e-65`. Once capped at probability 1, the new bound is fully consistent with this experiment. Complete root enumeration necessarily pays at least `S·m` for the first layer, so this attack cannot make the new first term less than 1.

**Distinct starts and partial chains:** absent full-width collisions, distinct guesses at the same position have distinct starts and cannot share first-chain queries. Different chain positions also have different query inputs because the index is encoded in both the start and each chain step. Start, mask, accumulator and raw chain-step domains remain separated as assessed in round 7; this commit changes no encoding. The generic collision/state-hit term is the appropriate kind of exception to first-chain disjointness. Reusing a state after a prepared partial chain is nevertheless legitimate: it costs only the prefix length before the link becomes known, as R8-1 demonstrates.

For a *single* speculative run contributing an advance `a`, charging at least `min(a,m)` distinct first-chain steps is sound. Replacing that `a` with an entire attack's saving `d` is not sound when advances combine. For `d<m`, multiple short successes can add up to `d` without any one run advancing `d`; for `d>m`, a full-chain speculation can combine with much cheaper short ones. A possible linear analysis must account for total successful partial work, rather than simply count all guesses at the same price. I found **no strategy beating `Q/(min(d,m)·2^(8b))` up to constant factors**, including these cases, but do not certify the supplied explanation as a proof of that general bound.

**More than half:** the dependency observation survives in a restricted sense. With just one correct speculative starting point and otherwise ordinary forward evaluation, the true chains split into two paths; one has length at least `N/2`. Merging can identify later links before the honest prefix reaches them, but it cannot make the true path's already-required chain steps disappear. Extra successful speculative work is required to beat the halfway point, excluding separate full-width state/key events. What fails is interpreting that work as two independent, full-chain-priced successes. The all-candidate partial tables in R8-1 contain additional correct guesses with certainty. Likewise, a downstream link inferred from merged candidate paths is not a fresh independent lucky event. “Every guessed run stays blind until its own prefix arrives” is too broad for such inference.

**Many puzzles:** for distinct puzzle contexts, first-chain queries remain specific to one puzzle. Conditional on a valid per-puzzle linear estimate, summing the allocated budgets gives the corresponding linear expected-opening estimate for a common parameter set; work aggregation does not repair the squared inference. Neither reproduced attack needs cross-puzzle reuse, repeated salts, partial leakage of an end, or accumulator inversion. Previously stated exceptional-event and implementation limitations were not reopened.

## Numerical and document checks

The one-chain figures are unchanged and correct for the stated guessing strategy. With `R=10^21`, `T=60`, `m=2^25`, `b=12`:

```text
Q/(m·2^96) = 2.25694915358e-14 = 2^-45.3326194118
log2(Q/m) + 32 = 82.6673805882 bits, hence b >= 11
T/m = 1.78813934326 microseconds per chain step
```

Squaring that probability gives `5.09381948184e-28`; the displayed generic term is about `3.1090e-32`. Their sum is indeed below `10^-27`. **The arithmetic is correct; the universal squared security inference is not.** The claim box, explanatory paragraph, paragraph after Table 1 and Table 2 note should not present the latter as established by needing two right guesses.

For Table 1, I used `A=13/ell_ns`, `N=60/(ell_ns·10^-9)`, `m=N/512`, build time `37.1·N/2^34` seconds, and open time from the stated 23.3 ns M4 step measurement. The guessing column is `6·10^22/(m·2^96)`:

| `ell` (ns) | `A` | `log2 N` | `log2 m` | Scaled build (s) | Open (min) | One-chain chance |
|---:|---:|---:|---:|---:|---:|---:|
| 13.0 | 1 | 32.1038 | 23.1038 | 9.967 | 1.792 | `8.4011e-14` |
| 6.5 | 2 | 33.1038 | 24.1038 | 19.934 | 3.585 | `4.2005e-14` |
| 3.5 | 3.7143 | 33.9969 | 24.9969 | 37.020 | 6.657 | `2.2618e-14` |
| 2.3 | 5.6522 | 34.6026 | 25.6026 | 56.335 | 10.130 | `1.4863e-14` |
| 1.0 | 13 | 35.8042 | 26.8042 | 129.570 | 23.300 | `6.4623e-15` |

These agree with the displayed rounding. The bold row uses the actually measured `N=2^34, m=2^25`, rather than forcing precisely 60 seconds at 3.5 ns; that gives 60.1295 seconds and the archived 37.1-second build and 404-second opening. This explains the small difference from exact-60-second scaling. The ratios `23.3/3.5=6.66` and `17/3.5=4.86` support “6.7 times” and “about 5 times.” Puzzle size is `68+512·12=6,212` bytes. This checks the arithmetic against the stated measurements, not an independent validation of a physical SHA-256 latency floor or a survey of the fastest hardware.

The mask correction is consistent throughout the guide's construction illustrations, using `H(y_i)` as overview shorthand for SPEC's labelled, context-bound mask. The audit history now correctly distinguishes the intended all-end-key change from the later raw-mask repair. Its account of the replacement bound is accurate as a description of what changed, but the proposed justification and two-guess estimate need the corrections in R8-1.

## Verification

`git show` confirms no C, Python or vector changes in this commit. Ran **one `make test`** in a fresh `git archive` extraction under `/tmp/chainseal-round8.UYat9E`, with exit status 0: **1,813 unit checks**, **200/200 SHA-NI emulation comparisons**, backend selftests, byte-for-byte vector regeneration, CLI tests, Python's **7 valid cases and 51 invalid inputs**, and cross-language tests all passed. The three scratch experiments are `merge_trials.py`, `partial_attack.py` with `partial.c`, and `subset_merge.py`; their logs are alongside `test.log`. No code regression was found, and no repository test or implementation file was modified.

VERDICT: fix-first
