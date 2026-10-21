# Round 6: all-chain key derivation

Audited `18931609fd17aa754803a88a8587c8dc5f8e888f` against its parent on 2026-10-21. **Fix first:** generation, ordinary solving, the independent Python reference, and the regenerated vectors implement the specified ordered accumulator correctly, and all requested repository checks pass on Apple M4. Nevertheless, the new security explanation contains concrete false claims, and a successful C solve returns a cursor that violates the new accumulator invariant and cannot be resumed. There is one blocker and one major below. Only `audit/round-6.md` was changed in the worktree; builds, probes, and generated files were confined to `/tmp/chainseal-round6.b3mRJ8`. Earlier resolved findings and the expressly excluded production, quantum, and x86-hardware limitations are not reopened.

## New findings, most severe first

### R6-1. blocker — The guessing explanation overlooks recovery of the preceding end and partial-chain savings

**Locations:** `SPEC.md:87,188`; `README.md:95`; the masking equation in `SPEC.md:72`.

**What is wrong:** needing every chain end does not imply that every earlier chain must be evaluated, or that a guessed link can only be confirmed by the honest prefix reaching it. A guess `g` for `x_k` also specifies the first `b` bytes of `y_(k−1)`, namely `z_(k−1) XOR g`. At the allowed width `b = 32`, it specifies the *entire* preceding end. This directly contradicts the new unconditional statements that a correct guess opens nothing without the earlier chains and that saving more than half the chain steps requires two correct guesses. Separately, speculative progress can be retained partway through a chain; `m` is not the cheapest useful saving.

**Evidence — concrete attacks, reproduced against both implementations:**

- **One guess opens a two-chain puzzle without running its first chain.** Set `n = 2, b = 32`. Guess `g = x_2`, compute `y'_1 = z_1 XOR g`, run chain 2 from `g` to obtain `y'_2`, and derive the accumulator, key, and commitment from these two ends. The commitment verifies a correct guess after only `m` chain steps. Chain 1 is never run. This works for honestly generated, uniformly random links and salts, with success probability `2^-256` per blind link guess; it does not require a hash collision or an exceptional oracle.
- **One guess saves more than half the sequential work.** Set `n = 3, b = 32`. Run the public chain 1 while running chain 3 from a guess `g` for `x_3`. Recover `y'_2 = z_2 XOR g`. After `m` chain rounds, all three proposed ends are available and their key can be checked. A correct single guess gives chain depth `m` instead of `3m`, saving `2m > 3m/2`; chain 2 is never evaluated. Account separately for the small start/accumulator/key/commitment overhead, as the documents do. The scratch reproduction used `m = 100` and verified the resulting key in C and Python.
- **The issue is not confined to exactly 32 bytes.** At `b = 31`, a guessed `x_2` leaves only one unknown byte of `y_1`. For `n = 2`, run chain 2 once, enumerate the 256 completions of `y_1`, and test the resulting keys. The scratch probe recovered the key without running chain 1. In general there are `2^(256−8b)` suffix completions. These checks cost labelled hashes and must be included in an attack budget; the attack is not a practical improvement at the default `b = 12`, where 160 bits remain unknown.
- **Saving less than one chain works even at the default width.** For `n = 2, b = 12, m = 100`, run just one step of chain 2 from a guessed link while running chain 1 normally. When chain 1 reveals the true link, retain the speculative state if the guess matches and finish the remaining 99 steps. A correct guess gives chain depth 199 instead of 200. The same construction saves any `1 ≤ d < m` chain steps, apart from the separately accounted start-hash overhead. A Python-built checkpoint at `(i,j) = (2,1)` with the proper `a_1` resumed to the correct key. Thus the sentence “The cheapest useful saving is one chain” is false; choosing one whole chain as the numerical example is fine.

The probes condition on a correct candidate supplied by the test setup to demonstrate its consequence; they do **not** claim to have brute-forced a 248- or 256-bit link. The probabilities follow from uniform hidden links. These are counterexamples to the stated implications, not evidence of a practical break of default parameters. The qualification that there is no general proof does not make these particular categorical claims true.

**Suggested fix:** describe the numerical bound explicitly as forward speculation that obtains preceding ends by evaluating the prefix, and make the half-work statement conditional on that model. Explain the information about `y_(k−1)` contained in a link guess and account for suffix enumeration at large widths. Replace the minimum-saving sentence with “For a saving of one whole chain, take `d = m`.” If the stronger claims are intended for the entire allowed parameter range, the analysis or masking construction needs to change; hashing all ends alone does not establish them.

### R6-2. major — A completed C cursor absorbs the last end twice when reused

**Locations:** `src/chainseal.c:308–320,323–330`; `src/chainseal.h:71–85`; `SPEC.md:157–162`; missing case in `tests/test.c:288–307`.

**What is wrong:** `cs_cursor.acc` and checkpoint bytes `[84:116)` are specified to contain `a_(i−1)`, including at `j = m`. The stop callback correctly sees that value. But a successful `cs_solve` absorbs `y_n` into `c.acc`, leaves `(c.i,c.j) = (n,m)`, and copies this post-absorption cursor to the caller. Its accumulator is now `a_n`, violating the public cursor invariant. Reusing it, directly or through checkpoint encoding/decoding, absorbs `y_n` again and returns `CS_EPUZZLE` for a valid puzzle.

**Evidence — reproduced:** all 36 scratch puzzles with `n ∈ {1,2,4}`, `m ∈ {1,3,7}`, and `b ∈ {1,12,31,32}` exhibited this failure. The first solve returns `CS_OK` and the correct key; the second returns `CS_EPUZZLE`. Python also rejects a resumed checkpoint made from the completed C cursor. A minimal C reproduction, inside `main` with `chainseal.h` included, is:

```c
cs_puzzle p;
cs_cursor c = {0};
uint8_t salt[16] = {0}, x[1] = {0}, key[32], got[32];
cs_generate_from(&p, key, 1, 1, 1, salt, x, NULL);
int first = cs_solve(&p, got, &c, NULL, 0, NULL, NULL);  /* CS_OK */
int again = cs_solve(&p, got, &c, NULL, 0, NULL, NULL);  /* CS_EPUZZLE */
cs_puzzle_free(&p);
```

For the single-chain case, the returned cursor must retain `ctx` as its accumulator but instead contains `TH(acc, ctx || y_1)`. The parent implementation had no accumulator to double-absorb and could reuse its final cursor. The new tests exercise stopping at `(n,m)` **before** absorption, which works, but never reuse the cursor returned after successful completion.

**Impact:** this is a library/checkpoint regression, not a demonstrated failure of the current CLI interruption path. The CLI saves cursors from the progress callback or `CS_ESTOPPED`, both before absorption; it does not serialize the cursor returned on success. The header expressly promises resumability on `CS_ESTOPPED`, but does not mark successful cursors as invalid, and their fields still claim the same invariant. Encoding such a returned cursor silently emits a checkpoint with the wrong semantic value.

**Suggested fix:** keep the returned cursor at `(n,m,y_n,a_(n−1))` and perform the last absorption/key derivation on temporary state. Preserve the same invariant on the completed `CS_EPUZZLE` path. Add a regression that solves successfully, encodes/decodes its returned cursor, and resumes again, including `n = 1`; retain the existing pre-absorption stop test.

## Security argument

I agree with the **restricted forward-speculation estimate**, not with all the new explanatory claims. For a fixed hidden link with `N = 2^(8b)` possible values, `g` distinct blind candidates each advanced by `d` steps cost `g·d` speculative chain steps and hit the true link with probability at most `min(1,g/N)`. This gives `min(1,Q_spec/(d·N))`; using a larger `Q` that also includes honest-prefix work remains a conservative budget. In that model a single successful speculative branch splits the required chain evaluations into two paths, so their maximum length is at least `n·m/2`. Multiple smaller successful advances require additional accounting; the single-run calculation is not by itself a proof for arbitrary adaptive strategies. R6-1 shows why the premise that the prefix must be evaluated is not true throughout the allowed parameter range. I found no practical strategy improving the claimed scaling at `b = 12`, and do not claim that the large-width examples asymptotically refute an “about” bound allowing constant factors. They do refute the categorical confirmation and two-guess statements.

The added accumulator has an 81-byte SHA-256 input: a one-byte length, the 16-byte label, and two 32-byte values. Its labelled prefix differs from every other labelled hash, including the equally long key hash; it cannot equal a 52-byte chain-step input. No new domain overlap was found. Under the stated random-oracle model, knowing a prefix of a missing end does not evaluate the accumulator on the complete input; it leaves the suffix search described above. Guessing an accumulator state or key remains a separate 256-bit search, and ordinary hash collisions/mergers are separate exceptional events, not covered by the link-only calculation. No accumulator associativity or length-extension shortcut lets a computed suffix be joined to an unknown accumulator prefix through the fixed-length format.

Across puzzles with fresh distinct salts, start hashes depend on their contexts, and chain-step inputs depend on salt and index, preventing direct reuse of the same chain queries. The accumulator carries context through `a_0`; reuse across contexts would need the corresponding hash-state coincidences or searches. Allocating independent speculative work across many puzzles gives a union bound in the **total** allocated budget, rather than a free multiplicative gain for each query. Repeated salts and precomputation after publication remain the documented qualifications. The [MMV paper, Theorem 3 and section 3.1](https://people.seas.harvard.edu/~salil/research/timelock.pdf), supplies an asymptotic statement for its own construction and polynomial-query attackers; it does not supply the new concrete bound for chainseal's accumulator.

The numerical arithmetic is correct for the scoped one-chain-saving estimate, with `Q = 10^21·60` and `m = 2^25`:

| Link width | `log2(Q/(m·2^(8b)))` | Probability |
|---|---:|---:|
| 10 bytes | −29.3326194 | `1.4791·10^-9` |
| 11 bytes | −37.3326194 | `5.7778·10^-12` |
| 12 bytes | −45.3326194 | `2.2569·10^-14` |

Thus “about `2^-45`” and the minimum integer `b ≥ 11` for a probability below `2^-32` are correct for that estimate. They do not quantify the chance of saving *any positive amount* of time.

## Implementation consistency and validation

| Requirement/check | Result |
|---|---|
| SPEC sections 4 and 5 | C generation absorbs every end in index order from `ctx`, then hashes `ctx || a_n`; C and Python fresh solving agree. In-place C absorption is safe because `th` consumes its inputs before writing the output. |
| Python independence and SPEC section 10 | `generate` recomputes starts, ends, all accumulators, key, commitment, and encodings from parameters/random inputs. The checker computes checkpoint state and `a_(i−1)` from those derived values, not the vector's asserted `y`, `acc`, or key. Separate mutations of a vector accumulator, checkpoint accumulator, and key were all rejected. |
| SPEC section 6.4 and boundary probes | 392 independently constructed checkpoints across 36 puzzles round-trip through C and resume to the independently generated Python key in both languages. These cover every `j` from 0 through `m` for every chain, including the first and last. All 308 positive-step callback stops match the independently constructed checkpoint bytes exactly. Only completed returned cursors fail, as in R6-2. |
| New helper APIs and callers | `cs_run_chain` reproduces the designated end; `cs_key_from_ends` absorbs all ends and checks the commitment. The removed last-link helper has no remaining callers. Generation waits for its chain workers before reading their ends. No new indexing, allocation-size, or threading defect was found in the changed paths. |
| CLI checkpoint handling and `info` | Buffers and exact-length validation use `CS_CHECKPOINT_SIZE = 116`; the accumulator is copied on decode. Additional `info` probes accept 116 bytes and reject 84, 115, and 117 bytes. Existing interruption/resume, malformed-header, puzzle-ID, and output/checkpoint collision tests pass. `info` intentionally checks structure, not accumulator authenticity. |
| `make test` | Passed: 1,792 unit checks, 200 SHA-NI instruction-emulation runs, native ARM/portable self-tests, byte-for-byte C vector regeneration, CLI tests, Python checks of 7 valid cases and 51 invalid inputs, and bidirectional C/Python cross-tests. |
| `make sanitize` | Passed the complete test target with AddressSanitizer/UndefinedBehaviorSanitizer; no diagnostic. |
| `make tsan` | Passed the unit and CLI targets with `halt_on_error=1`; no diagnostic. |
| `./chainseal bench attack` | Passed: `b=1,n=4,m=16`, 64 candidates per puzzle, 5,016 successes in 20,000 trials versus 5,000 expected and standard deviation 61.2; 3.87 seconds locally. |

The benchmark computes the honest prefix first and then tries candidate final chains. This checks the simulated success frequency for a hypothetical parallel schedule; its elapsed runtime is not a measurement of early-opening latency, and its printed candidate budget excludes honest-prefix and labelled-hash work. Its small-width result does not test the large-width counterexamples or prove optimality.

The implementation changes are appropriately small: the accumulator is necessary to make the key depend on all ends while retaining constant-size solver state, and the two new helpers serve both tests and the benchmark. Removing the accumulator would restore the old last-link weakness; no architectural rewrite is needed. The required repairs are the returned-cursor invariant and the scope/content of the security explanation. Validation was on Darwin arm64, Apple M4, Apple clang 21.0.0; real x86 execution remains outside this audit's claimed evidence.

VERDICT: fix-first
