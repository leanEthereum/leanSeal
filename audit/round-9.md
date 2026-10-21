# Round 9: conjectural guessing bound and hardware sources

Audited `e042e8cbc81893f2cbd42e865b9f546be63748c2`, including `f9f55c5`, on 2026-10-21. **Ready at the stated PoC bar:** the squared estimate is withdrawn, the distinction between a run's gain and an attack's combined gains is acknowledged, and the merging description and honest call count are corrected. Read together with their explicit qualifications, the remaining probability estimates are conjectural rather than claimed consequences of a proof. I found no new counterexample to the unsquared bound. Two minor presentation issues remain: some single-run wording still invites the inference just withdrawn, and the hardware model blurs FO4 units with gate counts and does not reproduce its endpoints exactly from its displayed inputs. The principal hardware citations support the ingredients attributed to them, and Table 1's parameter, timing and guessing arithmetic checks out. No implementation files changed in these commits; as requested, I did not rerun the test suite. Only this report was changed; scratch calculations, a small composition example, and downloaded papers are under `/tmp/chainseal-round9.jYw8UZ`.

## Findings in scope

| Finding | Status | Evidence |
|---|---|---|
| R8-1: squared estimate and general per-guess argument | **Resolved, with a wording follow-up below** | The square and `10^-27` claim are gone; SPEC explicitly calls the remaining bound unproved because gains can combine, and the guide makes the same qualification. Its per-run charge now uses that run's gain `a`. |
| R8-2: merging requires a sizable fraction of the link space | **Resolved** | `docs/index.html:428` now includes both the number of guesses and the number of chains covered; the sizable-fraction restriction is removed. |
| R8-3: honest call count omits masks and absorption | **Resolved** | `docs/index.html:374` now says `N+3n+1` **hash calls**, matching `N` steps, `n` starts, `n-1` masks, `n` absorptions and two final hashes. |

## New findings, most severe first

### R9-1. minor — Some single-run wording still uses the attack's total saving

**Locations:** `SPEC.md:192`; `docs/index.html:370–376,428`; the short explanation at `README.md:95`.

**What needs clarification:** SPEC retains the sentence beginning “To finish `d` steps sooner than an honest solver, a guessed run must already be `d` steps ahead.” For one run providing the entire gain this is the intended explanation. It is not a valid charge of `d` blind steps to an individual run when several gains combine. Later in the same paragraph, SPEC correctly acknowledges this distinction and says the general bound is unproved. The guide's “Guess ahead” bullet similarly uses “so” to move from a single-run cost to the general expression, although the preceding explanation expressly says that inference does not prove the claim.

**Evidence:** a small scratch example, `combined.py`, uses the unchanged Python reference with `n=3, m=256, b=1`. It prepares 64 steps for every candidate at chains 2 and 3, then selects each stored state when the preceding end unmasks the actual link. The derived key matches the generator and passes the commitment. No candidate runs more than 64 blind chain steps, but a conservative schedule including all hash overhead finishes in **656 compression rounds**, compared with `N=768`. It therefore meets a saving target `d=100` by combining two smaller advances. The total saving cannot be assigned as blind work to either candidate. This is an illustration of the acknowledged round-8 issue, not an attack on the conjectured bound and not a new implementation test failure.

**Suggested fix:** use `a` consistently for one run's own advance, explicitly introduce that explanation as the single-run case, and describe the general expression as conjectured wherever it is restated. Labeling the box “Conjecture” would make it self-contained. In “Status,” say that the examples defeat the two specified stronger formulas, rather than inviting a claim of tightness in every longer-saving regime.

**Severity rationale:** the nearby, explicit statements that gains combine and the general bound is unproved prevent this from remaining a claim to have established the invalid inference. This is a residual clarity problem, not a new assertion of the disproved squared bound. R8-1's substantive repair is complete.

### R9-2. minor — The circuit model needs explicit FO4 units and a reproducible endpoint calculation

**Locations:** `docs/index.html:389,394`.

**What needs clarification:** the cited timing unit is a **fanout-of-four inverter delay (FO4)**, not the delay of an arbitrary logic gate. Harris–Sutherland report adder delays in FO4; Nikolić et al. predict FO4 delays. Intel's count of logic levels is a different quantity. Converting the latter at one FO4 per level is an additional modeling assumption. The guide does signal a conditional model, but calling all three quantities “gate delays” hides this distinction.

**Evidence:** [Harris–Sutherland, Tables 3–5](https://pages.hmc.edu/harris/research/adderle.pdf) give differing adder delays for circuit families and wiring assumptions. [Nikolić et al., Table 5](https://stefannikolicns.github.io/files/Nikolic_et_al___Global_Is_the_New_Local_FPGA_Architecture_at_5nm_and_Beyond___2021.pdf) give F5/F3 values of **4.69/4.48 ps at nominal voltage**, and **4.69/4.30 ps at 0.7 V**. Thus the guide's 4.3–4.7 ps range exists, but its lower endpoint uses the common-voltage row, not F3's nominal-voltage value. The displayed model inputs, taken literally, yield

```text
64 × 10 × 4.3 ps       = 2.752 ns
64 × 17 × 4.7 ps × 1.8 = 9.20448 ns,
```

not 2.9–9.7 ns. The difference is small compared with the admitted model uncertainty, but the actual unrounded assumptions are missing. The displayed 45–150 ps per round likewise approximately matches the advertised endpoints, not the literal input products.

**Suggested fix:** state the FO4 unit and voltage convention, distinguish raw logic depth from FO4-normalized delay, and provide one equation with the actual adder, CSA/choice and overhead assumptions used to obtain the endpoints. Identify the 1.8 overhead allowance and one-FO4-per-patent-level conversion as the guide's assumptions. This is not a finding that the conditional hardware model is invalid, nor a demand for the physical lower bound the guide explicitly disclaims.

## Security wording assessment

**Claim box and proof discussion.** The box states the unsquared expression. Although it would read better with its conjectural status in the box itself, “Why the bound should hold” now expressly says the per-run cost does not prove it, and “Status” says the concrete proof has not been written. SPEC uses “is believed” followed by “This is not proved.” README ends its estimate with the corresponding limitation. Read in context, these are plainly unproved claims; the absence of a proof is not a new blocker. The same qualification applies to the proposed generic-event term and many-puzzle extension, rather than just the link-guessing term.

**What is established about individual guesses.** For an initially hidden uniform link, an independent blind candidate hits with probability `2^(-8b)`. Apart from full-width coincidences, distinct candidates at a position do not share first-chain queries; different positions are separated by their encoded indices. Later chains can merge. A run's own advance `a` can therefore be charged `min(a,m)` first-chain steps, but this does not count every useful candidate in a multi-run attack at a common price. Partial starts, merged suffixes and aggregate savings are now acknowledged. The benchmark establishes the frequency of its particular one-chain strategy, not optimality over all strategies.

**Confirmation and masks.** Statements that a guess is confirmed when the solver's prefix reaches it describe the basic strategy. They should not be read as a theorem that all later links remain unknown until the complete honest prefix reaches them: merged candidate paths can establish a later link earlier, as the previous reports explain. Similarly, “nothing about the end” is computational shorthand: knowing a mask output gives an end-testing predicate, but not raw end bytes or free inversion. These do not reinstate the raw-mask attack or justify a stronger bound. The guide's separately stated full-width exceptional events remain relevant.

**More than half and monotonicity.** For the table's `n=512`, let `E_d` mean opening with at least `d` steps saved. If `d>N/2`, then `E_d` is a subset of `E_m`. Consequently `Pr(E_d) <= Pr(E_m)` at the same budget. “Harder still” in the paragraph after Table 1 and the Table 2 note is defensible as **no easier**, not as a proved strict reduction or an additional numerical factor. The guide now explicitly states that it gives no smaller figure. The round-8 attack can put more than half the saving behind one uncertain long guess plus guaranteed short tables; this is consistent with the new wording about further prepared work. No squared estimate survives.

**One-chain figures and other statements.** The one-chain strategy still gives `6e22/(2^25·2^96) = 2.25694915358e-14 = 2^-45.3326194`. Its `2^-32` target requires at least `82.6674` bits, hence 11 bytes. Applying this as an upper bound on every strategy remains conditional on the conjecture. The publication-time boundary, fixed-envelope integrity requirement, commitment/key checking, nonce reuse warning and malformed-puzzle limitation are consistent with the earlier audits and unchanged code. The construction still makes no concrete quantum guarantee; I did not promote the guide's discussion of a particular quantum-search strategy into a proof for short links. No attack exceeding the unsquared conjecture was found in this round.

## Hardware source audit

I opened the primary papers or their full-text copies and the cited public discussions. The KU Leuven PDF failed through the web fetcher but downloaded successfully directly; its relevant equation and figures were inspected locally. Harris–Sutherland and Nikolić's relevant tables were also rendered and visually checked. MDPI returned an access error; a full copy of the Baldanzi paper was available through Semantic Scholar. The following distinguishes sourced facts from the guide's extrapolation.

| Source | Verification and limits of attribution |
|---|---|
| [Lee, Chan and Verbauwhede](https://www.esat.kuleuven.be/cosic/publications/article-958.pdf), equation (10), Figures 7–8 | The optimized iteration bound is one carry-propagate addition, one CSA and `Ch`; retiming attains it in their operator-delay model. This supports the stated round-loop ingredient. The preceding analysis assumes comparable delays for the Boolean/sigma functions and specific permissible operator transformations. It is a microarchitecture result, not a universal transistor-level lower bound. Their implementation also has initialization/retiming overhead, totaling 68 cycles per SHA-256 block; multiplying a modeled loop delay by 64 is an approximation. |
| [Harris and Sutherland](https://pages.hmc.edu/harris/research/adderle.pdf), Tables 3–5 and conclusion | Fast 32-bit static CMOS adders are around 12 FO4 with the stated wiring model; Table 5 includes a 7.5-FO4 footless-domino helper design. Thus “about 7–12” is a reasonable coarse envelope across selected fast circuit families, provided the unit and conditions are retained. It is not a common logic-level count for all adders. |
| [Nikolić et al.](https://stefannikolicns.github.io/files/Nikolic_et_al___Global_Is_the_New_Local_FPGA_Architecture_at_5nm_and_Beyond___2021.pdf), Tables 4–5 and section 4 | The 4.3–4.7 ps ingredient is supported by predictive device modeling with specified voltages. It is neither a measured arbitrary-gate delay nor a measured SHA datapath. The guide correctly labels it predicted; R9-2 concerns the missing unit/voltage distinction. |
| [Baldanzi et al.](https://pdfs.semanticscholar.org/51b3/78bb688a73fe2825c6277ce208fe13474bfd.pdf), Table 5 and section 4 | The optimized 7 nm synthesis reports 5.15 GHz, and the SHA-256 block takes 67 cycles. Their ratio is 13.0097 ns, supporting the 13.0 ns reference. The guide correctly identifies synthesis rather than a fabricated chip measurement. This paper alone does not establish an exhaustive “fastest published” survey. |
| TSMC [2020 announcement](https://pr.tsmc.com/english/news/2729) and [2021 announcement](https://pr.tsmc.com/english/news/2831) | The releases support the advertised N7-to-N5 15% performance gain and N5-to-N3 gain of up to 15%. Applying both to this SHA core is the guide's expressly labeled extrapolation, not a TSMC measurement of the core. `13/1.15^2 = 9.82987 ns`, or 153.59 ps per round, and `A=1.3225`; the displayed values are correct. |
| [Intel patent US20180089642A1](https://patents.google.com/patent/US20180089642A1/en), Figures 6–7 discussion | The patent does describe a 13-logic-gate critical path for the new state computations after the stated precomputation and deferred-state changes. This supports the gate-depth attribution. Its conversion into picoseconds is the guide's extra assumption, not a measured patent result or a complete chained-hash timing guarantee. |
| [Drake, July 2018](https://ethresear.ch/t/vdf-based-rng-with-linear-lookahead/2573/3) | His reply proposes a conservative `A_max=10` and hopes public VDF ASICs could reduce it to roughly 5. The cited thread itself is generic; his [September reply in the linked discussion](https://ethresear.ch/t/verifiable-delay-functions-and-attacks/2365/12) explicitly identifies the planned fixed-2048-bit-modulus ASIC as the RSA setup for Wesolowski's VDF. The precedent is therefore supported. It is a chosen attacker/honest-hardware factor, not evidence that SHA-256 has the same attainable factor relative to a synthesis result. |

The model's additions, possible unrolling and node scaling are engineering hypotheses. The guide now explicitly says its fast endpoint is conditional, that `A=10` is not ruled out, and that 3.5 ns is not a physical lower bound. Those limitations are adequately stated and are not audit blockers. “Certain” improvement and “fastest published” should be understood cautiously: the sources checked support the stated reference point and optimization opportunities, not an exhaustive hardware survey or a measured faster chain circuit.

## Arithmetic checks

The hardware table's per-round entries use whole-hash time divided by 64. This gives 364.06 ps for 23.3 ns, 265.625 ps for 17 ns, 203.125 ps for 13 ns and 54.6875 ps for 3.5 ns. These are normalized averages, not the actual 5.15 GHz clock period. The corresponding advantages `13/23.3=0.558`, `13/17=0.765` and `13/3.5=3.714` match the displayed rounding. Intel's conditional conversion is `64·13·(4.3..4.7) ps = 3.5776..3.9104 ns`, agreeing with 3.6–3.9 ns. At 3.5 ns the round budget is approximately 11.6–12.7 FO4 over that range; at `A=10`, 1.3 ns gives approximately 4.3–4.7 FO4. The guide's “about 12” and “about 4.5” arithmetic is consistent, subject to R9-2.

For Table 1, use `N=60/ell`, `m=N/512`, build time `37.1·N/2^34` seconds and open time `404·N/2^34` seconds from the archived reference run. The probability column is `6e22/(m·2^96)`:

| Displayed `A` | `ell` (ns) | `log2 N` | `log2 m` | Build (s) | Open (min) | One-chain chance |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 13.0 | 32.1038 | 23.1038 | 9.967 | 1.809 | `8.4011e-14` |
| 2 | 6.5 | 33.1038 | 24.1038 | 19.934 | 3.618 | `4.2005e-14` |
| 3.7 | 3.5 | 33.9969 | 24.9969 | 37.020 | 6.719 | `2.2618e-14` |
| 4.5 | 2.9 | 34.2682 | 25.2682 | 44.679 | 8.109 | `1.8741e-14` |
| 10 | 1.3 | 35.4257 | 26.4257 | 99.669 | 18.089 | `8.4011e-15` |

All displayed Table 1 rows agree at their precision. The bold row deliberately uses the measured `N=2^34, m=2^25`, giving 60.1295 seconds at 3.5 ns, rather than an exact 60-second scaling; its 37.1-second build is therefore correct. Using the separate 23.3 ns microbenchmark instead of the archived 404-second opening would give 8.03 rather than 8.11 minutes in the 2.9 ns row; the displayed 8.1 is consistent with scaling the actual opening measurement. The speed-change examples also check: `60·2.9/3.5=49.71` seconds and `60·1.3/3.5=22.29` seconds. Puzzle size remains `68+512·12=6,212` bytes.

## Verification boundary

Compared the commits and confirmed an empty diff for `src/`, `ref/` and `tests/` since round 8. Reviewed the previous counterexample logs and report, checked the revised text, ran the small composition example described above, and independently recalculated the numerical tables. No full test suite, sanitizer, benchmark or implementation build was run in this round, as requested. The remaining findings are minor documentation follow-ups; no blocker or major is open.

VERDICT: ready
