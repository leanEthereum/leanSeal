# Round 14: the revision answering an outside critique of the paper

An outside critique of the paper led to a revision: a hiding theorem for the encryption, a bond for malformed puzzles with an outlined verification game, and a sealed-bid batch auction specified as a complete application and compared with commit–reveal. OpenAI's GPT-6 Astra at high reasoning effort reviewed the uncommitted revision on 2026-10-28, against `d125bd9`, in three passes of one thread; each pass reviewed the revision after the fixes for the previous one. The reports are reproduced as received, with local paths shortened; the changes they led to are in [README.md](README.md).

## Referee review of the uncommitted leanSeal revision

**Revise before committing:** the revision answers several criticisms honestly, but Theorem 2 needs a computationally bounded attacker model, and the proposed bond and auction lack rules needed to support their security, incentive and completeness claims.

### Findings, most severe first

#### 1. major — Theorem 2 inherits unlimited computation, making its HMAC assumption ineffective

**Location:** [security.tex:17](../paper/sections/security.tex:17), [security.tex:45](../paper/sections/security.tex:45), [security.tex:48](../paper/sections/security.tex:48), [appendix-proof.tex:80](../paper/sections/appendix-proof.tex:80).

**Problem:** Theorem 2 quantifies over attackers “as in Theorem 1,” which permits unbounded computation and charges only random-oracle queries. HMAC is explicitly a public function outside those oracles. Exhaustive HMAC computation therefore consumes no counted queries or rounds.

There is a perfect distinguishing attack. Define
\[
S=\{\operatorname{HMAC}_k(\operatorname{be64}(0))
 \mathbin\Vert\operatorname{HMAC}_k(\operatorname{be64}(1))
 \mathbin\Vert\operatorname{HMAC}_k(\operatorname{be64}(2)):
 k\in\{0,1\}^{256}\}.
\]
Since \(|S|\le 2^{256}\), choose a 96-byte string \(\Delta\notin S\oplus S\); such a string exists because \(2^{512}<2^{768}\). Request encryption of either \(0^{96}\) or \(\Delta\), and test whether the ciphertext belongs to \(S\). The two ciphertext supports are disjoint. This uses one envelope and zero random-oracle queries or rounds.

This does **not** contradict the displayed inequality if \(\delta\) allows unrestricted distinguishing computation: then \(\delta\) is essentially one, making the bound vacuous. It contradicts the intended application of ordinary computational PRF security to the theorem’s attacker class.

**Fix:** Keep Theorem 1 information-theoretic, but restrict Theorem 2’s additional computation, including public HMAC evaluations. For example:

> “For every attacker making at most \(Q_{\rm pre}\) and \(Q_{\rm on}\) random-oracle queries and at most \(t\) additional computation steps…”

Define \(\delta\) as a resource-indexed multiuser PRF advantage, accounting for the reduction’s runtime, \(2q\) keys, message lengths and HMAC queries. State explicitly that this computational restriction is additional to Theorem 1.

#### 2. major — The bisection description does not establish the claimed one-honest-disputer guarantee

**Location:** [tradeoffs.tex:45](../paper/sections/tradeoffs.tex:45), [tradeoffs.tex:47](../paper/sections/tradeoffs.tex:47), [tradeoffs.tex:49](../paper/sections/tradeoffs.tex:49).

**Problem:** A pairwise game identifies a locally inconsistent party; it does not necessarily certify the other party’s whole computation.

For example, a claimant and colluding disputer can agree on fabricated intermediate checkpoints and disagree only on the final key derivation. Every midpoint comparison selects the suffix. The claimant derives its final key correctly from their fabricated accumulator, while the disputer deliberately gives an incorrect answer. The disputer loses, although the claimant’s shared prefix was never valid.

If the first disputer monopolizes the game, or winning that game finalizes the assertion, this defeats an honest independent challenger. The text supplies no multiple-challenger or finalization rule excluding that implementation.

The description also omits the canonical initial and terminal states, their binding to the admitted envelope and claimed result, and the state-preimage disclosures needed for the final step. A 32-byte midpoint hash alone cannot be executed by the contract.

**Fix:** Specify the assertion and dispute state machine. Anchor the initial state to the admitted puzzle and the terminal state to the claimed key and commitment check. Require authenticated state openings at final adjudication. Ensure every timely honest challenge remains effective despite colluding challengers; winning one pairwise game must not certify a shared invalid prefix. Define how a valid late opening interacts with a pending malformation claim.

Until then, replace the unconditional guarantee with:

> “A suitably specified optimistic verification protocol could establish malformation, assuming an honest challenger with sufficient time and access to the computation.”

#### 3. major — Solver or disputer nonperformance can prevent settlement indefinitely

**Location:** [tradeoffs.tex:45](../paper/sections/tradeoffs.tex:45), [tradeoffs.tex:52](../paper/sections/tradeoffs.tex:52), [tradeoffs.tex:84](../paper/sections/tradeoffs.tex:84), [tradeoffs.tex:85](../paper/sections/tradeoffs.tex:85).

**Problem:** There is a deadline for initially disputing a claim, but no solver-result deadline, reassignment rule, per-move timeout, timeout winner or bounded dispute-finalization rule. An assigned solver can disappear without producing either a key or a malformation claim. A disputer can initiate a game and stop responding.

Settlement waits for every bid to open or be excluded, so either behavior can lock an entire batch’s escrows indefinitely. Whether the solver receives payment before or after disappearing is itself unspecified.

The auction table’s “minutes later after a missed reveal” also omits the challenge period and potentially much longer dispute process.

**Fix:** Specify result deadlines, solver replacement, nonperformance penalties, move deadlines, timeout defaults and bounded handling of repeated or concurrent challenges. Pay for a timely verifiable outcome, whether successful opening or established failure. State the resulting worst-case settlement bound, including challenge periods, and put it in Table `tab:auction`.

#### 4. major — Designating a solver does not prevent sender self-payment

**Location:** [tradeoffs.tex:52](../paper/sections/tradeoffs.tex:52), [tradeoffs.tex:55](../paper/sections/tradeoffs.tex:55), [tradeoffs.tex:116](../paper/sections/tradeoffs.tex:116).

**Problem:** “The sender, not being the designated solver, cannot claim this payment” assumes distinct addresses have distinct controllers. A sender can control or collude with a selected solver. No eligibility, selection or identity assumption prevents that. Depending on unspecified payout rules, bond-funded dispute rewards may also return to sender-controlled parties.

Thus the claimed losses \(d\) and \(d+B\) are not established as irrecoverable expenditure. The later acknowledgment that recoverable rewards reduce the penalty is correct, but contradicts the categorical claim here.

**Fix:** Specify solver selection and payout rules and analyze coalitions. Replace the quoted sentence with:

> “Designation prevents outsiders from copying an assignment’s reward, but does not exclude sender-controlled solvers. The effective penalty subtracts every reward recoverable by the sender or its coalition.”

Use \(d-r\), or \(d+B-r\), in the incentive analysis, with \(r\) covering all recoverable payments.

#### 5. major — The auction does not establish its claimed one-slot exposure window

**Location:** [tradeoffs.tex:82](../paper/sections/tradeoffs.tex:82), [mempool.tex:44](../paper/sections/mempool.tex:44), [mempool.tex:66](../paper/sections/mempool.tex:66).

**Problem:** Admission specifies when batch \(k\) closes, but not when it opens. It therefore does not establish that an envelope cannot be published several slots before its batch closes. Moreover, exposure starts when a builder or public mempool first receives the envelope, not when it appears on chain.

The timing table assumes a bid is committed first and posted near the close. That publication protocol is missing from the auction. The application also does not choose between fast finality and the explicitly acknowledged reorganization risk.

**Fix:** Define the admission interval and first-publication procedure, including off-chain exposure, propagation and finality assumptions. Require
\[
t_{\rm close/fixed}-t_{\rm first\ exposure}<N\ell
\]
for honestly submitted bids. Either supply the commitment-and-late-publication protocol assumed by the timing table or size the puzzle for the actual longer interval.

#### 6. major — Valid encryption does not establish a valid, executable auction bid

**Location:** [tradeoffs.tex:82](../paper/sections/tradeoffs.tex:82), [tradeoffs.tex:83](../paper/sections/tradeoffs.tex:83), [tradeoffs.tex:85](../paper/sections/tradeoffs.tex:85), [introduction.tex:42](../paper/sections/introduction.tex:42).

**Problem:** A correctly authenticated envelope can contain invalid bid syntax or a payment obligation exceeding its public escrow. Neither condition is puzzle malformation. The application specifies no validation, exclusion or penalty rule for these cases, yet says decrypted bids count and well-formed-puzzle bids settle.

“Clears at a uniform price” also does not determine allocation, ties, supply reservation, payments or refunds. Independent bidder escrows alone do not establish independent settlement if batches compete for shared sale inventory.

**Fix:** Define the bid format and validity predicate; enforce escrow sufficiency on both opening paths; specify invalid-bid exclusion, penalties and refunds; and identify a deterministic clearing and allocation rule with separately reserved assets for each batch.

Otherwise rename the subsection **“An application outline: sealed-bid batch auctions”** and remove “complete application” from the introduction.

#### 7. major — Admission does not bound the computation it promises to fund and adjudicate

**Location:** [tradeoffs.tex:43](../paper/sections/tradeoffs.tex:43), [tradeoffs.tex:76](../paper/sections/tradeoffs.tex:76), [tradeoffs.tex:82](../paper/sections/tradeoffs.tex:82); [SPEC.md:38](../SPEC.md:38), [SPEC.md:136](../SPEC.md:136).

**Problem:** The auction does not restrict accepted puzzle work or envelope length to the reference setting used in its cost and availability claims.

The format permits \(nm\le2^{60}\), approximately 128 years of work at 3.5 ns per step, and ciphertexts up to \(2^{24}\) bytes. Authenticating a maximum-length envelope alone requires over 262,144 SHA-256 compressions. “A few hundred” is therefore not a bound for admitted inputs; fully decrypting the message costs substantially more.

Charging a fixed deposit without a corresponding work limit also does not establish the claimed workload-per-expenditure bound.

**Fix:** Set application-specific limits on \(n,m,b,nm\), envelope length and aggregate admitted work. Relate fees and capacity to those limits. For tag failure, replace the current sentence with:

> “Given a key matching \(C\), the contract checks the envelope’s authentication tag directly. This costs work linear in the envelope length, which admission caps at [specified limit].”

No plaintext decryption is needed to establish a failing tag.

#### 8. major — An attacker can induce nearly a full solve without forfeiting the bond

**Location:** [tradeoffs.tex:40](../paper/sections/tradeoffs.tex:40), [tradeoffs.tex:76](../paper/sections/tradeoffs.tex:76), [tradeoffs.tex:84](../paper/sections/tradeoffs.tex:84).

**Problem:** The denial-of-service analysis says each malicious solve costs the attacker both its deposit and bond. The refund rules permit a counterexample:

1. Submit cheap inconsistent chains, but a valid envelope under a known key matching \(C\).
2. Miss the reveal deadline.
3. Let the assigned solver perform almost all the work.
4. Publish the known key before failure is established.

The bid opens and \(B\) is refunded. Almost the entire solve was induced for the deposit alone, further reduced by any recoverable rewards.

**Fix:** Price worst-case solver work against the irrecoverable portion of \(d\). Replace the relevant claim with:

> “A missed reveal can induce nearly a full solve while costing only the net deposit penalty. The bond is additionally forfeited when malformation is established before a successful opening resolves the bid.”

Quantify the workload funded by that net penalty, including verification, dispute and redundancy costs. Deposits price demand; they do not themselves establish a finite recovery-capacity or latency guarantee.

#### 9. major — The abstract claims elimination of an option that the bond only prices

**Location:** [abstract.tex:7](../paper/sections/abstract.tex:7), [introduction.tex:42](../paper/sections/introduction.tex:42), [tradeoffs.tex:73](../paper/sections/tradeoffs.tex:73), [tradeoffs.tex:88](../paper/sections/tradeoffs.tex:88).

**Problem:** For any finite \(d+B\), a sender can prepare a malformed puzzle, reveal when favorable, and otherwise purchase exclusion by forfeiting the penalty. The paper gives neither a bound on that sender’s gain nor a bond-sizing result eliminating this behavior.

The abstract nevertheless says the auction “removes the option to withhold.” The more careful statement at line 73 correctly says the bond prices malformation rather than ruling it out. “Without penalizing bidders that go offline” is also inaccurate unless it explicitly means *without the additional bond penalty*: they still lose \(d\).

**Fix:** Use consistently:

> “In a sealed-bid batch auction, a valid, adequately escrowed bid with a well-formed puzzle remains binding after a missed reveal. Withholding a malformed bid incurs an additional bond penalty; an honest offline bidder still forfeits the reveal deposit.”

Claims of deterrence beyond this need an explicit utility bound and sufficient net penalty.

#### 10. minor — The commit–reveal comparison substitutes whole-escrow forfeiture for an equal penalty

**Location:** [tradeoffs.tex:88](../paper/sections/tradeoffs.tex:88), [tradeoffs.tex:96](../paper/sections/tradeoffs.tex:96), [tradeoffs.tex:98](../paper/sections/tradeoffs.tex:98).

**Problem:** Commit–reveal can impose a separate deposit \(d+B\). It need not confiscate the entire trading escrow to match leanSeal’s malformed-withholding penalty. Nothing equates \(B\) with that escrow.

The genuine distinction is that commit–reveal charges its higher penalty on accidental missed reveals too. The current middle column obscures that distinction and does not implement the requested equal-penalty comparison.

**Fix:** Replace the prose with:

> “Commit–reveal can impose the same \(d+B\) penalty on every missed reveal, but then an offline bidder pays it too.”

Change the middle column to **“Commit–reveal, deposit \(d+B\)”** and update its forfeiture cells. Label Table `tab:bond` as **forfeitures**, rather than total costs: precomputation and locked capital are not free merely because they precede submission.

#### 11. minor — The numerical hiding summary incorrectly drops its dependence on \(q\)

**Location:** [security.tex:56](../paper/sections/security.tex:56).

**Problem:** The first term does not dominate for unrestricted \(q\). After the theorem’s factor two, the nonce contribution is \(q^2/2^{128}\): it is already \(2^{-116}\) at \(q=64\), and \(2^{-108}\) at \(q=1024\).

“Several envelopes … add only the nonce term” is also false: \(P'=P+2q\) and the multiuser HMAC advantage depend on \(q\).

**Fix:** Replace with:

> “For the reference puzzle and sufficiently few envelopes, the doubled link-guessing term is about \(2^{-116}\). The bound also includes \(q^2/2^{128}\), the additional path-value terms through \(P'=P+2q\), and \(2\delta\). The nonce term can dominate when many envelopes share a puzzle.”

#### 12. minor — Exactly 2.5 times faster does not open the reference puzzle before 12 seconds

**Location:** [abstract.tex:5](../paper/sections/abstract.tex:5), [introduction.tex:37](../paper/sections/introduction.tex:37).

**Problem:** The reference delay is \(2^{33}\cdot3.5\text{ ns}=30.064771072\) seconds. Dividing by 2.5 gives **12.0259084288 seconds**, still after the deadline. The exact break-even factor is approximately **2.505397589**.

**Fix:** Prefer the already correct concrete example:

> “At 1.3 ns per step, the reference puzzle opens in 11.2 seconds, before a 12-second ordering deadline.”

Alternatively say “more than about 2.5 times faster.”

#### 13. minor — The linked paper and security documentation still describe the previous revision

**Location:** [README.md:32](../README.md:32), [SPEC.md:206](../SPEC.md:206), [docs/security.md:76](../docs/security.md:76), [docs/security.md:70](../docs/security.md:70).

**Problem:** README advertises the bond and auction but links to `docs/leanseal.pdf`, which remains the old **26-page** paper. The supplied revised PDF has **30 pages**. The linked old PDF still uses the rejected timed-commitment wording and says the encryption reduction is unwritten.

SPEC.md and docs/security.md also explicitly say the reduction has not been written. The security documentation’s hardware-appendix reference becomes stale because the new hiding appendix moves hardware from Appendix B to Appendix C.

**Fix:** After repairing the theorem, synchronize those descriptions and references, and publish the corrected built PDF at the README’s target. Keep the explicit statement that the prototype does not implement the bond.

### Checked and found correct

**The proof structure is otherwise sound in its disclosed model.**

- The nonce-collision probability is at most \(q(q-1)/2^{129}\), conservatively bounded by \(q^2/2^{129}\). Predrawing nonces is valid for adaptive envelope requests.
- There are exactly \(2q\) added path values. Their only predecessor is \(K\), giving legitimate revelation round \(T_{\rm key}+1\).
- The sequentiality claim extends unchanged. The coupling extends because equal transcripts produce equal adaptive requests, and distinct labels/nonces give distinct subkey inputs outside the added collision event.
- The bad-event argument survives the envelopes: they depend on independent ideal subkeys, and no path input contains a subkey. Queries to the subkey derivations must guess the still-hidden \(K\). The \(QP'/2^{256}+P'^2/2^{256}\) allowance is sufficient.
- The factor two correctly accounts for the two challenge bits. No additional final-key-guess term \(2^{-256}\) is needed for this distinguishing game.
- Replacing the keyed functions makes equal-length ciphertexts and tags independent of the challenge bit, including adaptive requests.
- The strict threshold \(<T_{\rm key}\) is sufficient. The theorem correctly makes no guarantee from that round onward.
- Treating HMAC outside the random oracles is expressly disclosed in the appendix. This is a separate-primitive idealization, not a proof modeling HMAC through the same ideal SHA oracle. Finding 1 concerns its computational resources, not a hidden modeling choice.
- The encryption construction matches SPEC.md §7.

**The proposed step state contains enough information in principle.** A chain step updates its current state with \(F_i\). A boundary can update the accumulator, recover the next link using the mask and public \(z_i\), and derive the next start. The last boundary can derive \(K\) and check \(C\). Earlier chain ends need not be retained. The missing pieces are the game rules and authenticated endpoints, not another secret component of the state.

A matching-\(C\) key with a failing tag is explicitly recognized and can be adjudicated directly. Conversely, possession of a matching key alone does not prove that the chains derive it. Any independent solver can reconstruct the correct trace without the sender, subject to adequate time, data availability and the repaired dispute rules.

**The numerical recomputations largely agree with the revision.** Values below are derived from the paper’s stated inputs; they do not independently validate assumed hardware speeds, power consumption or rental prices.

| Quantity | Recomputed result |
|---|---|
| Reference work, path values, key round | \(N=8,589,934,592\); \(P=8,589,934,641\); \(T_{\rm key}=8,589,934,625\) |
| Reference delay | 30.064771072 s |
| Minimum step latency for a 12 s window | 1.396983862 ns |
| Delay at 1.3 ns | 11.166914970 s, correctly rounded to 11.2 s |
| Hardware advantage ratios | \(13/3.5=3.7143\); \(23.2/3.5=6.6286\) |
| Reference bounds, 16/24/32-byte links | Approximately \(2^{-53.33}\), \(2^{-117.33}\), \(2^{-148.33}\) |
| One-year bounds | Approximately \(2^{-33.33}\), \(2^{-97.33}\), \(2^{-108.33}\) |
| One year of preprocessing against the reference puzzle | Additional contribution approximately \(2^{-128.33}\) |
| Full-width versus link-guessing term | Approximately \(2^{31}\) smaller |
| Minimum chains for a one-year delay | 33 |
| Halved measured build times | Air 21.05 s; Max 15.05 s |
| Halved measured solve time | 201 s, or 3 min 21 s |
| Four-chain build projection | 49.82 s |
| Five-puzzle batch amortization | 18.76 s per reference puzzle |
| Single-chain stock projection | 30 s per puzzle; 2,880/day, reasonably described as about 2,800 |
| CPU/GPU cost ratios | Approximately 0.70 and 0.0965 seconds per second of delay |
| Recurring generation at 265 transactions/12 s | 463.75 laptops at 21 s; 681.43 at 2,800/day |
| Energy at assumed 20 W | 0.1167–0.1714 Wh/transaction |
| Total assumed power | 9.275–13.629 kW |
| Full recovery demand | About 662.5 attacker-speed circuits or 4,438.75 laptop cores |
| One-percent recovery demand | About 44.39 laptop cores |
| Rental cost at $0.04/core-hour | 0.2233 cents per 201-second solve |
| Option estimates for 12/30/201 s | 0.0148% / 0.0234% / 0.0606%; $1.48 on $10,000 at 12 s |
| Puzzle sizes for 16/4/1 chains | 452 / 164 / 92 bytes |
| Envelope overhead | 512 / 224 / 152 bytes |
| Sealed 110-byte message | 622 or 262 bytes |
| Growth from a 179-byte median | 3.8603× or 1.8492× |
| Added calldata gas | 8,192 or 2,432; floor-rate figures 20,480 or 6,080 |
| Hardware model | 2.752–5.1136 ns before overhead; upper adjusted endpoint 9.74448 ns |
| Demonstration workload and loss | \(2^{29}=N/16\); approximately 9.2546% loss |
| Bisection depth | About 33 logarithmic levels; a schedule longer than \(2^{33}\) has a worst-case ceiling of 34 |

The timing-table scaling, sixty-fold finality scaling, 13.5/12.5 timing ratios, two-second-puzzle estimates, 480,000 mutation count and reported prototype gas figures agree with their stated calculations or local records. I independently counted the archived sample’s 20 blocks and 5,300 transactions and recomputed its 179-byte median.

The 20 W estimate and unarchived stock-building run are honestly identified as such. I confirmed the identities of [BLT25](https://eprint.iacr.org/2025/1254) and [Tree-BTE through its author’s publication list](https://sourav1547.github.io/). **Tree-BTE’s 0.89 MB figure and BLT25’s absence of reported sizes remain independently unverified:** the source PDFs returned HTTP 403, and the browser fallback was unavailable. I do not count those claims as verified or as demonstrated errors.

**Critique coverage:**

| Critique item | Assessment |
|---|---|
| 1. Timed-commitment terminology | Adequately corrected in the revised sources. Missing verifiable recovery is admitted. Linked artifacts still need synchronization. |
| 2. Malformed-puzzle denial of service | Asymmetry admitted correctly; payment, capacity and dispute mechanisms remain insufficiently specified. |
| 3. Complete application and equal baseline | Not adequately answered yet: Findings 2–10 affect the proposed application and comparison. |
| 4. Sandwich demonstration | Adequately corrected. Ordinary encryption, reveal and pool rules receive the credit; the separate recovery experiment is qualified. |
| 5. Hardware sensitivity | Substantially answered, subject to the small 2.5× correction. |
| 6. Encryption proof | Substantial progress: the hybrid proof works, but the computational-model defect must be repaired. The exact-encoding quantum gap remains honestly admitted. |
| 7. Recurring generation cost | Adequately answered numerically, with measurement limitations disclosed. |
| Solver-reward correction | Net-penalty principle accepted, but the new designation claim reintroduces an unsupported exclusion of self-claims. |
| Outsourcing correction | Adequately answered: recovery requires every component puzzle to be well formed. |
| Closing request | Not yet met: a complete robust application and quantified disruption cost still depend on unspecified mechanisms. |

The prototype comparison is accurate: [SealedInbox.sol:218](../poc/contracts/src/SealedInbox.sol:218) accepts a matching key, pays the public bounty and does not execute the missed ticket. It implements neither the bond nor bisection. The revised text correctly distinguishes those facts.

Verification consisted of the complete uncommitted diff, relevant sources and SPEC, both supplied PDFs, visual inspection of the revised proof/protocol pages, prototype call-path inspection, archived-data checks and Python arithmetic. `git diff --check` passed. No LaTeX build or implementation test suite was run. No worktree files were changed, added or deleted; no commit was made. Prose checks found no em-dashes or question-shaped section/paragraph headings.

VERDICT: revise

## Referee review of the leanSeal revision, round 2

**Revise:** the theorem’s principal defect is fixed and most earlier corrections are satisfactory, but the solver deadlines, failure-payment rules, bisection adjudication and reveal timing still contain major inconsistencies.

### Findings, most severe first

#### 1. major — The solver deadline expires before an honest malformation claim can stand

**Location:** [tradeoffs.tex:54](../paper/sections/tradeoffs.tex:54), [tradeoffs.tex:94](../paper/sections/tradeoffs.tex:94).

**Problem:** Payment requires the solver’s claim to **stand before its deadline**. The example sets both the solver deadline \(D_s\) and challenge period \(D_c\) to ten minutes.

An honest solver finishing after 201 seconds submits its claim at minute 3.35. Even without a challenger, that claim cannot stand before minute 13.35. The written rule instead slashes the solver and reassigns the bid at minute 10. A disputed claim takes longer still.

The settlement paragraph also overlooks the challenge period for an **unchallenged** malformation claim. That case does not necessarily finish within ten minutes.

**Fix:** Make \(D_s\) a submission deadline, with adjudication extending the assignment:

> “Before \(D_s\), the solver must submit a valid opening, accepted authentication-failure evidence, or a malformation claim. A timely claim preserves the assignment until adjudication finishes. Payment and release or forfeiture of the solver’s stake follow that result.”

Then distinguish these conditional bounds, measured from assignment:

- Successful opening or direct failure evidence: \(D_s\).
- Unchallenged malformation claim: \(D_s+D_c\).
- Disputed claim: \(D_s+D_c+69\tau\).

With the example parameters, these are **10, 20 and 158 minutes**. Update the table accordingly, retaining the honest/live-solver and timely-inclusion assumptions.

#### 2. major — Direct tag-failure evidence is missing from the solver’s payable outcomes

**Location:** [tradeoffs.tex:43](../paper/sections/tradeoffs.tex:43), [tradeoffs.tex:46](../paper/sections/tradeoffs.tex:46), [tradeoffs.tex:54](../paper/sections/tradeoffs.tex:54), [tradeoffs.tex:90](../paper/sections/tradeoffs.tex:90).

**Problem:** Suppose solving produces a key matching \(C\), but the envelope’s tag fails. The contract can correctly establish malformation directly.

Nevertheless, neither listed payable outcome applies: the transaction has not opened, and the solver cannot make the game’s required claim that its derived key fails the commitment check. The solver-payment rule therefore does not cover an honest solver reporting this expressly supported failure case.

**Fix:** Explicitly include accepted authentication-failure evidence as successful completion of an assignment:

> “A payable outcome is a valid opening, a directly verified authentication failure under a key matching \(C\), or the solver’s malformation claim surviving adjudication.”

Specify that direct failure releases the honest solver’s stake and pays its assignment reward.

#### 3. major — Final adjudication requires a challenger hash that the game never obtains

**Location:** [tradeoffs.tex:46](../paper/sections/tradeoffs.tex:46), [tradeoffs.tex:48](../paper/sections/tradeoffs.tex:48).

**Problem:** At each midpoint, the claimant posts a hash and the challenger supplies only agreement or disagreement. When the challenger disagrees, the interval’s upper endpoint moves, but the challenger supplies no hash for that new endpoint.

Final adjudication nevertheless compares the computed successor against “each side’s hash.”

For a four-step computation, let the claimant supply a false midpoint \(S'_2\). The honest challenger disagrees, then agrees with the true \(S_1\). The final step computes \(S_2\). The contract has the claimant’s hash of \(S'_2\), but the challenger’s only submitted upper-end hash remains that of \(S_4\). Comparing against both contradicts both, including the honest challenger.

**Fix:** The simplest repair preserves the Boolean game:

> “The contract recomputes the successor of the opened agreed state and compares its hash with the claimant’s recorded upper-end hash. The claimant wins if they match; otherwise the challenger wins.”

Alternatively, require the challenger to submit its own midpoint hash on disagreement and maintain both parties’ endpoint hashes explicitly.

#### 4. major — The reveal phase can disclose bids before the stated finality deadline

**Location:** [tradeoffs.tex:88](../paper/sections/tradeoffs.tex:88), [tradeoffs.tex:89](../paper/sections/tradeoffs.tex:89).

**Problem:** The bid set is declared fixed only when slot \(k\)’s block becomes final, but bidders may reveal within \(W\) slots after slot \(k\), without waiting for finality.

For example, with \(W=1\) or \(2\), keys can become public after 12 or 24 seconds under the paper’s approximately 13-minute current-finality assumption. A longer puzzle does not protect a voluntarily revealed key. A reorganization can then change the auction’s admitted set after its bids are readable.

Even the fast-finality version needs an explicit requirement that voluntary release follows finality.

**Fix:** Replace the reveal timing with:

> “The reveal phase begins only after the block containing the admitted bid set is final. Each bidder publishes its key within the next \(W\) slots.”

Use that same event to anchor refunds, missed-reveal detection and settlement bounds. Alternatively, explicitly adopt the weaker reorganization-degradation policy for this auction and narrow its guarantee.

#### 5. minor — The admission policy caps work but does not specify the required privacy delay

**Location:** [tradeoffs.tex:87](../paper/sections/tradeoffs.tex:87), [tradeoffs.tex:88](../paper/sections/tradeoffs.tex:88).

**Problem:** The upper bound \(nm\le2^{33}\) admits \(n=m=1\). Admission therefore does not establish the reference delay claimed in the exposure paragraph. This does not attack a correctly configured reference puzzle, but the application leaves its required configuration unspecified.

The suggested current-finality variant also cannot fit the stated upper bound: at 3.5 ns, \(2^{33}\) steps provide only 30.065 seconds, not 13 minutes.

**Fix:** Define a target exposure interval and the required work for honest bidders, preferably enforced by admission. For the stated reference application, require the selected reference work and explicitly restrict the application to the assumed fast-finality setting. A current-finality variant needs separately increased work limits and recomputed costs.

#### 6. minor — The auction’s admitted envelopes can exceed its stated 512-byte overhead

**Location:** [tradeoffs.tex:87](../paper/sections/tradeoffs.tex:87), [tradeoffs.tex:108](../paper/sections/tradeoffs.tex:108).

**Problem:** Admission permits \(n=16,b=32\). Its overhead is
\[
128+nb=128+16\cdot32=640\text{ bytes},
\]
whereas Table `tab:auction` says 152–512 bytes.

**Fix:** Either restrict this application to \(b=24\), or replace the table entry with:

> “152 to 640 bytes; 512 with the reference parameters.”

The other 512-byte figures describing the particular reference configuration remain correct.

#### 7. minor — The theorem summaries still omit qualifications or misplace the factor two

**Location:** [SPEC.md:206](../SPEC.md:206), [introduction.tex:37](../paper/sections/introduction.tex:37).

**Problem:** SPEC.md describes “twice the bound above … plus” the nonce term and \(\delta\). Read literally, this doubles only the delay bound. The theorem doubles the nonce and HMAC terms too.

The introduction still says “the same bound, doubled” limits distinguishing advantage, omitting the additional terms and the newly required computation bound.

**Fix:** Give SPEC.md the exact expression:
\[
2\left(
\frac{Q_{\rm on}}{2^{8b}}
+\frac{Q_{\rm pre}}{2^{128+8b}}
+\frac{QP'+P'^2}{2^{256}}
+\frac{q^2}{2^{129}}
+\delta
\right),\qquad P'=P+2q,
\]
with the first term absent for \(n=1\).

Replace the introduction’s sentence with:

> “A second theorem gives a corresponding hiding bound for computationally bounded attackers, including nonce-collision and HMAC-PRF terms.”

### Checked and found correct

**Disposition of all 13 previous findings:**

| Previous finding | Round 2 disposition |
|---|---|
| 1. Unbounded computation versus HMAC security | **Fixed.** Theorem 2 explicitly bounds additional computation by \(t\) and uses a time-indexed PRF advantage. |
| 2. Incomplete bisection soundness | **Partly fixed.** Initial-state anchoring, state openings and independent parallel challenges address the original omissions and colluding-first-disputer case. Final adjudication still needs Finding 3 above. |
| 3. Solver/disputer nonperformance | **Partly fixed.** Deadlines, stake losses and reassignment are supplied, but their interaction with claim finalization is inconsistent. |
| 4. Sender-controlled solver payments | **Fixed.** Coalition recovery \(r\) is acknowledged; designation no longer purports to prevent self-payment. |
| 5. Exposure window | **Partly fixed.** Current-slot admission and first off-chain exposure are specified. Voluntary release still needs synchronization with finality. |
| 6. Invalid bids, escrow and clearing | **Fixed at the paper-design level.** The revision supplies a validity predicate, escrow check, exclusion, separately deposited supply, allocation and refunds. |
| 7. Unbounded admitted computation | **Fixed in substance.** Work, envelope length and batch count are bounded. The permitted configurations introduce the narrower issues in Findings 5–6 above. |
| 8. Late opening avoids bond forfeiture | **Fixed.** The attack and its implication for net-deposit pricing are now stated explicitly. |
| 9. Finite bond claimed to eliminate the option | **Fixed.** The paper now distinguishes binding well-formed bids from the priced malformed-puzzle option. |
| 10. Unequal commit–reveal penalty comparison | **Fixed.** The middle column uses \(d+B\), and the offline-bidder distinction is correct. |
| 11. Missing \(q\)-dependence in hiding summary | **Fixed.** The security section retains the nonce, \(P'\) and multiuser HMAC terms. |
| 12. Exactly 2.5× faster wording | **Fixed.** The replacement uses the correct 1.3 ns / 11.2 s example. |
| 13. Stale documentation and linked PDF | **Fixed as synchronization.** Both PDFs match, stale “unwritten reduction” statements are removed, and the hardware appendix reference is corrected. Finding 7 above concerns the new summary wording. |

**Theorem 2.** I found no remaining major defect in the revised theorem or hybrid argument. The \(2q\) additional path values, nonce-collision event, factor two and strict round threshold remain correctly accounted for. The ideal simulator can use PRF-oracle handles without knowing their keys: no path input contains a subkey, and no subkey is legitimately revealed before the stopping threshold.

The simulation-time statement would be clearer if it explicitly included total envelope-byte processing and the oracle cost convention. Given the specification’s bounded lengths, I do not regard that as a demonstrated failure of the revised bound. HMAC’s treatment outside the random oracles remains honestly disclosed.

**Game and mechanism.** Parallel independent challenges fix the previous colluding-first-disputer problem. The checkpoint plus current link remains sufficient for local chain, boundary and final-key calculations. The late-key rule now explicitly resolves pending games before a claim stands. The revised net-penalty and denial-of-service discussion correctly distinguishes pricing work from guaranteeing available capacity.

**New numerical checks:**

| Claim | Recomputed result |
|---|---|
| Bisection depth for reference work plus boundary steps | Worst-case depth **34 rounds** |
| Two moves per round plus final adjudication | \(34\cdot2+1=\mathbf{69}\) moves |
| Game allowance at \(\tau=2\) minutes | **138 minutes** |
| Challenge period plus game | **148 minutes** |
| Solver submission allowance plus challenge and game | **158 minutes**, correctly under three hours |
| Earliest unchallenged failure after a 201-second solve | **13.35 minutes**, exposing Finding 1 |
| Maximum unchallenged failure with corrected submission-deadline semantics | **20 minutes** |
| Delay at 1.3 ns | **11.166914970 seconds**, correctly 11.2 s |
| Relative speed \(3.5/1.3\) | **2.6923**, correctly 2.7 |
| Permitted auction overhead | **152–640 bytes**, with 512 for the reference parameters |

“About a dozen compressions” is plausible but not exactly reproducible until the fixed bid’s field widths are stated. For a 96-byte bid, straightforward HMAC tag evaluation uses **13 compressions** with reference overhead and **15** at the admitted maximum; deriving the MAC subkey adds two, and checking the commitment adds another two. The statement should make clear which operations it counts.

Both PDF files are **32 pages**, **369,576 bytes**, and byte-identical, with SHA-256:

`e1112dbe8dabed7d7119bce6dd330993238eeee0584adca945be5c68d2a6fb04`

The revised sources and PDF retain the corrected terminology, sandwich-demo attribution, recurring-cost accounting and outsourcing qualification. The prototype remains accurately described as implementing neither the bond nor the game. Critique points 1, 4, 5, 6 and 7 are now answered substantially; the remaining major findings concern points 2, 3 and the closing request for a complete robust application.

Verification used the full revision diff, source and specification inspection, PDF extraction and visual inspection, explicit deadline and bisection counterexamples, and Python arithmetic. `git diff --check` passed. No unresolved PDF reference markers, prose em-dashes or question-shaped section/paragraph headings were found. No LaTeX build or implementation tests were run. No worktree files were changed and no commit was made.

VERDICT: revise

## Round 3 review of leanSeal

I approve this revision: all seven round-2 findings are fixed in substance, and I found no remaining blocker or major defect in the revised material; two minor wording issues remain.

### Findings, most severe first

#### 1. minor — The compression count needs an explicit bid length

**Location:** [paper/sections/tradeoffs.tex:89](../paper/sections/tradeoffs.tex:89)

**Problem:** “Fewer than 20 SHA-256 compressions” depends on the plaintext length, but the preceding paragraph specifies only a fixed-length tuple `(k,p,x)`, without its encoding widths.

For the largest admitted puzzle, the authenticated envelope prefix has `480 + L` bytes. Checking the commitment, deriving the MAC subkey and checking the tag costs
`7 + ceil((489 + L)/64)` compressions. This is 17 for a 96-byte bid, but reaches 20 at 280 bytes.

**Fix:** Specify the intended encoding and qualify the count, for example:

> Encode each of \(k,p,x\) as a 32-byte unsigned integer, giving a 96-byte plaintext. Checking the commitment, deriving the MAC subkey and checking the tag then take at most 17 SHA-256 compressions.

#### 2. minor — The auction table obscures the settlement clock’s starting point

**Location:** [paper/sections/tradeoffs.tex:112](../paper/sections/tradeoffs.tex:112)

**Problem:** The text correctly measures the 10-, 20- and 158-minute bounds **from assignment**. The table instead says “after a missed reveal, 10 minutes later, 20 after an unchallenged claim, 158 after a disputed one.” This suggests different starting points and omits any interval between the reveal deadline and solver assignment.

**Fix:** Replace the leanSeal settlement cell with:

> After the reveal window if all bids reveal; otherwise, from the first solver assignment: at most 10 minutes for an opening or failing tag, 20 for an unchallenged claim, and 158 for a disputed claim.

Keep the caption’s honest, live solver and timely-inclusion assumptions.

### Checked and found correct

All seven round-2 findings are fixed:

| Round-2 finding | Status and evidence |
|---|---|
| **1. Solver deadline could expire during a timely dispute** | **Fixed.** `tradeoffs.tex:56` makes \(D_s\) a submission deadline and retains a timely claim’s assignment until adjudication. |
| **2. A failing tag was not a payable solver outcome** | **Fixed.** `tradeoffs.tex:56` explicitly includes evidence of a failing tag under a key matching \(C\), with payment and stake recovery. |
| **3. Final adjudication required an unavailable challenger endpoint** | **Fixed.** `tradeoffs.tex:48` checks the recomputed successor against the claimant’s upper-endpoint hash. The challenger supplies only agreement or disagreement during bisection. |
| **4. Reveal could begin before the admitted bid set was final** | **Fixed.** `tradeoffs.tex:91` starts the reveal window after slot \(k\)’s block is final. |
| **5. Admission and finality did not ensure the intended exposure delay** | **Fixed.** `tradeoffs.tex:89–90` requires \(nm=2^{33}\) and explicitly assumes finality within the reference delay. It acknowledges that current finality requires substantially more work. |
| **6. The admitted parameters exceeded the table’s 512-byte maximum** | **Fixed.** Admission now requires \(n\le16\) and \(b=24\), giving overhead \(128+nb\), from 152 to 512 bytes. |
| **7. Introduction and SPEC misstated the hiding result** | **Fixed.** `introduction.tex:37` acknowledges bounded additional computation. `SPEC.md:206` includes the outer factor 2, \(P'=P+2q\), nonce term, HMAC term and \(n=1\) exception. |

The remaining checks support approval:

- **Theorem 2:** The revised statement and appendix retain the necessary computation bound and time-indexed multi-key PRF assumption. The two subkeys per envelope account for \(P'=P+2q\); nonce collisions contribute \(q^2/2^{129}\) before the outer factor 2. Comparing each challenge-bit experiment with the common ideal experiment explains that factor and \(2\delta\). The threshold remains strictly before \(T_{\mathrm{key}}\). I found no new counterexample or missing case in the changed text.
- **Bisection:** An honest challenger preserves a correct lower endpoint and an incorrect claimed upper endpoint. The final transition therefore defeats a false claim; an honest claimant survives malicious branch choices. Parallel games preserve an honest challenge despite colluding challengers. I also exhaustively checked this branching invariant on 1,080 small false traces.
- **Payments and liveness:** Timely claims, direct tag failures, reassignment and late matching keys now have coherent outcomes under the stated assumptions. The coalition accounting \(d-r\) and \(d+B-r\) continues to cover sender-controlled solvers. The paper acknowledges capacity, inclusion and dispute-cost limitations rather than claiming unconditional service.
- **Arithmetic:** A trace just above \(2^{33}\) steps needs 34 bisection rounds. Two moves per round plus final adjudication gives 69 moves. With \(D_s=D_c=10\) minutes and \(\tau=2\) minutes, the bounds are **10, 20 and 158 minutes from assignment**. The reference chain work takes 30.0648 seconds at 3.5 ns per step and 11.1669 seconds at 1.3 ns per step, consistent with the rounded hardware figures.
- **Presentation and artifacts:** The rebuilt review PDF has 32 pages and is byte-identical to `docs/leanseal.pdf`. I inspected the rendered game and auction-table pages. The source scan found no em-dashes or question-shaped headings. The bond remains accurately presented as a protocol outline requiring deployment specification, not functionality implemented in `poc/`.

Verification used source and diff inspection, PDF extraction and rendering, Python arithmetic and the small bisection check. `git diff --check` passed. I did not run LaTeX or prototype tests. No worktree files were changed; scratch artifacts were confined to `/tmp/leanseal-review.RqDYJH`.

VERDICT: approve
