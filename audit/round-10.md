# Round 10: the whole repository

Audited `7b04dd7` on 2026-10-28 by OpenAI's GPT-5.6 Sol. The report is reproduced as received, with its formatting adapted to Markdown and one remark about the organization's name left out; the changes it led to are in [README.md](README.md).

## Verdict

At commit `7b04dd7`, leanSeal is a strong, unusually candid research prototype. I found no break of the chained-hash construction, no mismatch between the specification and core Rust implementation, and no error in the stated classical random-oracle round bound.

It is not production-ready. The main blockers are in the EVM PoC's key custody, signing dependencies, and safe deployment configuration, not the time-lock primitive itself. This agrees with the repository's warning not to protect anything of value.

## Findings

### 1. [High if deployed] `sealnet` exposes Ethereum private keys through command-line arguments.

`Args::parse` copies every argument into a long-lived `HashMap<String, String>`, and `connect` reads the wallet from `--key`; `delegate` parses it a second time. See `main.rs:37–90` and `main.rs:174–184`.

This can expose the key through shell history, process listings, diagnostic captures, and process memory for the lifetime of keeper/solver/searcher daemons. It is acceptable only for the stated local Anvil demo. Before any valuable-key use, switch to a keystore, hardware/remote signer, or protected file descriptor and erase temporary key material.

### 2. [Medium] The PoC signing path has a current timing-side-channel advisory.

`cargo audit --deny warnings` fails for `poc/node/Cargo.lock` because it locks `crypto-bigint 0.5.5`, reached through Alloy → k256 → elliptic-curve and used by the local `PrivateKeySigner`.

[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) reports secret-dependent timing in operations intended to be constant-time, with possible cryptographic-secret recovery depending on the downstream algorithm and observer. I did not establish a practical attack against this exact signer, but it is a deployment blocker until the Alloy/k256 chain can use the patched `crypto-bigint >=0.7.6` generation or signing is moved out of process. The scan also reports two unmaintained transitive crates, `derivative` and `paste`.

The core leanSeal crate's dependency audit is clean.

### 3. [Medium] A security-critical target allowlist is optional and disabled by default.

`restricted` begins false; `restrictTo` is a separate, one-time administrative transaction, and `_run` enforces the allowlist only when `restricted` is true. See `SealedInbox.sol:64–66`, `:137–144`, and `:256–270`.

Without restriction, an arbitrary target can use state updated after keys are revealed and call the guarded pool while the global `executing()` bypass is active, the adaptive attack the documentation itself identifies. The demo deploy script restricts immediately, so the provided demonstration is configured correctly. A safer design would commit the allowlist in the constructor, deploy and initialize atomically, or reject submissions until restriction is finalized.

### 4. [Low] Secret erasure is incomplete beyond the already acknowledged "main paths."

HMAC copies the raw key into `k`, constructs pads, and leaves those buffers and SHA state unerased in `hash.rs:110–133`. CLI keys and plaintexts are also wiped only after several fallible operations; write, RNG, authentication, or save errors return before the `fill(0)` calls in `main.rs:549–624` and `main.rs:880–906`.

`docs/security.md` correctly disclaims complete side-channel hardening, so this is defense-in-depth rather than a contradicted primary guarantee. RAII zeroization should nevertheless cover all HMAC scratch buffers and error paths.

### 5. [Low, paper] The `2^52` budget-error margin is stated too broadly.

Assumption A3 says that a budget error of up to `2^52` keeps "the bound" below `2^-64`, without identifying the parameter set. See `security.tex:8–11`.

This is true, conservatively, for the reference 30-second, 24-byte-link puzzle: its bound is about `2^-117.33`, leaving roughly 53 bits. It is not true generally:

- One-year, 24-byte puzzle: about `2^-97.33`, leaving only about 33 bits.
- A 16-byte-link reference puzzle is already about `2^-53.33`.

The theorem and concrete tables are correct; the sentence should explicitly say "for the reference 30-second puzzle with 24-byte links."

### 6. [Low, process] The green CI badge covers only the core crate.

Current GitHub checks are all green, including Rust 1.80, x86, ARM Linux, and Apple ARM. But the workflow does not run the Solidity tests, build/test the node, run dependency auditing, or exercise fuzz targets. This is why the node advisory coexists with a fully green commit. Add PoC contract/node jobs, `cargo audit`, and scheduled sanitizer fuzzing.

## Paper and proof assessment

The core proof appears internally sound on detailed review:

- The honest schedules `m+n+3` for generation and `n(m+2)+1` for key derivation are correct.
- The path-value count `P=n(m+3)+1` is correct.
- The ideal-experiment coupling, path-collision event, hidden-link guessing terms, and full-width predecessor bounds are consistent.
- The actual byte domains are separated by fixed labels, indices, and input lengths, matching the independent-oracle abstraction.
- I independently reproduced the headline exponents: approximately `-117.33`, `-97.33`, `-148.34`, and `-108.33` for the cited parameter cases.
- The proof's relationship to Pietrzak–Reyzin (ePrint 2026/2569) is methodological; that paper does not independently validate leanSeal's custom coupling.

The paper is appropriately explicit about what is not proved: message-confidentiality reduction, exact-encoding quantum security, puzzle well-formedness, and a physical lower bound on SHA latency. The MMV construction and quantum result (ePrint 2023/932) support the high-level background, but not every property of this encoding.

The largest substantive uncertainty is the assumed 3.5 ns sequential SHA step. It is a modeled design point, not a measured or fabricated lower bound. The paper says this clearly. Therefore "30 seconds" should be understood as a parameterized hardware estimate, not an unconditional cryptographic delay.

## Validation performed

- Exact reviewed commit remains the current `main` tip.
- Core `cargo clippy`, complete `make test`, portable/hardware cross-checks, Python reference, vectors, and packaging: passed.
- Core dependency audit: clean.
- Solidity: 33/33 tests passed; formatting, compilation, size checks, adversarial protocol tests, and documented gas figures passed.
- PoC node: release build, clippy, and tests passed; dependency audit failed as described above.
- Four fuzz targets completed 1,000 local iterations each without sanitizers. A local Apple-ARM AddressSanitizer run did not terminate, so I do not count the repository's historical "108 million ASan inputs" as independently reproduced.
- The 26-page paper rebuilt successfully. Extracted text exactly matches the committed PDF. There are three minor 2.7–3.8 pt overfull table warnings but no visible clipping or broken references.
- The reviewed checkout remains clean; I made no source changes.

Overall: credible research, good specification discipline, and no discovered primitive-level break, but keep the "do not use for value" warning until findings 1–3 are fixed and the proof, hardware model, and contracts receive independent human specialist review.
