# Review guide

This guide is for a human reviewer of the leanSeal v1 format and its Rust implementation. It lists the places where an error would break security, puts them in order of leverage, and says what to check at each one. The line references are to the tree after the review fixes listed at the end.

The core is small: about 220 lines of specification ([SPEC.md](../SPEC.md) Sections 1–7) and about 870 lines of Rust (`src/hash.rs`, `src/puzzle.rs`, `src/envelope.rs`, `src/backend/mod.rs`). The rest of the crate is the command-line tool, benchmarks and tests.

## Where the tests cannot help

The tests are extensive, but they share one blind spot. The Rust implementation and the Python reference ([ref/leanseal_ref.py](../ref/leanseal_ref.py)) were both written by AI from the same specification. The test vectors and cross-tests therefore catch any place where the two implementations disagree, but not a mistake that both inherit from the specification. They also cannot see properties that leave the outputs unchanged, such as where randomness comes from or whether a comparison runs in constant time.

| What the tests establish | How | What they cannot establish |
|---|---|---|
| SHA-256 and HMAC are correct | NIST and RFC 4231 vectors ([tests/library.rs:20](../tests/library.rs#L20), [:59](../tests/library.rs#L59)); Python uses `hashlib` | — |
| Every backend matches portable SHA-256 | Random comparison on 1–4 lanes ([tests/library.rs:79](../tests/library.rs#L79)); `selftest` in CI asserts which backend ran | — |
| Rust implements the specification as Python reads it | Python recomputes every field of every vector ([ref/leanseal_ref.py:366](../ref/leanseal_ref.py#L366)); each side opens the other's envelopes ([tests/cross.sh](../tests/cross.sh)) | That the specification is right |
| Decoders reject malformed input | Mutation tests ([tests/decode_props.rs:165](../tests/decode_props.rs#L165)) and four cargo-fuzz targets | — |
| Round trips work | Grids of `n`, `m`, `b`; checkpoint stop and resume | Randomness quality, constant time, file permissions, the order of checks |

A review therefore gets the most from the specification first, then the proof, and then the properties that tests cannot see. Code that the cross-tests pin down needs only a single careful read.

## Review order

### 1. The format (highest leverage)

Read [SPEC.md](../SPEC.md) Sections 1–7 and ask whether this is the right construction, independently of the code.

- **Labelled hashes** (Section 1): `TH(label, x) = SHA256(u8(len) ‖ label ‖ x)`. The length prefix makes labels prefix-free. Check that every label is distinct: `start`, `mask`, `acc`, `key`, `commit`, `enc`, `mac`, `puzzle-id`, all under `leanseal/v1/`.
- **The chain step** (Section 3): `F_i(s) = SHA256(s ‖ salt ‖ be32(i))`, exactly 52 bytes and one compression. Check the padded block: W8–W11 are the salt, W12 is `i`, W13 is `0x80000000`, W14 is 0 and W15 is `0x1A0`. Check that the salt and `i` make the step function distinct across puzzles and across chains.
- **Domain separation by length** ([SPEC.md:63](../SPEC.md)): no other hash input in the format is 52 bytes long, so a chain-step query never answers another oracle. See issue 1 below for a wrong number in this paragraph.
- **Generation** (Section 4): start values `TH(start, ctx ‖ be32(i) ‖ x_i)`; masks `TH(mask, ctx ‖ y_i)[0:b] ⊕ x_{i+1}`; accumulator `a_0 = ctx`, `a_i = TH(acc, a_{i−1} ‖ y_i)`; `K = TH(key, ctx ‖ a_n)`; `C = TH(commit, ctx ‖ K)`. Ask whether binding `ctx` into every hash is enough to stop values from one puzzle being reused in another, and whether the accumulator should bind anything else.
- **Encryption** (Section 7): `k_enc = TH(enc, K ‖ nonce)` and `k_mac = TH(mac, K ‖ nonce)`; keystream block `j` is `HMAC(k_enc, be64(j))`; the tag is `HMAC(k_mac, ·)` over every envelope byte before it. This is a hand-built encrypt-then-MAC. Decide whether it is acceptable or should be replaced with a standard AEAD built from SHA-256.
- **Encodings** (Section 6): magic, version, reserved bytes, exact lengths. These are pinned by the decoders and their tests; a quick read is enough.

### 2. The proof against the format

The delay theorem ([SPEC.md](../SPEC.md) Section 8; paper Section 4 and Appendix A, [paper/sections/appendix-proof.tex](../paper/sections/appendix-proof.tex)) is written out but not checked by anyone.

- Check that the oracles the proof models are exactly the hashes of Sections 3–5, including the length-separation argument for the 52-byte step.
- Check the round count `T_key = n·(m + 2) + 1` and the path-value count `P = n·(m + 3) + 1` against the solver of Section 5.
- Check the three claims in Appendix A (`claim:sequential`, `claim:hybrid`, `claim:bad`) and the final bound `Q_on / 2^(8b) + Q_pre / 2^(128+8b) + (Q·P + P² + 1) / 2^256`.
- Check the arithmetic behind the headline figures (2^−117 for 30 s with `b = 24`); the figures for each link width are in [docs/security.md](security.md#link-width).

### 3. Generation and solving: [src/puzzle.rs](../src/puzzle.rs)

The cross-tests pin these functions, so read them once for structure rather than line by line.

| Lines | Function | What to check |
|---|---|---|
| [314–325](../src/puzzle.rs#L314-L325) | `generate` | The salt and links come from `getrandom` (the OS generator), and the links are wiped on drop. **The tests cannot see this.** `TestRng` is used only in `vectors.rs` and `selftest`, and `generate_from`, which takes caller-chosen inputs, is hidden from the documentation. |
| [366–430](../src/puzzle.rs#L366-L430) | `generate_from`, worker threads | Chains are taken from an atomic counter, each chain's end is stored by index, and every index is filled even if some threads fail to spawn. Chains run in 2^22-step blocks ([387](../src/puzzle.rs#L387)). |
| [431–444](../src/puzzle.rs#L431-L444) | masks, accumulator, key | The mask from end `i` (0-based) hides link `i + 1`; link 0 is published in clear; the accumulator absorbs ends in order. |
| [195–204](../src/puzzle.rs#L195-L204) | `solve`, unmasking | The offset `cur.i · b` reads the link that generation hid with this chain's end, and the next start uses chain index `cur.i + 1`. |
| [206–213](../src/puzzle.rs#L206-L213), [105–110](../src/puzzle.rs#L105-L110) | final key and `check_key` | The solved key is checked against `C` in constant time before it is returned. |
| [245–292](../src/puzzle.rs#L245-L292) | checkpoints | The puzzle id binds every puzzle byte ([98–103](../src/puzzle.rs#L98-L103)). The cursor state is not authenticated; a damaged one makes the key check fail, and the tool then names the checkpoint, not the puzzle (issue 4). |

### 4. Envelopes and secrets: [src/envelope.rs](../src/envelope.rs)

| Lines | Function | What to check |
|---|---|---|
| [109–122](../src/envelope.rs#L109-L122) | `Envelope::open` | Order of checks: the key commitment, then the tag in constant time over all bytes before it, and only then decryption. No plaintext exists before the tag passes. **Tests check the outcome, not the order.** |
| [45–66](../src/envelope.rs#L45-L66) | `seal` | The nonce is supplied by the caller. Subkeys are wiped on drop. The tag covers the magic, the whole puzzle, the nonce, the length and the ciphertext. |
| [29–38](../src/envelope.rs#L29-L38) | `stream` | The counter starts at 0 and increases by one per 32-byte block; the final partial block is truncated. |
| [80–103](../src/envelope.rs#L80-L103) | `Envelope::decode` | The puzzle length is taken from its header and checked before any allocation; the total length must match exactly. |
| [18–28](../src/envelope.rs#L18-L28) | `secret_decode` | The key is checked against the puzzle's commitment on load. |

### 5. Secrets on disk and in memory

These are invisible to every test that compares outputs.

| Location | What to check |
|---|---|
| [src/main.rs:607–609](../src/main.rs#L607-L609) | Each `encrypt` draws a fresh nonce from `getrandom`, so a secret reused for `q` envelopes repeats a 16-byte nonce with probability at most about `q² / 2^129`. |
| [src/runtime.rs:82–114](../src/runtime.rs#L82-L114) | Files are written to a new temporary file (`create_new`, so no symlink is followed), synced and renamed. Secret files get mode 0600. |
| [src/main.rs:896–899](../src/main.rs#L896-L899) | `open` writes the message only after `Envelope::open` succeeds. |
| [src/secret.rs:4–7](../src/secret.rs#L4-L7) | Wiping is `fill(0)` followed by `black_box`: best effort, not guaranteed against compiler copies. |

### 6. The accelerated backends: [src/backend/](../src/backend/)

These files are the only `unsafe` code. The random agreement test and the CI `selftest` cover their output on every architecture that CI runs, so the review is of memory safety rather than arithmetic.

- [backend/mod.rs:37–52](../src/backend/mod.rs#L37-L52): a hardware backend is constructed only after run-time feature detection, which is what makes the `#[target_feature]` calls sound.
- [backend/arm.rs:6–15](../src/backend/arm.rs#L6-L15) and the matching function in `x86.rs`: the lane count is 1 or 2, and the slices have equal lengths ([mod.rs:92–119](../src/backend/mod.rs#L92-L119)).
- The constant words: [arm.rs:34](../src/backend/arm.rs#L34), [x86.rs:31](../src/backend/x86.rs#L31) and the portable loop at [mod.rs:99–112](../src/backend/mod.rs#L99-L112) all build `[i, 0x80000000, 0, 416]`.

### 7. Lower priority

- **SHA-256 and HMAC** ([src/hash.rs](../src/hash.rs)): covered by standard vectors and by Python's `hashlib`. A read of the padding in `finish` ([90–102](../src/hash.rs#L90-L102)) and of HMAC key handling ([111–133](../src/hash.rs#L111-L133)) is enough.
- **Decoders**: fuzzed and mutation-tested.
- **The command-line tool** (`src/main.rs`, 1,225 lines): argument parsing and reporting. Only the paths in item 5 matter for security.
- **`poc/`**: the mempool prototype, a separate review.

## Issues found while preparing this guide

All six are fixed. None of them affected the delay or the confidentiality of a correctly used envelope.

| Issue | Fix |
|---|---|
| [SPEC.md:63](../SPEC.md) gave the shortest labelled-hash input as 56 bytes; the start hash with `b = 1` is 55 (1 + 17 + 32 + 4 + 1). The argument holds either way, since 55 > 52. | Corrected to 55, with the sum. |
| No test vector or cross-test used the default link width, 24. | A vector with `n = 16`, `b = 24` ([src/vectors.rs](../src/vectors.rs)); [tests/cross.sh](../tests/cross.sh) now covers `b` in {1, 12, 24, 32}. Adding it exposed a hard-coded case count in the vector generator, also fixed. |
| No test built a puzzle in more than one 2^22-step block and then solved it. | `generation_in_several_blocks_matches_solving` in [tests/library.rs](../tests/library.rs), with `m = 2^22 + 3`. |
| A solve resumed from a damaged checkpoint reported the puzzle as malformed, which accuses an honest sender. | The tool now says that the checkpoint may be damaged and how to solve from the start ([src/main.rs](../src/main.rs), `run_jobs`); [tests/cli.sh](../tests/cli.sh) damages a checkpoint and checks the message. |
| `open -k KEY` put the key in the argument list, where other local users can read it. | `-k -` reads the key from standard input. The help text, the README and the usage guide say to pass an unpublished key in a file or on standard input. |
| `generate_from` is public and takes caller-chosen salt and links. | Hidden from the documentation, with a warning that the inputs must be uniformly random and secret. `seal` keeps its caller-supplied nonce, which its documentation already covers. |

## Before changing the status line

The README says that no human cryptographer has reviewed the code or the format. When sections 1–5 above have been reviewed, and the issues have been fixed or accepted, that line can name the reviewer and the commit reviewed. Section 6 and the proof can be listed separately if they were reviewed to a different depth.
