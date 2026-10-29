# Round 12: the proof-of-concept encrypted mempool

Audited commit `a90416a` on 2026-10-28 by Anthropic's Claude Opus 5.5, since GPT-6 Astra declined to audit the contracts; the changes it led to are in [README.md](README.md). **Fix first:** a builder that keeps an honest sender's pending reveal out of the next two blocks learns the key, makes the ticket miss and sandwiches it, which breaks the pool guard's main promise; three smaller defects in the demo token and the node follow.

## Findings, most severe first

### 1. major — Excluding a pending reveal for `revealWindow` blocks lets a builder trade ahead of the ticket with the key it read

**Locations:** poc/contracts/src/SealedInbox.sol:168 (reveal window), poc/contracts/src/SealedInbox.sol:189-192 (an unrevealed ticket is consumed as `Missed`), poc/contracts/src/SealedInbox.sol:82-84 and 203-206 (the lock drops once the slot is done), poc/contracts/src/SealedInbox.sol:218-228 (`forceOpen` queues the ticket in a later slot), poc/contracts/script/Deploy.s.sol:19 (`revealWindow = 2`), poc/node/src/main.rs:168-169 (the sender broadcasts the reveal to the public mempool).

**Failure scenario, reproduced:** The test is `testAuditCensoredRevealIsSandwiched` in the scratch test file. Alice submits a sealed swap of 10 A in block N, and the inbox is restricted to the pool as in the deploy script. In block N+1 her `reveal(id, key)` is pending in the public mempool. A builder copies `key` from the calldata and leaves the reveal out of blocks N+1 and N+2. In block N+3 the attacker calls `execute` with an empty envelope. Alice's ticket becomes `Missed`, the queue is empty and `locked()` returns false. The attacker then swaps 50 A directly on the pool and calls `forceOpen(id, key)`, which queues Alice's swap and pays the attacker the bounty. Three blocks later the keeper runs Alice's swap, and the attacker back-runs it.

The test's assertion that Alice gets the fair price fails:
- Alice receives 8.9847 B against a fair 9.9010 B, a loss of 9.25%.
- Alice also loses `deposit - bounty` (0.008 ETH burned).
- The attacker gains 0.9338 A plus the 0.002 ETH bounty.

The README's limitation "Late execution is unprotected" assumes that the sender withheld its key. Here the sender broadcast its reveal on time. Only two blocks of exclusion are needed. So the docstring's claim that "a key read from a pending reveal cannot buy a position ahead of its ticket" holds only against attackers that cannot delay inclusion. The brief names exactly that attacker: a builder controlling order across blocks.

**Fix:** Do not let a ticket whose key may already be public lose its position while the pool is open. Either of these works:
- **Never execute a missed ticket.** `forceOpen` only settles the bounty and the burn.
- **Keep the ticket in place.** Keep the head slot, and with it the pool lock, until the missed ticket is force-opened or a bounded deadline passes. Then run it in its original position, or drop it at the deadline.

In both cases, size `revealWindow` against the number of consecutive blocks one builder can plausibly control, and state the remaining censorship assumption in the README limits.

### 2. minor — Anyone can freeze the demo pool through the token's public `mint`

**Locations:** poc/contracts/src/demo/Token.sol:15-17 (`mint` has no access control), poc/contracts/src/demo/Token.sol:33 (`balanceOf[to] += amount` in `transferFrom`), poc/contracts/src/demo/Pool.sol:26-27 and 42 (the pool pulls the input token with `transferFrom`).

**Failure scenario, reproduced:** The test is `testAuditPublicMintFreezesPool`, and the lead from the earlier partial review is confirmed.
1. As a control, the pool trades normally.
2. Any address calls `a.mint(pool, type(uint256).max - a.balanceOf(pool))`, then does the same for `b`.
3. From then on every swap with `amountIn > 0` reverts with `Panic(0x11)` in both directions. The reason is that `transferFrom` adds to the pool's balance, which is already at the integer limit.
4. `addLiquidity` reverts the same way.
5. A sealed swap is consumed with `Executed(id, false, false)`.

The pool keeps reserves separately from token balances, and nothing can lower its balance, so the freeze is permanent. `restrictTo` does not help because the mint is a direct call. The same open `mint` also lets anyone mint unlimited input tokens and drain the pool's reserves. That second effect is established from the source and was not tested.

**Fix:** Give `Token` an owner that the constructor sets, and allow only the owner to call `mint`. Deploy.s.sol already mints only from the deployer, so the demo keeps working.

### 3. minor — The keeper's default batch can exceed the standard 128 KiB transaction size limit and then retries the same batch forever

**Locations:** poc/node/src/main.rs:225 (`--batch` defaults to 32), poc/node/src/main.rs:239-249 (the batch is built from `cursor` with full envelopes, including missed tickets), poc/node/src/main.rs:262 (an error retries the same batch), poc/contracts/script/Deploy.s.sol:19 (`maxEnvelope = 4096`).

**Failure scenario, established from the source:** The on-chain state and the calldata size are reproduced in `testAuditKeeperDefaultBatchExceedsTxSizeLimit`. One sender submits 32 tickets with 4,096-byte envelopes and `gasLimit = 0` in a single block. The inbox accepts all of them, because a zero gas limit adds nothing to the slot budget. The keeper's `execute` calldata for that slot is 133,188 bytes, which is above 131,072 (128 KiB).

The rest of the scenario is established from the source plus client policy, and was not reproduced. geth and reth reject transactions above 128 KiB at the RPC/txpool. On such a node the keeper logs the error, rebuilds the identical batch from the unchanged cursor, and never makes progress. While that lasts, the queue holds the pool locked. The attacker pays gas only, because revealing the tickets refunds the deposits. anvil, which the demo uses, was not available to test, and I did not verify whether it enforces the same limit.

**Fix:** Bound each batch by encoded calldata size as well as count, for example by adding envelopes while the total stays under about 120 KiB. Pass empty bytes for tickets that are still `Sealed`, since `execute` accepts any bytes for them. Halve the batch after a submission error instead of retrying it unchanged.

### 4. minor — `sealnet send` reports a reveal as done without checking the receipt status

**Locations:** poc/node/src/main.rs:168-170.

**Failure scenario, established from the source:** `send` waits for block `slot + 1`, sends `reveal`, and logs "revealed the key of #id in block X" from the receipt without checking `r.status()`. The gas estimate can succeed inside the window, at block `slot + 2`, while the transaction is mined at `slot + 3`. In that case the reveal reverts with `OutsideWindow`, the key is permanently public in the failed transaction's calldata, and the ticket will be marked `Missed`. That is the state of finding 1, reached without any censorship. The command still prints success and exits 0. The keeper and the solver both check `status()`; the sender does not.

**Fix:** Check `r.status()` and fail loudly when the reveal did not land. Before sending, refuse to reveal when the current block already makes inclusion by `slot + revealWindow` unlikely.

## What was checked

All commands ran on macpro in the scratch copy /tmp/leanseal-audit.RtnjXv/repo (the whole tree at `a90416a` without `.git`), with `CARGO_TARGET_DIR=/tmp/leanseal-audit.RtnjXv/target`. The worktree was not modified.

**Commands and results:**
- `forge build --offline` (solc 0.8.28) succeeded.
- `forge test --offline`: 33 passed, 0 failed (26 in SealedInbox.t.sol, 7 in LeanSeal.t.sol).
- `cargo build --release --locked --offline` succeeded.
- `cargo clippy --release --locked --offline -- -D warnings` succeeded with no warnings.
- `cargo test --release --locked --offline`: 1 passed.
- `forge test --gas-report` for `testRevealAndExecuteInOrder|testWithheldKeyIsForcedOpen` matches the README table: `submit` 192,116 to 267,989; `reveal` 74,487 to 74,499; `execute` at most 356,272; `forceOpen` 126,600.
- The audit tests are in /tmp/leanseal-audit.RtnjXv/repo/poc/contracts/test/Audit.t.sol on macpro. They ran with `forge test --offline --match-contract AuditTest --match-test testAudit`. Three fail as intended (findings 1, 2 and 3) and two pass (the gas reserve probes described below).
- `demo.sh` was not run, because anvil is not installed on macpro.

**Checked and found correct:**
- **LeanSeal.sol against SPEC.md sections 6 and 7:**
  - Envelope magic, version and reserved bytes are checked as one 8-byte constant.
  - The puzzle header offsets are right: `b` at 5, reserved bytes 6 and 7, `n` at 8, `m` at 12, `ctx` = bytes [4:36), commitment at 36.
  - The bounds 1 ≤ b ≤ 32, 1 ≤ n ≤ 2^20, 1 ≤ m ≤ 2^48, n·m ≤ 2^60 and L ≤ 2^24 are enforced, as are the exact total length and the label lengths (18 and 15).
  - HMAC padding is correct for a 32-byte key, keystream block j is `HMAC(k_enc, be64(j))`, and the tag covers everything before it and is checked before decryption.
  - The XOR spill past `len` stays inside the rounded allocation.
  - All 7 vectors open correctly and every invalid vector is rejected.
- **Gas accounting:** I wrote a probe that finds the least gas `execute` needs for one ticket, using a 348-byte envelope with `gasLimit` 200,000 and a 4,028-byte envelope with `gasLimit` 1,000,000. At that minimum the account call receives exactly the same gas as with ample gas. One gas less, the transaction reverts with `InsufficientGas`, not out-of-gas. So `_enoughGas` covers EIP-150, the cold delegate access, decryption and the bookkeeping after the call. With the deployed parameters the worst single ticket needs about 3.3M gas, well under the keeper's 16M and EIP-7825's 2^24.
- **Queue state machine:**
  - Slots are pushed in increasing block order.
  - `forceOpen` always appends to the current block's slot, which cannot be done yet, because execution needs `block.number > slot + revealWindow`.
  - Ticket ids enter a slot list only as `Sealed`, `Revealed` or `Forced`.
  - A repeated `forceOpen` reverts with `WrongState`.
  - Reveal and execute windows do not overlap.
  - A wrong envelope reverts the whole call instead of consuming a ticket.
  - A failing, expiring, undecryptable or re-delegated ticket is consumed with `ok: false` and does not block later tickets.
- **Reentrancy:**
  - `execute` is serialized by `busy`.
  - `reveal` and `forceOpen` update state before `_pay`.
  - The transient `executing` flag is cleared after every account call, and it rolls back if the frame reverts.
  - With `restrictTo([pool])` the only code that runs under the flag is the pool and the tokens, and neither calls back.
- **Delegation:** `submit` and `_run` both compare the sender's code hash with `keccak256(0xef0100 ‖ account)`. A contract cannot match that hash (EIP-3541), and `SealedAccount.run` accepts calls only from the inbox.
- **README against the code:** the protocol steps, the daemon flags and defaults, the EIP-7825 check, the solver's state code 4 (`Missed`), and the 7702 authorization nonce `nonce + 1` in `delegate` all match what the code does.

VERDICT: fix-first
