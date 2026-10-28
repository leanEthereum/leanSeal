# sealnet: an encrypted mempool on leanSeal

This research prototype orders encrypted calls through an on-chain queue. Senders publish leanSeal envelopes, reveal their keys after inclusion, and execute in committed slot order through EIP-7702 accounts. A guarded demo pool reserves access for those calls after a reveal, preventing the demonstrated post-reveal sandwich. Withheld transactions can be opened later for a bounty, outside their original position.

The prototype requires an EVM with EIP-7702 and Cancun transient storage (the demo uses Prague). It is not ready for real funds.

## Run the demo

Install Foundry (`anvil`, `forge`, and `cast`), Rust, and Python 3. From the repository root:

```bash
git submodule update --init poc/contracts/lib/forge-std
PORT=18571 bash poc/demo.sh
```

The script builds the contracts and Rust binary, starts a local chain with two-second blocks, deploys a guarded pool, and starts the keeper, solver, and searcher. Its exit trap kills and waits for all four processes.

Representative output (transaction hashes, block numbers, and timings vary):

```text
== 1. plaintext swap in the public mempool
[searcher] plaintext swap ...: 10.000 in, front-running it
[searcher] sandwich landed
   alice got 8.9847 B for 10 A; fair price 9.9010 B; lost 9.25%
== 2. the same swap sealed with leanSeal
[  sender] sealed tx #0 ordered in block 24: 576 bytes (256 of plaintext)
[searcher] revealed swap #0: 10.000 in, front-running it
[searcher] front-run of revealed #0 reverted: pool locked until the batch executes
[  keeper] slot 24: executed #0 in order (ok: true)
   alice got 9.7247 B for 10 A; fair price 9.7247 B; lost 0.00%
== 3. a sealed swap whose sender withholds the key
[  keeper] slot 33: #1 missed its reveal, penalty burned
[  solver] solving #1: 8x67108864 sequential steps
[  solver] forced #1 open in block ...; executed late: true
```

The demo uses eight chains with `2^26` steps each and 24-byte links. Its delay is hardware-dependent; this is an illustrative workload, not a production security parameter.

## Components

| Path | Role |
|---|---|
| `contracts/src/LeanSeal.sol` | Structural validation, key commitments, authenticated envelope opening using SHA-256. |
| `contracts/src/SealedInbox.sol` | Deposits, global queue, reveal accounting, gas caps, execution and late opening. |
| `contracts/src/SealedAccount.sol` | EIP-7702 delegate that calls targets with the sender's address and approvals. |
| `contracts/src/demo/` | Tokens and a constant-product pool with an optional inbox guard. |
| `node/` | Rust `sealnet` sender, keeper, solver, delegate setup, and sandwich searcher. |
| `contracts/test/` | Cryptographic vectors and adversarial protocol regressions. |

## Protocol

1. **Submit.** Encrypt `abi.encode(address target, bytes data, uint64 expiry)` and call `submit(envelope, gasLimit)` with the exact deposit. The inbox validates all envelope and puzzle structure rules from [SPEC.md](../SPEC.md): magic, version, reserved bytes, `1 <= b <= 32`, `1 <= n <= 2^20`, `1 <= m <= 2^48`, `n*m <= 2^60`, `L <= 2^24`, and exact total length. It does not verify puzzle solvability. The whole envelope is bound by its hash.
2. **Cap and order.** Each non-empty block becomes one slot in an append-only queue. Tickets retain submission order within that slot. The deployment accepts at most 4,096 envelope bytes and 1,000,000 requested account gas per ticket, and at most 10,000,000 summed account gas per slot. A ticket exceeding the latter reverts with `SlotFull`.
3. **Reveal.** Anyone knowing the key may reveal in the next two blocks. The sender receives its 0.01 ETH deposit back. Each reveal increments `pendingReveals`. While this count is nonzero, direct `swap` and `addLiquidity` calls on the guarded pool revert with `"locked"`.
4. **Execute.** After the head slot's window, call `execute(bytes[] envelopes)`. Entries correspond to tickets starting at `cursor`; an unrevealed ticket can use empty bytes. Only the head slot can run. Revealed tickets decrement `pendingReveals` and execute in order. Unrevealed tickets become `Missed`, and `deposit - bounty` is added to `burned`. Completing a slot advances `head` and resets `cursor`. The call returns the processed count and emits `Progress(head, cursor)`.
5. **Preserve progress.** Before consuming a ticket, the inbox reserves account gas with the EIP-150 adjustment, decryption work proportional to envelope size, and bookkeeping gas. An underfunded executor stops before that ticket; earlier progress remains. If no ticket was processed, `InsufficientGas` reverts. Callers can also supply shorter prefixes. `gasLimit` means gas delivered to the account call, including the delegate wrapper, not gas delivered to the final target.
6. **Isolate calls.** Expiry, malformed plaintext, authentication failure, and target failure consume a properly funded ticket without blocking later tickets. Account calls copy no return data. `ok` records low-level call success; an undelegated EOA can return success without doing anything. Revoked delegation cannot block a batch. Execution is serialized against reentrancy, with ticket state updated before external calls.
7. **Force open.** Anyone with a missed ticket's matching key may call `forceOpen(id, key, envelope)`. It executes late unless expired or otherwise failing, and pays only the 0.002 ETH bounty. The remaining 0.008 ETH stays locked forever, counted in `burned`; no withdrawal exists. Since a withholding sender can claim its own bounty, the **net penalty is deposit − bounty**. Insufficient execution gas reverts and leaves the ticket `Missed`. So does a call while `pendingReveals > 0` (`Locked`): otherwise a withheld ticket could be opened during a lock and trade ahead of a revealed one. The solver waits for the lock to clear before claiming.
8. **Restrict targets.** The deployer may call `restrictTo(targets)` once; afterwards a sealed call to any other target fails (`ok: false`). The demo allows only the pool.

During each account call the inbox sets a transient `executing()` flag. The guard is `locked() = pendingReveals > 0 && !executing()`, so sealed calls and their nested calls can access the pool while ordinary external trades wait. Passing a zero guard address deploys an unguarded pool.

This reserves an execution position relative to every transaction that touches this guarded pool, at the application level. It is not enough on its own. All keys of a batch are public before the batch runs, so a sealed call ordered ahead of a victim could adapt to the victim's plaintext if it read state that someone wrote after the reveals, for example a contract that the attacker updates with the victim's trade. The target allowlist closes this for the demo market: a sealed swap on the pool has fixed parameters, chosen before any reveal. It serves the ordering purpose of LUCID's protocol-level execution of decrypted transactions at the top of the next block; this PoC does not implement LUCID or protect arbitrary unguarded applications.

## Daemons and recovery

All roles take `--rpc` and `--key`; inbox roles also take `--inbox`.

- `keeper` reads `head`, `cursor`, `queueLength`, and `slotAt` from the contract on startup and after each transaction. It fetches the head slot's `Sealed` logs, takes up to 32 envelopes starting at the cursor, and executes with an explicit 25-million gas limit. It drains mature slots and retries after RPC or transaction errors. Restarting requires no backfill flag. `slotLength` and `slotTicket` also expose the queue contents.
- `solver` scans `Missed` logs from `--from` (default 0), reconciles current ticket state, and solves sequentially. It skips puzzles exceeding `--max-steps` (default `2^34` total chain steps). Per-ticket errors are logged without stopping other work. It rechecks state before solving and claiming; losing a claim race is logged. Restart from the default or an earlier `--from` to retry failed historical tickets.
- `sandwich` takes `--pool` and `--size` (default 50 whole tokens). It attacks pending plaintext swaps and decrypts `Revealed` events to attempt a direct front-run. The revealed attack uses fixed transaction gas so a pool-lock revert is mined and visible.
- `send` takes `--to` and `--data`. It reads the deposit from the inbox. `--plain` submits directly; `--withhold` omits the reveal. Defaults are `--chains 8 --steps 2^26 --gas 300000 --expiry 100`. Numeric overflow and out-of-format puzzle parameters are rejected instead of wrapped. Expiry is a block offset.

## Checks and gas

From the repository root:

```bash
(cd poc/contracts && forge test)
(cd poc/node && cargo build --release && cargo clippy --release -- -D warnings && cargo test --release)
(cd poc/contracts && forge test --gas-report --match-test 'testRevealAndExecuteInOrder|testWithheldKeyIsForcedOpen')
```

Measured with Solidity 0.8.28, the last command reports these **unit-test call costs**, not transaction estimates or the cost of building/solving puzzles. Protocol tests use vector case 4: `n = 5`, `m = 100`, `b = 12`, with 256-byte swap plaintexts.

| Call | Gas |
|---|---:|
| Successful `submit` | 191,988–267,849 |
| Successful `reveal` | 79,707–96,819 |
| `execute`, two revealed swaps | 355,494 |
| `forceOpen`, one late swap | 211,436 |

Storage warmth, queue position, calldata, target behavior, and envelope size change costs. The conservative gas reserve means callers must supply more gas than the call ultimately consumes.

## Limits

- **Guard availability.** Any pending reveal locks the pool for plaintext traders until execution drains all pending reveals. Unpaid keepers and a backlog can prolong this lock.
- **Late execution is unprotected.** The key is public in the `forceOpen` transaction, so a searcher can front-run it. The transient flag permits late execution but does not reserve its original position. Senders should set `minOut` and an expiry; the demonstration deliberately uses `minOut = 0`.
- **Penalty size.** The net withholding penalty is deposit − bounty, not the whole deposit. Successful reveal refunds do not depend on successful target execution.
- **Structure is not solvability.** A sender knowing a matching key can reveal a puzzle whose links do not solve to it, recover the deposit, and avoid a penalty. A missed inconsistent puzzle can waste solver work before its commitment fails. The solver bounds total steps but remains sequential and has no persistent checkpoints.
- **Reorgs.** Queue order follows the canonical chain. A reveal on a replaced branch can expose plaintext before reordered inclusion. Daemon cursors are not reorg-aware; restart/backfill and state reconciliation do not provide finality.
- **Public metadata.** Sender, gas limit, deposit, envelope length, and timing remain visible. The demo searcher does not solve puzzles before reveal; real confidentiality depends on delay relative to ordering and on attacker hardware.
- **Last revealer.** A sender can inspect others' reveals before choosing to withhold.
- **No execution fees.** Keepers pay execution gas. Ticket and slot gas caps bound account allowances, not total decryption overhead or the number of low-gas tickets; processing can span calls.
- **Reward-copying race.** Anyone seeing `forceOpen` in the mempool can copy its key and compete for the bounty.
- **Application scope.** Only guarded pool operations receive position protection, and only for sealed calls restricted to non-adaptive targets. General programmable sealed transactions need execution immediately after key release, with no ordinary transaction in between, which only a protocol such as LUCID provides. A sealed swap ordered ahead of a victim can still front-run it blindly; that is probabilistic front-running, priced by deposits and fees.
- **Fresh puzzles.** The sender builds a fresh puzzle per transaction. Delay starts when a puzzle becomes public; reusing a published puzzle does not restart its delay.
