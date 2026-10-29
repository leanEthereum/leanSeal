# sealnet: an encrypted mempool on leanSeal

This research prototype orders encrypted calls through an on-chain queue. Senders publish leanSeal envelopes, reveal their keys after inclusion, and execute in committed slot order through EIP-7702 accounts delegated to the inbox's own `SealedAccount`. A guarded demo pool refuses direct trades while any sealed call is queued, so a key read from a pending reveal cannot buy a position ahead of its call. A withheld transaction's key can be published later for a bounty, but the transaction never runs: a builder that kept a pending reveal out of its window already knows that key.

The prototype requires an EVM with EIP-7702 and Cancun transient storage (the demo uses Prague). It is not ready for real funds.

## Run the demo

Install Foundry (`anvil`, `forge`, and `cast`), Rust, and Python 3. From the repository root:

```bash
git submodule update --init poc/contracts/lib/forge-std
PORT=18571 bash poc/demo.sh
```

The script builds the contracts and Rust binary, starts a local chain with two-second blocks, deploys a guarded pool, and starts the keeper, solver, and searcher. Each role reads its anvil key from a file in a private temporary directory. The last section waits up to `FORCE_WAIT` seconds (default 300) for the solver to publish the withheld key. Its exit trap kills and waits for all four processes and removes the key files.

Representative output (transaction hashes, block numbers, and timings vary):

```text
== 1. plaintext swap in the public mempool
[searcher] plaintext swap ...: 10.000 in, front-running it
[searcher] sandwich landed
   alice got 8.9847 B for 10 A; fair price 9.9010 B; lost 9.25%
== 2. the same swap sealed with leanSeal
[  sender] sealed tx #0 ordered in block 23: 576 bytes (256 of plaintext)
[searcher] pending reveal of #0: decrypted a swap of 10.000 in, front-running it
[searcher] front-run of #0 reverted in block 25, ahead of the reveal: pool locked while #0 is queued
[  sender] revealed the key of #0 in block 25
[  keeper] slot 23: executed #0 in order (ok: true)
   alice got 9.7247 B for 10 A; fair price 9.7247 B; lost 0.00%
== 3. a sealed swap whose sender withholds the key
[  sender] withholding the key of #1
[  keeper] slot 31: #1 missed its reveal, penalty burned; it will not run
[  solver] solving #1: 8x67108864 sequential steps
[  solver] found the key of #1 in 13.7s
[  solver] published the key of #1 in block 42; the bounty is paid, the bond is owed back to the sender, and the call stays cancelled
   key published; alice got 0.0000 B: the swap did not run, and she lost 0.008 ETH of her deposit
[  sender] withdrew 0.010 ETH of bonds
```

The demo uses eight chains with `2^26` steps each and 24-byte links. Its delay is hardware-dependent; this is an illustrative workload, not a production security parameter.

## Components

| Path | Role |
|---|---|
| `contracts/src/LeanSeal.sol` | Structural validation, key commitments, authenticated envelope opening using SHA-256. |
| `contracts/src/SealedInbox.sol` | Deposits, bonds, work limits, delegation checks, global queue and pool lock, gas caps, execution and forced opening. |
| `contracts/src/SealedAccount.sol` | EIP-7702 delegate, deployed by the inbox, that calls targets with the sender's address and approvals. |
| `contracts/src/demo/` | Tokens that only their deployer can mint, and a constant-product pool with an optional inbox guard. |
| `node/` | Rust `sealnet` sender, keeper, solver, delegate setup, and sandwich searcher. |
| `contracts/test/` | Cryptographic vectors and adversarial protocol regressions. |

## Protocol

1. **Submit.** The inbox takes submissions once its targets are fixed (step 9). Encrypt `abi.encode(address target, bytes data, uint64 expiry)` and call `submit(envelope, gasLimit)` with exactly the deposit plus the bond. The sender's code must be the EIP-7702 delegation designator `0xef0100 || account()`, where `account()` is the `SealedAccount` that the inbox deploys in its constructor; any other sender, including a contract or an account delegated elsewhere, reverts with `NotDelegated`. The inbox validates all envelope and puzzle structure rules from [SPEC.md](../SPEC.md): magic, version, reserved bytes, `1 <= b <= 32`, `1 <= n <= 2^20`, `1 <= m <= 2^48`, `n*m <= 2^60`, `L <= 2^24`, and exact total length. It then applies the deployment's fixed work limits, `minWork <= n*m <= maxWork`, `n <= maxChains` and `b >= minLinkBytes`, and reverts with `OutOfLimits` otherwise; the demo deployment admits `2^28 <= n*m <= 2^30`, `n <= 16` and `b >= 24`. A sender may have at most `maxOpen` puzzles (4 in the demo) whose keys are not yet public, or `submit` reverts with `TooManyOpen`. The inbox does not verify puzzle solvability. The whole envelope is bound by its hash.
2. **Cap and order.** Each non-empty block becomes one slot in an append-only queue. Tickets retain submission order within that slot. The deployment accepts at most 4,096 envelope bytes and 1,000,000 requested account gas per ticket, and at most 10,000,000 summed account gas per slot. A ticket exceeding the latter reverts with `SlotFull`.
3. **Reveal.** Anyone knowing the key may reveal in the next two blocks. The sender receives its 0.01 ETH deposit back; its 0.005 ETH bond stays until the ticket executes. A reveal mined later reverts, though its key is then public, so `send` reveals only while the reveal can still land in the window and fails if it did not.
4. **Execute.** After the head slot's window, call `execute(bytes[] envelopes)`. Entries correspond to tickets starting at `cursor`; an unrevealed ticket can use empty bytes. Only the head slot can run. Revealed tickets execute in queue order. Before each runs, the inbox checks the envelope's tag under the revealed key: if it verifies, the bond is credited to the sender; if it fails, the ticket becomes `Malformed`, does not run, and the bond is added to `burned`. Unrevealed tickets become `Missed` and never run, and `deposit - bounty` is added to `burned`. Completing a slot advances `head` and resets `cursor`. The call returns the processed count and emits `Progress(head, cursor)`.
5. **Preserve progress.** Before consuming a ticket, the inbox reserves account gas with the EIP-150 adjustment, decryption work proportional to envelope size, and bookkeeping gas. An underfunded executor stops before that ticket; earlier progress remains. If no ticket was processed, `InsufficientGas` reverts. Callers can also supply shorter prefixes. `gasLimit` means gas delivered to the account call, including the delegate wrapper, not gas delivered to the final target.
6. **Isolate calls.** Expiry, a plaintext that does not decode, a failing tag, and target failure consume a properly funded ticket without blocking later tickets. Account calls copy no return data. `ok` records low-level call success. Before each account call the inbox checks the sender's delegation again; a sender that revoked or changed it gets `ok: false`, and the batch continues. Execution is serialized against reentrancy, with ticket state updated before external calls.
7. **Force open.** Anyone with a missed ticket's matching key may call `forceOpen(id, key, envelope)`. The inbox checks the key against the commitment and the envelope against its hash, records the key and pays the 0.002 ETH bounty. If the tag verifies, the ticket becomes `Forced` and the bond is credited to the sender; if it fails, the ticket becomes `Malformed` and the bond is added to `burned`. The bounty is paid either way, since a failing tag is a result the solver could not have avoided. The ticket does not run. Its key may have been public before its position could be fixed again: a builder that reads a pending reveal and keeps it out of the window makes the ticket miss while holding its key, and could trade around it if it ran later. The remaining 0.008 ETH stays locked forever, counted in `burned`; no withdrawal exists. Since a withholding sender can claim its own bounty, the **net penalty is deposit − bounty**, plus the bond when the tag fails. A missed ticket whose chains do not lead to the committed key has no matching key to post, so its bond stays locked with its deposit: proving such malformation needs the verification game of the paper's Appendix D, which this PoC does not implement.
8. **Withdraw.** Credited bonds are paid by `withdraw()`, so that `execute` and `forceOpen` never send ether to a sender, which could refuse it.
9. **Restrict targets.** The deployer calls `restrictTo(targets)` once, and `submit` reverts with `NotRestricted` until then; a sealed call to any other target fails (`ok: false`). The demo allows only the pool.

During each account call the inbox sets a transient `executing()` flag. The guard is `locked() = head < queueLength() && !executing()`: from the moment a ticket is submitted until `execute` processes its slot and every earlier one, direct `swap` and `addLiquidity` calls on the guarded pool revert with `"locked"`, while sealed calls and their nested calls access the pool. A pending reveal therefore exposes a key only while its ticket's position is already reserved. A withheld ticket stops locking once `execute` marks it `Missed`, and it never runs afterwards. Direct trades and `addLiquidity` succeed only when no ticket is queued. During sealed traffic, trades go through the sealed path, where a new ticket lands in a later slot than every ticket whose key could already be known. Passing a zero guard address deploys an unguarded pool.

This reserves an execution position relative to every transaction that touches this guarded pool, at the application level. Because every sender runs the canonical `SealedAccount`, which calls exactly the committed target and data, the target allowlist constrains the code that runs under the `executing()` flag. It is not enough on its own. All keys of a batch are public before the batch runs, so a sealed call ordered ahead of a victim could adapt to the victim's plaintext if it read state that someone wrote after the reveals, for example a contract that the attacker updates with the victim's trade. The target allowlist closes this for the demo market: a sealed swap on the pool has fixed parameters, chosen before any reveal. It serves the ordering purpose of LUCID's protocol-level execution of decrypted transactions at the top of the next block; this PoC does not implement LUCID or protect arbitrary unguarded applications.

## Daemons and recovery

All roles take `--rpc` and `--key-file`, a file holding the account's hexadecimal key that only its owner can read; inbox roles also take `--inbox`. Keys never appear in argument lists or process listings.

- `delegate` takes `--to` and points the sender's account at that address with an EIP-7702 authorization. The demo passes the inbox's `account()`.
- `keeper` reads `head`, `cursor`, `queueLength`, and `slotAt` from the contract on startup and after each transaction. It reads up to `--batch` (default 32) ticket ids of the head slot from the cursor with `slotLength` and `slotTicket`, fetches the envelopes of revealed tickets from `Sealed` logs by ticket id, passes empty bytes for unrevealed ones, keeps the calldata under 120 KiB (nodes refuse transactions over 128 KiB), and executes with an explicit gas limit, `--gas` (default 16,000,000). Values above EIP-7825's transaction cap of 2^24 = 16,777,216 are rejected. When `execute` processes only a prefix, the keeper continues from the new cursor. It drains mature slots. After a refused or reverted transaction it retries with half as many tickets, down to one, and returns to `--batch` after a success. Restarting requires no backfill flag.
- `solver` scans `Missed` logs from `--from` (default 0), reconciles current ticket state, and solves sequentially. It skips puzzles exceeding `--max-steps` (default `2^34` total chain steps). Per-ticket errors are logged without stopping other work. It rechecks state before solving and claiming; losing a claim race is logged. A claim publishes the key and the envelope with `forceOpen`, which pays the bounty and settles the bond by the tag; the ticket does not run. Restart from the default or an earlier `--from` to retry failed historical tickets.
- `sandwich` takes `--pool` and `--size` (default 50 whole tokens). It attacks pending plaintext swaps. It also reads keys from pending `reveal` transactions, decrypts their envelopes, and bids a higher tip to trade ahead of the reveal; keys from mined `Revealed` events get the same attack. Each ticket is attacked once. Key attacks use fixed transaction gas so a pool-lock revert is mined and visible.
- `withdraw` collects the bonds credited to the account.
- `send` takes `--to` and `--data`. It reads the deposit and the bond from the inbox and checks that the account delegates to the inbox's `account()`. `--plain` submits directly; `--withhold` omits the reveal. Defaults are `--chains 8 --steps 2^26 --gas 300000 --expiry 100`. Numeric overflow, including an expiry offset past the last block number, and out-of-format puzzle parameters are rejected instead of wrapped. Expiry is a block offset.

## Checks and gas

From the repository root:

```bash
(cd poc/contracts && forge test)
(cd poc/node && cargo build --release && cargo clippy --release -- -D warnings && cargo test --release)
(cd poc/contracts && forge test --gas-report --match-test 'testRevealAndExecuteInOrder|testWithheldKeyIsForcedOpenButNotRun')
(cd poc/contracts && forge test --gas-report --match-test testBondCreditedAfterExecution)
```

Measured with Solidity 0.8.28, the last two commands report these **unit-test call costs**, not transaction estimates or the cost of building/solving puzzles. Protocol tests use vector case 4: `n = 5`, `m = 100`, `b = 12`, with 256-byte swap plaintexts.

| Call | Gas |
|---|---:|
| Successful `submit` | 218,924–294,797 |
| Successful `reveal` | 75,112–75,124 |
| `execute`, two revealed swaps | 423,973 |
| Successful `forceOpen` | 110,235 |
| `withdraw` | 33,037 |

Storage warmth, queue position, calldata, target behavior, and envelope size change costs. The conservative gas reserve means callers must supply more gas than the call ultimately consumes.

## Limits

- **Guard availability.** Any queued ticket locks the pool for direct traders and liquidity providers until the keeper executes its slot, at least `revealWindow + 1` blocks after submission. Steady sealed traffic, unpaid keepers, and a backlog prolong this lock. Anyone can hold it by submitting one ticket per block, paying submit and reveal gas, or deposit − bounty per withheld ticket. The open-puzzle cap limits each account, not the number of accounts.
- **Censored reveals.** A builder that controls `revealWindow + 1` consecutive blocks can keep an honest sender's reveal out of the window. The sender then loses deposit − bounty and its call does not run; the builder learns the plaintext but cannot trade around it. The window should exceed the number of consecutive blocks one builder can plausibly control. Senders should still set `minOut` and an expiry; the demonstration deliberately uses `minOut = 0`.
- **Penalty size.** The net withholding penalty is deposit − bounty, not the whole deposit. Successful reveal refunds do not depend on successful target execution. The bond is forfeited only for a failing tag.
- **Cancellation after reveal.** The deposit prices only missed reveals, not cancellation through the sender's own state. A sender can reveal on time, recover its deposit, and then revoke its approval, move its funds, or change its delegation so that its committed call fails, without penalty. Removing that option needs execution right after key release, which LUCID provides.
- **Structure is not solvability.** A sender knowing a matching key and a valid envelope under it can reveal a puzzle whose links do not solve to it, recover the deposit and the bond, and avoid a penalty. A missed inconsistent puzzle can waste a solve of up to `maxWork` steps before its commitment fails; the sender then loses its deposit and bond, but the solver is not paid. Establishing such malformation needs the paper's verification game, and paying the solver needs its designated solvers; neither is implemented. The solver remains sequential and has no persistent checkpoints.
- **Reorgs.** Queue order follows the canonical chain. A reveal on a replaced branch can expose plaintext before reordered inclusion. Daemon cursors are not reorg-aware; restart/backfill and state reconciliation do not provide finality.
- **Public metadata.** Sender, gas limit, deposit, envelope length, and timing remain visible. The demo searcher does not solve puzzles before reveal; real confidentiality depends on delay relative to ordering and on attacker hardware.
- **Last revealer.** A sender can inspect others' reveals before choosing to withhold.
- **No execution fees.** Keepers pay execution gas. Ticket and slot gas caps bound account allowances, not total decryption overhead or the number of low-gas tickets; processing can span calls.
- **Reward-copying race.** Anyone seeing `forceOpen` in the mempool can copy its key and compete for the bounty. The paper assigns each missed reveal to a solver from a staked registry instead; this PoC does not.
- **Signing.** The node signs with alloy's local signer, which uses k256 0.13 and crypto-bigint 0.5, subject to the timing advisory RUSTSEC-2026-0387. No alloy release yet uses the fixed crypto-bigint 0.7. The demo signs only anvil's published keys.
- **Application scope.** Only guarded pool operations receive position protection, and only for sealed calls restricted to non-adaptive targets. General programmable sealed transactions need execution immediately after key release, with no ordinary transaction in between, which only a protocol such as LUCID provides. A sealed swap ordered ahead of a victim can still front-run it blindly; that is probabilistic front-running, priced by deposits and fees.
- **Fresh puzzles.** The sender builds a fresh puzzle per transaction. Delay starts when a puzzle becomes public; reusing a published puzzle does not restart its delay.
