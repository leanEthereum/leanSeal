# sealnet: an encrypted mempool on leanSeal

A proof of concept of the design in the paper (section "Sealing Transactions with leanSeal"). Senders seal transactions under leanSeal puzzles. The chain fixes their order before anyone can read them. Each sender then reveals its key, and anyone executes the transactions in the committed order. A sender that stays silent forfeits a deposit, and a solver opens its transaction from the puzzle alone.

It runs on any EVM chain with EIP-7702 as a contract plus off-chain daemons, so it needs no client changes. The same data, a ciphertext and a commitment to its key, is what LUCID (EIP-8184) puts in a sealed transaction's ticket (see [Mapping to LUCID](#mapping-to-lucid)).

## Run the demo

You need Foundry (`anvil`, `forge`) and a Rust toolchain.

```bash
git submodule update --init poc/contracts/lib/forge-std
poc/demo.sh
```

The script starts a local chain with 2-second blocks, deploys the contracts and a constant-product pool, and starts a keeper, a solver and a sandwich searcher. Then it runs three swaps of 10 A for B from the same account:

```text
== 1. plaintext swap in the public mempool
[searcher] plaintext swap 0x7eee…6666: 10.000 in, front-running it
[searcher] sandwich landed
   alice got 8.9847 B for 10 A; fair price 9.9010 B; lost 9.25%
== 2. the same swap sealed with leanSeal
[  sender] built a puzzle of 8x67108864 steps in 3.4s
[searcher] sealed submission 0x2e6d…8df0: 676 bytes I cannot read
[  sender] sealed tx #0 ordered in block 24: 576 bytes (256 of plaintext)
[  sender] revealed the key of #0 in block 26
[  keeper] slot 24: executed #0 in order (ok: true)
   alice got 9.7247 B for 10 A; fair price 9.7247 B; lost 0.00%
== 3. a sealed swap whose sender withholds the key
[  keeper] slot 33: #1 missed its reveal, deposit forfeited
[  solver] solving #1: 8x67108864 sequential steps
[  solver] found the key of #1 in 19.5s
[  solver] forced #1 open in block 47; executed late: true
```

The demo puzzle takes about 20 seconds to solve on one core, against 2-second blocks. A deployment would use a delay of about a minute against the fastest assumed hardware (paper, section "Costs").

## Components

| Path | Role |
|---|---|
| `contracts/src/LeanSeal.sol` | Checks a key against a puzzle's commitment and opens a leanSeal v1 envelope on chain. Every hash is SHA-256, so this is a few precompile calls. Tested against `tests/vectors.json`. |
| `contracts/src/SealedInbox.sol` | The mempool contract: `submit`, `reveal`, `execute`, `forceOpen`. |
| `contracts/src/SealedAccount.sol` | EIP-7702 delegate that lets the inbox call as the sender's account, so an opened transaction runs with the sender's address, balances and approvals. |
| `contracts/src/demo/` | A token and a fee-less constant-product pool. |
| `node/` (`sealnet`) | Off-chain roles: `send`, `keeper`, `solver`, `delegate`, `sandwich`. |
| `demo.sh` | The end-to-end run above. |

## Protocol

1. **Submit.** The sender builds a puzzle, encrypts `abi.encode(target, data, expiry)` in a leanSeal envelope, and calls `submit(envelope, gasLimit)` with a deposit. The block that includes the call fixes the transaction's position: the slot is the block number, and the order within the slot is the order of submission. The inbox stores the hash of the whole envelope, so a revealed key cannot open a different transaction.
2. **Reveal.** In the next `revealWindow` blocks, the sender, or anyone holding the key, calls `reveal(id, key)`. The inbox checks the key against the puzzle commitment (one SHA-256) and refunds the deposit.
3. **Execute.** After the window, anyone calls `execute(slot, envelopes)` with the envelopes from the slot's `Sealed` events. The inbox decrypts each revealed transaction and runs it in the committed order. A transaction that fails to decrypt or decode, has expired or reverts is skipped and does not block the slot. Unrevealed tickets are marked missed; their deposits are forfeited.
4. **Force open.** A solver that finds a missed ticket's key from the puzzle calls `forceOpen(id, key, envelope)` and collects the deposit. The transaction then runs late, unless it has expired.

Gas on the demo (`forge test --gas-report`): `submit` about 199,000 (mostly storage of the ticket), `reveal` about 74,000, `execute` about 150,000 for one swap including decryption, `forceOpen` about 165,000 to 200,000.

## Mapping to LUCID

| LUCID ticket field | sealnet |
|---|---|
| `key_commitment` | the puzzle's commitment `C`, checked with SHA-256 instead of keccak256 |
| `ciphertext_hash` | `envelopeHash` |
| `key_publisher` | the sender itself; the puzzle replaces a third party as the fallback |
| `key_publication_fee` (forfeited on a missed reveal) | `deposit` |
| `header` of the ciphertext envelope | the encoded puzzle, 92 to 452 bytes |

LUCID fixes ChaCha20-Poly1305 as the cipher, so inside LUCID only the puzzle part of leanSeal is used and `K` serves as `k_dem`. LUCID also expects keys within a slot, so the fallback guarantees that a withheld transaction is disclosed and can run late, not that it runs at its position.

## Limits

This is a proof of concept. It is not audited and is not safe to deploy with real funds.

- **Order is fixed by the chain, not the protocol.** On a chain with reorganizations, a revealed transaction can be front-run in a replacement block. The design fits chains with fast finality.
- **Metadata is public.** The sender, the deposit, the gas limit and the envelope length are visible.
- **The searcher in the demo does not try to solve puzzles.** The demo puzzle is far shorter than a real one; privacy comes from the puzzle taking longer to solve than the time between broadcast and ordering.
- **Reveals are on chain and visible before the window closes,** so a sender can wait and see the others' reveals before deciding (the "last revealer" problem). A deployment should collect reveals off chain and post them together.
- **Puzzles are not checked.** A sender can submit a puzzle that does not solve to its key. It loses its deposit, and its transaction never opens.
- **The solver's reward can be stolen.** Anyone who sees a solver's `forceOpen` in the mempool can copy the key. A deployment should use a commit–reveal of the key or a designated solver.
- **Execution fees are not charged.** The keeper pays the gas of `execute`; a deployment would charge each ticket for its gas limit, as Shutter and LUCID do.
- **The sender builds a fresh puzzle per transaction.** A wallet should keep a stock of single-chain puzzles built in advance (paper, section "The number of chains").
