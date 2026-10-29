//! sealnet: an encrypted mempool in front of an EVM chain, using leanSeal
//! timed commitments and the SealedInbox contract.
//!
//!   send      seal a call, submit it, and reveal the key once it is ordered
//!   keeper    execute each slot's revealed transactions after its window
//!   solver    solve the puzzles of withheld keys and publish them for the bounty
//!   delegate  point the sender's account at the inbox's SealedAccount (EIP-7702)
//!   sandwich  a searcher that front-runs plaintext swaps and keys it sees pending

use alloy::eips::BlockNumberOrTag;
use alloy::network::{EthereumWallet, TransactionBuilder, TransactionBuilder7702};
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent, SolValue};
use eyre::{bail, eyre, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};

sol!(
    #[sol(rpc)]
    SealedInbox,
    "../contracts/out/SealedInbox.sol/SealedInbox.json"
);
sol!(
    #[sol(rpc)]
    Pool,
    "../contracts/out/Pool.sol/Pool.json"
);

const POLL: Duration = Duration::from_millis(250);
/// EIP-7825 caps a transaction's gas at 2^24.
const TX_GAS_CAP: u64 = 1 << 24;
/// geth and reth refuse transactions over 128 KiB; keep execute's calldata below.
const TX_BYTES: usize = 120 * 1024;

struct Args(HashMap<String, String>);

impl Args {
    fn parse(items: &[String]) -> Result<Self> {
        let mut m = HashMap::new();
        let mut it = items.iter();
        while let Some(k) = it.next() {
            let k = k.strip_prefix("--").ok_or_else(|| eyre!("unexpected argument {k}"))?;
            let flag = matches!(k, "withhold" | "plain");
            let v = if flag { "1".into() } else { it.next().ok_or_else(|| eyre!("--{k} needs a value"))?.clone() };
            m.insert(k.to_string(), v);
        }
        Ok(Self(m))
    }
    fn get(&self, k: &str) -> Result<&str> {
        self.0.get(k).map(String::as_str).ok_or_else(|| eyre!("missing --{k}"))
    }
    fn or<'a>(&'a self, k: &str, d: &'a str) -> &'a str {
        self.0.get(k).map(String::as_str).unwrap_or(d)
    }
    fn flag(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
    fn num(&self, k: &str, d: u64) -> Result<u64> {
        Ok(match self.0.get(k) {
            Some(v) => parse_num(v)?,
            None => d,
        })
    }
    fn addr(&self, k: &str) -> Result<Address> {
        Ok(self.get(k)?.parse()?)
    }
}

/// The block at which a call expires, `offset` blocks after `head`.
fn expiry_block(head: u64, offset: u64) -> Result<u64> {
    head.checked_add(offset).ok_or_else(|| eyre!("--expiry {offset} runs past the last block number"))
}

/// Integers, also written as powers of two (2^20).
fn parse_num(v: &str) -> Result<u64> {
    match v.split_once('^') {
        Some(("2", e)) => 1u64.checked_shl(e.parse::<u32>()?).ok_or_else(|| eyre!("power of two out of u64 range: {v}")),
        _ => Ok(v.parse()?),
    }
}

fn checked_u32(value: u64, name: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| eyre!("--{name} exceeds uint32 range"))
}

/// Read the account key from --key-file, which only its owner may read, so the
/// key stays out of argument lists, shell history and process listings.
fn signer(a: &Args) -> Result<PrivateKeySigner> {
    use std::os::unix::fs::PermissionsExt;
    let path = a.get("key-file")?;
    if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
        bail!("{path} is readable by others; chmod 600 it");
    }
    let text = std::fs::read_to_string(path)?;
    let signer = text.trim().parse::<PrivateKeySigner>();
    let mut bytes = text.into_bytes();
    bytes.fill(0);
    std::hint::black_box(&bytes);
    Ok(signer?)
}

async fn connect(a: &Args) -> Result<(DynProvider, Address)> {
    connect_as(a, signer(a)?).await
}

async fn connect_as(a: &Args, signer: PrivateKeySigner) -> Result<(DynProvider, Address)> {
    let me = signer.address();
    let p = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect(a.or("rpc", "http://127.0.0.1:8545"))
        .await?;
    Ok((p.erased(), me))
}

fn log(who: &str, msg: impl AsRef<str>) {
    println!("[{who:>8}] {}", msg.as_ref());
}

async fn wait_block_above(p: &DynProvider, n: u64) -> Result<u64> {
    loop {
        let b = p.get_block_number().await?;
        if b > n {
            return Ok(b);
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn send(a: &Args) -> Result<()> {
    let gas = checked_u32(a.num("gas", 300_000)?, "gas")?;
    let n = checked_u32(a.num("chains", 8)?, "chains")?;
    let m = a.num("steps", 1 << 26)?;
    if n == 0 || n > 1 << 20 || m == 0 || m > 1 << 48 || u64::from(n).checked_mul(m).is_none_or(|v| v > 1 << 60) {
        bail!("--chains/--steps out of range: require 1 <= chains <= 2^20, 1 <= steps <= 2^48, chains*steps <= 2^60");
    }
    let (p, me) = connect(a).await?;
    let to = a.addr("to")?;
    let data: Bytes = a.get("data")?.parse()?;
    if a.flag("plain") {
        let tip = 2_000_000_000;
        let tx = TransactionRequest::default()
            .with_to(to)
            .with_input(data)
            .with_max_priority_fee_per_gas(tip)
            .with_max_fee_per_gas(max_fee(&p, tip).await?);
        let pending = p.send_transaction(tx).await?;
        log("sender", format!("plaintext tx {} sent to the public mempool", pending.tx_hash()));
        let r = pending.get_receipt().await?;
        log("sender", format!("included in block {}", r.block_number.unwrap_or_default()));
        return Ok(());
    }
    let inbox = SealedInbox::new(a.addr("inbox")?, p.clone());
    // The inbox accepts only accounts delegated to its own SealedAccount.
    let account = inbox.account().call().await?;
    if p.get_code_at(me).await?.as_ref() != [&[0xef, 0x01, 0x00][..], account.as_slice()].concat() {
        bail!("{me} must delegate to {account} first: sealnet delegate --to {account}");
    }
    let expiry = expiry_block(p.get_block_number().await?, a.num("expiry", 100)?)?;
    let t = Instant::now();
    let (puzzle, key) = leanseal::generate(n, m, 24, &leanseal::GenOptions::default())?;
    log("sender", format!("built a puzzle of {n}x{m} steps in {:.1?}", t.elapsed()));

    let plain = (to, data, expiry).abi_encode_params();
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)?;
    let envelope = leanseal::seal(&puzzle, &key, &nonce, &plain)?;
    let deposit = inbox.deposit().call().await?;
    let r = inbox
        .submit(envelope.clone().into(), gas)
        .value(deposit)
        .send()
        .await?
        .get_receipt()
        .await?;
    let ev = r
        .inner
        .logs()
        .iter()
        .find_map(|l| SealedInbox::Sealed::decode_log(&l.inner).ok())
        .ok_or_else(|| eyre!("no Sealed event"))?;
    let (id, slot) = (ev.id, ev.slot);
    log(
        "sender",
        format!("sealed tx #{id} ordered in block {slot}: {} bytes ({} of plaintext)", envelope.len(), plain.len()),
    );
    if a.flag("withhold") {
        log("sender", format!("withholding the key of #{id}"));
        return Ok(());
    }
    // A reveal mined after slot + window reverts but leaves the key public, so
    // send it only while it can still land in the next block.
    let window = inbox.revealWindow().call().await?;
    let now = wait_block_above(&p, slot).await?;
    if now >= slot + window {
        bail!("block {now} is too late to reveal #{id} (window ends at {}); the key stays private", slot + window);
    }
    let r = inbox.reveal(id, key.into()).send().await?.get_receipt().await?;
    let block = r.block_number.unwrap_or_default();
    if !r.status() {
        bail!("the reveal of #{id} reverted in block {block}; its key is public but the ticket will miss");
    }
    log("sender", format!("revealed the key of #{id} in block {block}"));
    Ok(())
}

async fn delegate(a: &Args) -> Result<()> {
    use alloy::eips::eip7702::Authorization;
    use alloy::signers::SignerSync;
    let signer = signer(a)?;
    let (p, me) = connect_as(a, signer.clone()).await?;
    // The sender pays for this transaction too, so the authorization uses the next nonce.
    let nonce = p.get_transaction_count(me).await?;
    let auth = Authorization { chain_id: U256::from(p.get_chain_id().await?), address: a.addr("to")?, nonce: nonce + 1 };
    let sig = signer.sign_hash_sync(&auth.signature_hash())?;
    // Gas is set by hand: estimates may leave out the 25,000 per authorization.
    let tx = TransactionRequest::default().with_to(me).with_gas_limit(100_000).with_authorization_list(vec![auth.into_signed(sig)]);
    p.send_transaction(tx).await?.get_receipt().await?;
    log("sender", format!("account {me} now delegates to {}", a.addr("to")?));
    Ok(())
}

async fn sealed_events(p: &DynProvider, inbox: Address, topic: (usize, U256)) -> Result<Vec<SealedInbox::Sealed>> {
    let f = Filter::new().address(inbox).event_signature(SealedInbox::Sealed::SIGNATURE_HASH).from_block(0);
    let f = match topic.0 {
        1 => f.topic1(FixedBytes::from(topic.1)),
        _ => f.topic2(FixedBytes::from(topic.1)),
    };
    let mut out: Vec<_> = p
        .get_logs(&f)
        .await?
        .iter()
        .map(|l| SealedInbox::Sealed::decode_log(&l.inner).map(|e| e.data))
        .collect::<Result<_, _>>()?;
    out.sort_by_key(|e| e.id);
    Ok(out)
}

/// Envelopes of the given tickets, in the given order, from their Sealed logs.
async fn envelopes_of(p: &DynProvider, inbox: Address, ids: &[U256]) -> Result<Vec<Bytes>> {
    let topics: Vec<FixedBytes<32>> = ids.iter().map(|id| FixedBytes::from(*id)).collect();
    let f = Filter::new().address(inbox).event_signature(SealedInbox::Sealed::SIGNATURE_HASH).from_block(0).topic1(topics);
    let mut by_id = HashMap::new();
    for l in p.get_logs(&f).await? {
        let e = SealedInbox::Sealed::decode_log(&l.inner)?.data;
        by_id.insert(e.id, e.envelope);
    }
    ids.iter().map(|id| by_id.remove(id).ok_or_else(|| eyre!("missing envelope of #{id}"))).collect()
}

async fn keeper(a: &Args) -> Result<()> {
    let (p, _) = connect(a).await?;
    let addr = a.addr("inbox")?;
    let gas = a.num("gas", 16_000_000)?;
    if gas > TX_GAS_CAP {
        bail!("--gas {gas} exceeds the EIP-7825 transaction cap of {TX_GAS_CAP}");
    }
    let batch = a.num("batch", 32)?.max(1);
    // After a failed transaction the next batch is half as long, down to one ticket.
    let mut size = batch;
    let inbox = SealedInbox::new(addr, p.clone());
    let window = inbox.revealWindow().call().await?;
    log("keeper", format!("reconciling on-chain queue, window {window} blocks, {gas} gas per call"));
    loop {
        let result: Result<()> = async {
            loop {
                let head = inbox.head().call().await?;
                if head == inbox.queueLength().call().await? { break; }
                let slot = inbox.slotAt(head).call().await?;
                if slot + window >= p.get_block_number().await? { break; }
                let cursor = inbox.cursor().call().await?;
                let len = inbox.slotLength(slot).call().await?;
                let end = len.min(cursor + U256::from(size));
                let mut ids = Vec::new();
                let mut i = cursor;
                while i < end {
                    ids.push(inbox.slotTicket(slot, i).call().await?);
                    i += U256::from(1);
                }
                if ids.is_empty() { bail!("empty slot {slot}"); }
                // An unrevealed ticket only needs empty bytes to be marked missed.
                let mut revealed = Vec::new();
                for id in &ids {
                    if inbox.tickets(*id).call().await?.state == 2 { revealed.push(*id); }
                }
                let mut by_id: HashMap<U256, Bytes> =
                    revealed.iter().copied().zip(envelopes_of(&p, addr, &revealed).await?).collect();
                // Each entry costs its length, padded, plus an offset and a length word.
                let mut envs = Vec::new();
                let mut bytes = 0;
                for id in &ids {
                    let env = by_id.remove(id).unwrap_or_default();
                    bytes += env.len().div_ceil(32) * 32 + 64;
                    if !envs.is_empty() && bytes > TX_BYTES { break; }
                    envs.push(env);
                }
                // execute may process only a prefix; the loop then resumes from the new cursor.
                let sent = envs.len() as u64;
                let r = match inbox.execute(envs).gas(gas).send().await {
                    Ok(pending) => pending.get_receipt().await?,
                    Err(e) => {
                        size = (sent / 2).max(1);
                        bail!("execute of {sent} tickets refused ({e}); retrying with {size}");
                    }
                };
                if !r.status() {
                    size = (sent / 2).max(1);
                    bail!("execute of {sent} tickets reverted; retrying with {size}");
                }
                size = batch;
                for l in r.inner.logs() {
                    if let Ok(e) = SealedInbox::Executed::decode_log(&l.inner) {
                        log("keeper", format!("slot {slot}: executed #{} in order (ok: {})", e.id, e.ok));
                    } else if let Ok(e) = SealedInbox::Missed::decode_log(&l.inner) {
                        log("keeper", format!("slot {slot}: #{} missed its reveal, penalty burned; it will not run", e.id));
                    }
                }
            }
            Ok(())
        }.await;
        if let Err(e) = result { log("keeper", format!("retrying after error: {e}")); }
        tokio::time::sleep(POLL).await;
    }
}

async fn solve_ticket(p: &DynProvider, addr: Address, id: U256, max_steps: u64) -> Result<()> {
    let inbox = SealedInbox::new(addr, p.clone());
    if inbox.tickets(id).call().await?.state != 4 {
        log("solver", format!("#{id} already handled; lost race or historical event"));
        return Ok(());
    }
    let ev = sealed_events(p, addr, (1, id)).await?.pop().ok_or_else(|| eyre!("no envelope for #{id}"))?;
    let env = leanseal::Envelope::decode(&ev.envelope)?;
    let puzzle = env.puzzle.clone();
    if u64::from(puzzle.n()).checked_mul(puzzle.m()).is_none_or(|steps| steps > max_steps) {
        log("solver", format!("skipping #{id}: exceeds --max-steps {max_steps}"));
        return Ok(());
    }
    // Recheck after fetching the envelope, immediately before doing expensive work.
    if inbox.tickets(id).call().await?.state != 4 {
        log("solver", format!("#{id}: lost race before solving"));
        return Ok(());
    }
    log("solver", format!("solving #{id}: {}x{} sequential steps", puzzle.n(), puzzle.m()));
    let t = Instant::now();
    let key = tokio::task::spawn_blocking(move || {
        let mut cur = puzzle.cursor();
        puzzle.solve(&mut cur, leanseal::backend::Backend::best()?, 0, |_| false)
    }).await??;
    log("solver", format!("found the key of #{id} in {:.1?}", t.elapsed()));
    if inbox.tickets(id).call().await?.state != 4 {
        log("solver", format!("#{id}: lost race before claiming"));
        return Ok(());
    }
    // Publishing the key settles the ticket and pays the bounty; the ticket does not run.
    let claim = async {
        let r = inbox.forceOpen(id, key.into()).send().await?.get_receipt().await?;
        if !r.status() { bail!("claim reverted"); }
        let block = r.block_number.unwrap_or_default();
        log("solver", format!("published the key of #{id} in block {block}; the bounty is paid and the call stays cancelled"));
        Ok(())
    }.await;
    if let Err(e) = claim {
        if inbox.tickets(id).call().await?.state != 4 {
            log("solver", format!("#{id}: lost claim race"));
        } else { return Err(e); }
    }
    Ok(())
}

async fn solver(a: &Args) -> Result<()> {
    let (p, _) = connect(a).await?;
    let addr = a.addr("inbox")?;
    let mut from = a.num("from", 0)?;
    let max_steps = a.num("max-steps", 1 << 34)?;
    log("solver", format!("watching for missed reveals from block {from}"));
    loop {
        let scan: Result<()> = async {
            let head = p.get_block_number().await?;
            if head >= from {
                let f = Filter::new().address(addr)
                    .event_signature(SealedInbox::Missed::SIGNATURE_HASH).from_block(from).to_block(head);
                for l in p.get_logs(&f).await? {
                    match SealedInbox::Missed::decode_log(&l.inner) {
                        Ok(ev) => {
                            if let Err(e) = solve_ticket(&p, addr, ev.id, max_steps).await {
                                log("solver", format!("#{}: {e}; continuing", ev.id));
                            }
                        }
                        Err(e) => log("solver", format!("invalid event: {e}; continuing")),
                    }
                }
                from = head + 1;
            }
            Ok(())
        }.await;
        if let Err(e) = scan { log("solver", format!("scan error: {e}; retrying")); }
        tokio::time::sleep(POLL).await;
    }
}

/// Open ticket `id` with a key learned from a reveal and trade ahead of its swap.
/// `pending` is the reveal's tip and hash while it waits in the mempool; the
/// front-run outbids it. Fixed gas makes a guard revert mined and visible.
async fn front_run_key(
    p: &DynProvider,
    pool: &Pool::PoolInstance<DynProvider>,
    inbox: Address,
    id: U256,
    key: FixedBytes<32>,
    size: U256,
    pending: Option<(u128, alloy::primitives::TxHash)>,
) -> Result<()> {
    let sealed = sealed_events(p, inbox, (1, id)).await?.pop().ok_or_else(|| eyre!("missing envelope"))?;
    let plain = leanseal::Envelope::decode(&sealed.envelope)?.open(&key.0)?;
    let (target, data, _) = <(Address, Bytes, u64)>::abi_decode_params(&plain)?;
    if target != *pool.address() { return Ok(()); }
    let Ok(call) = Pool::swapCall::abi_decode(&data) else { return Ok(()) };
    let mut tx = pool.swap(call.aToB, size, U256::ZERO).gas(300_000);
    if let Some((tip, _)) = pending {
        log("searcher", format!("pending reveal of #{id}: decrypted a swap of {} in, front-running it", fmt_eth(call.amountIn)));
        let front_tip = tip + 1_000_000_000;
        tx = tx.max_priority_fee_per_gas(front_tip).max_fee_per_gas(max_fee(p, front_tip).await?);
    } else {
        log("searcher", format!("revealed swap #{id}: {} in, front-running it", fmt_eth(call.amountIn)));
    }
    let receipt = tx.send().await?.get_receipt().await?;
    let mut place = String::new();
    if let Some((_, hash)) = pending {
        if let Some(r) = p.get_transaction_receipt(hash).await? {
            let at = |b: Option<u64>, i: Option<u64>| (b.unwrap_or_default(), i.unwrap_or_default());
            let ahead = at(receipt.block_number, receipt.transaction_index) < at(r.block_number, r.transaction_index);
            place = format!(" in block {}, {} the reveal", receipt.block_number.unwrap_or_default(), if ahead { "ahead of" } else { "behind" });
        }
    }
    if receipt.status() {
        log("searcher", format!("front-run of #{id} landed{place}"));
    } else {
        log("searcher", format!("front-run of #{id} reverted{place}: pool locked while #{id} is queued"));
    }
    Ok(())
}

async fn sandwich(a: &Args) -> Result<()> {
    let (p, _) = connect(a).await?;
    let pool_addr = a.addr("pool")?;
    let inbox_addr = a.addr("inbox")?;
    let pool = Pool::new(pool_addr, p.clone());
    let size = U256::from(a.num("size", 50)?) * U256::from(10u64).pow(U256::from(18));
    log("searcher", "watching the public mempool");
    let mut seen = std::collections::HashSet::new();
    // Each ticket is attacked once, as early as its key is visible.
    let mut attacked = std::collections::HashSet::new();
    let mut from = p.get_block_number().await?;
    loop {
        let head = p.get_block_number().await?;
        if head >= from {
            let f = Filter::new().address(inbox_addr)
                .event_signature(SealedInbox::Revealed::SIGNATURE_HASH).from_block(from).to_block(head);
            for l in p.get_logs(&f).await? {
                let Ok(ev) = SealedInbox::Revealed::decode_log(&l.inner) else { continue };
                if !attacked.insert(ev.id) { continue; }
                if let Err(e) = front_run_key(&p, &pool, inbox_addr, ev.id, ev.key, size, None).await {
                    log("searcher", format!("revealed attack error: {e}"));
                }
            }
            from = head + 1;
        }
        let block = p.get_block_by_number(BlockNumberOrTag::Pending).full().await?;
        let txs = block.map(|b| b.transactions.into_transactions_vec()).unwrap_or_default();
        for tx in txs {
            let hash = *tx.inner.tx_hash();
            if !seen.insert(hash) {
                continue;
            }
            let to = alloy::consensus::Transaction::to(&tx);
            let input = alloy::consensus::Transaction::input(&tx);
            let tip = alloy::consensus::Transaction::max_priority_fee_per_gas(&tx).unwrap_or(0);
            if to == Some(inbox_addr) && input.starts_with(&SealedInbox::submitCall::SELECTOR) {
                log("searcher", format!("sealed submission {hash}: {} bytes I cannot read", input.len()));
                continue;
            }
            // A pending reveal carries the key in its calldata before it executes.
            if to == Some(inbox_addr) {
                if let Ok(call) = SealedInbox::revealCall::abi_decode(input) {
                    if attacked.insert(call.id) {
                        if let Err(e) = front_run_key(&p, &pool, inbox_addr, call.id, call.key, size, Some((tip, hash))).await {
                            log("searcher", format!("pending-reveal attack error: {e}"));
                        }
                    }
                }
                continue;
            }
            // Plaintext swaps arrive directly or wrapped in a delegated account call.
            let Ok(call) = Pool::swapCall::abi_decode(input) else { continue };
            if to != Some(pool_addr) {
                continue;
            }
            log("searcher", format!("plaintext swap {hash}: {} in, front-running it", fmt_eth(call.amountIn)));
            let out = pool.quote(call.aToB, size).call().await?;
            let (front_tip, back_tip) = (tip + 1_000_000_000, tip.saturating_sub(1_000_000_000).max(1));
            let _front = pool
                .swap(call.aToB, size, U256::ZERO)
                .max_priority_fee_per_gas(front_tip)
                .max_fee_per_gas(max_fee(&p, front_tip).await?)
                .send()
                .await?;
            let back = pool
                .swap(!call.aToB, out, U256::ZERO)
                .max_priority_fee_per_gas(back_tip)
                .max_fee_per_gas(max_fee(&p, back_tip).await?)
                .send()
                .await?;
            back.get_receipt().await?;
            log("searcher", "sandwich landed");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A fee cap that leaves room for the base fee to double.
async fn max_fee(p: &DynProvider, tip: u128) -> Result<u128> {
    let base = p.get_block_by_number(BlockNumberOrTag::Latest).await?.and_then(|b| b.header.base_fee_per_gas).unwrap_or(0);
    Ok(2 * base as u128 + tip)
}

fn fmt_eth(v: U256) -> String {
    let milli = v / U256::from(1_000_000_000_000_000u64);
    format!("{}.{:03}", milli / U256::from(1000), milli % U256::from(1000))
}

#[tokio::main]
async fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = argv.split_first().ok_or_else(|| eyre!("usage: sealnet send|keeper|solver|delegate|sandwich [--opt value]..."))?;
    let a = Args::parse(rest)?;
    match cmd.as_str() {
        "send" => send(&a).await,
        "keeper" => keeper(&a).await,
        "solver" => solver(&a).await,
        "sandwich" => sandwich(&a).await,
        "delegate" => delegate(&a).await,
        _ => bail!("unknown command {cmd}"),
    }
}

#[cfg(test)]
mod numeric_tests {
    use super::*;
    #[test]
    fn rejects_wrapped_options() {
        assert!(parse_num("2^64").is_err());
        assert!(parse_num("2^4294967296").is_err());
        assert!(checked_u32(parse_num("4294967297").unwrap(), "chains").is_err());
        assert!(checked_u32(parse_num("4294967296").unwrap(), "gas").is_err());
        assert_eq!(parse_num("2^26").unwrap(), 1 << 26);
        assert_eq!(checked_u32(u32::MAX.into(), "gas").unwrap(), u32::MAX);
        assert!(expiry_block(1, u64::MAX).is_err());
        assert_eq!(expiry_block(1, u64::MAX - 1).unwrap(), u64::MAX);
    }
}
