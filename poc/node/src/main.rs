//! sealnet: an encrypted mempool in front of an EVM chain, using leanSeal
//! timed commitments and the SealedInbox contract.
//!
//!   send      seal a call, submit it, and reveal the key once it is ordered
//!   keeper    execute each slot's revealed transactions after its window
//!   solver    solve the puzzles of withheld keys and force their opening
//!   delegate  point the sender's account at SealedAccount (EIP-7702)
//!   sandwich  a searcher that front-runs plaintext swaps it sees pending

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

/// Integers, also written as powers of two (2^20).
fn parse_num(v: &str) -> Result<u64> {
    match v.split_once('^') {
        Some(("2", e)) => Ok(1u64 << e.parse::<u32>()?),
        _ => Ok(v.parse()?),
    }
}

async fn connect(a: &Args) -> Result<(DynProvider, Address)> {
    let signer: PrivateKeySigner = a.get("key")?.parse()?;
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
    let (p, _) = connect(a).await?;
    let to = a.addr("to")?;
    let data: Bytes = a.get("data")?.parse()?;
    let gas = a.num("gas", 300_000)?;
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
    let (n, m) = (a.num("chains", 8)? as u32, a.num("steps", 1 << 26)?);
    let t = Instant::now();
    let (puzzle, key) = leanseal::generate(n, m, 24, &leanseal::GenOptions::default())?;
    log("sender", format!("built a puzzle of {n}x{m} steps in {:.1?}", t.elapsed()));

    let expiry = p.get_block_number().await? + a.num("expiry", 100)?;
    let plain = (to, data, expiry).abi_encode_params();
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)?;
    let envelope = leanseal::seal(&puzzle, &key, &nonce, &plain)?;
    let deposit = inbox.deposit().call().await?;
    let r = inbox
        .submit(envelope.clone().into(), gas as u32)
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
    wait_block_above(&p, slot).await?;
    let r = inbox.reveal(id, key.into()).send().await?.get_receipt().await?;
    log("sender", format!("revealed the key of #{id} in block {}", r.block_number.unwrap_or_default()));
    Ok(())
}

async fn delegate(a: &Args) -> Result<()> {
    use alloy::eips::eip7702::Authorization;
    use alloy::signers::SignerSync;
    let (p, me) = connect(a).await?;
    let signer: PrivateKeySigner = a.get("key")?.parse()?;
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

async fn keeper(a: &Args) -> Result<()> {
    let (p, _) = connect(a).await?;
    let addr = a.addr("inbox")?;
    let inbox = SealedInbox::new(addr, p.clone());
    let window = inbox.revealWindow().call().await?;
    let mut slot = a.num("from", p.get_block_number().await?)?;
    log("keeper", format!("executing slots from block {slot}, window {window} blocks"));
    loop {
        let head = p.get_block_number().await?;
        while slot + window < head {
            if inbox.slotLength(slot).call().await? > U256::ZERO && !inbox.slotDone(slot).call().await? {
                let envs: Vec<Bytes> = sealed_events(&p, addr, (2, U256::from(slot)))
                    .await?
                    .into_iter()
                    .map(|e| e.envelope)
                    .collect();
                let r = inbox.execute(slot, envs).send().await?.get_receipt().await?;
                for l in r.inner.logs() {
                    if let Ok(e) = SealedInbox::Executed::decode_log(&l.inner) {
                        log("keeper", format!("slot {slot}: executed #{} in order (ok: {})", e.id, e.ok));
                    } else if let Ok(e) = SealedInbox::Missed::decode_log(&l.inner) {
                        log("keeper", format!("slot {slot}: #{} missed its reveal, deposit forfeited", e.id));
                    }
                }
            }
            slot += 1;
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn solver(a: &Args) -> Result<()> {
    let (p, _) = connect(a).await?;
    let addr = a.addr("inbox")?;
    let inbox = SealedInbox::new(addr, p.clone());
    let mut from = p.get_block_number().await?;
    log("solver", "watching for missed reveals");
    loop {
        let head = p.get_block_number().await?;
        if head >= from {
            let f = Filter::new()
                .address(addr)
                .event_signature(SealedInbox::Missed::SIGNATURE_HASH)
                .from_block(from)
                .to_block(head);
            for l in p.get_logs(&f).await? {
                let id = SealedInbox::Missed::decode_log(&l.inner)?.data.id;
                let ev = sealed_events(&p, addr, (1, id)).await?.pop().ok_or_else(|| eyre!("no envelope for #{id}"))?;
                let env = leanseal::Envelope::decode(&ev.envelope)?;
                let puzzle = env.puzzle.clone();
                log("solver", format!("solving #{id}: {}x{} sequential steps", puzzle.n(), puzzle.m()));
                let t = Instant::now();
                let key = tokio::task::spawn_blocking(move || {
                    let mut cur = puzzle.cursor();
                    puzzle.solve(&mut cur, leanseal::backend::Backend::best()?, 0, |_| false)
                })
                .await??;
                log("solver", format!("found the key of #{id} in {:.1?}", t.elapsed()));
                let r = inbox.forceOpen(id, key.into(), ev.envelope.clone()).send().await?.get_receipt().await?;
                for l in r.inner.logs() {
                    if let Ok(e) = SealedInbox::Executed::decode_log(&l.inner) {
                        log("solver", format!("forced #{} open in block {}; executed late: {}", e.id, r.block_number.unwrap_or_default(), e.ok));
                    }
                }
            }
            from = head + 1;
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn sandwich(a: &Args) -> Result<()> {
    let (p, _) = connect(a).await?;
    let pool_addr = a.addr("pool")?;
    let inbox_addr = a.addr("inbox")?;
    let pool = Pool::new(pool_addr, p.clone());
    let size = U256::from(a.num("size", 50)?) * U256::from(10u64).pow(U256::from(18));
    log("searcher", "watching the public mempool");
    let mut seen = std::collections::HashSet::new();
    loop {
        let block = p.get_block_by_number(BlockNumberOrTag::Pending).full().await?;
        let txs = block.map(|b| b.transactions.into_transactions_vec()).unwrap_or_default();
        for tx in txs {
            let hash = *tx.inner.tx_hash();
            if !seen.insert(hash) {
                continue;
            }
            let to = alloy::consensus::Transaction::to(&tx);
            let input = alloy::consensus::Transaction::input(&tx);
            if to == Some(inbox_addr) && input.starts_with(&SealedInbox::submitCall::SELECTOR) {
                log("searcher", format!("sealed submission {hash}: {} bytes I cannot read", input.len()));
                continue;
            }
            // Plaintext swaps arrive directly or wrapped in a delegated account call.
            let Ok(call) = Pool::swapCall::abi_decode(input) else { continue };
            if to != Some(pool_addr) {
                continue;
            }
            let tip = alloy::consensus::Transaction::max_priority_fee_per_gas(&tx).unwrap_or(0);
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
