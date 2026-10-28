#!/usr/bin/env python3
"""Sample recent Ethereum mainnet blocks and measure transaction sizes.

Reproduces the Ethereum statistics quoted in the leanSeal paper.

    python3 -I bench/eth-sample.py [--rpc URL] [--last BLOCK] [--count 20] \
        --out bench-results/eth-sample.json

Size convention. A transaction's size is the byte length of its signed
encoding as returned by eth_getRawTransactionByHash: the EIP-2718 typed
envelope (type byte || RLP payload; plain RLP for legacy type-0 txs), i.e.
exactly the bytes included in the block body. For blob (type-3) txs this
excludes the blob sidecar, which is gossiped alongside but not part of the block.

Calldata is the tx `input` field; `calldata_nonzero` counts its nonzero
bytes (these cost 16 gas each versus 4 for zero bytes, pre-EIP-7623 floor).

Python 3 standard library only.
"""

import argparse
import json
import statistics as st
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"
BLOCK_BATCH = 5  # full blocks are a few hundred KB each
TX_BATCH = 50  # raw-tx lookups per HTTP request
PAUSE = 0.25  # seconds between HTTP requests, to stay under rate limits


def rpc_batch(url, calls, tries=6):
    """Send [(method, params), ...] as one JSON-RPC batch; return results in order.

    Retries the whole batch on HTTP errors or any per-item error, with
    exponential backoff. A null result is returned as None (caller checks).
    """
    body = json.dumps([{"jsonrpc": "2.0", "id": i, "method": m, "params": p}
                       for i, (m, p) in enumerate(calls)]).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "curl/8"}
    for attempt in range(tries):
        time.sleep(PAUSE if attempt == 0 else PAUSE * 4 ** attempt)
        try:
            req = urllib.request.Request(url, body, headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                resp = json.load(r)
            if not isinstance(resp, list):
                raise RuntimeError(f"non-batch reply: {str(resp)[:200]}")
            errs = [x["error"] for x in resp if "error" in x]
            if errs or len(resp) != len(calls):
                raise RuntimeError(f"rpc errors: {errs[:2]} (got {len(resp)}/{len(calls)})")
            return [x["result"] for x in sorted(resp, key=lambda x: x["id"])]
        except (urllib.error.URLError, TimeoutError, RuntimeError, ValueError) as e:
            print(f"  retry {attempt + 1}/{tries}: {e}", file=sys.stderr)
    sys.exit("giving up after repeated RPC failures")


def nbytes(hexstr):
    """Byte length of a 0x-prefixed hex string."""
    return (len(hexstr) - 2) // 2


def pct(xs, p):
    """p-th percentile, linear interpolation between closest ranks
    (statistics.quantiles 'inclusive', same as numpy's default)."""
    return st.quantiles(xs, n=100, method="inclusive")[p - 1]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rpc", default=DEFAULT_RPC)
    ap.add_argument("--last", type=int, help="last block (default: latest - 2)")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    last = a.last
    if last is None:  # stay 2 blocks behind the head to avoid reorged tips
        last = int(rpc_batch(a.rpc, [("eth_blockNumber", [])])[0], 16) - 2
    numbers = list(range(last - a.count + 1, last + 1))

    # 1. Blocks with full transaction objects.
    raw_blocks = []
    for i in range(0, len(numbers), BLOCK_BATCH):
        chunk = numbers[i:i + BLOCK_BATCH]
        raw_blocks += rpc_batch(a.rpc, [("eth_getBlockByNumber", [hex(n), True]) for n in chunk])
        print(f"blocks {chunk[0]}..{chunk[-1]} fetched", file=sys.stderr)
    assert all(b is not None for b in raw_blocks), "missing block"

    blocks, txs, hashes = [], [], []
    for b in raw_blocks:
        blocks.append({
            "number": int(b["number"], 16),
            "hash": b["hash"],
            "timestamp": int(b["timestamp"], 16),
            "size": int(b["size"], 16),  # RLP size of the whole block
            "tx_count": len(b["transactions"]),
            "gas_used": int(b["gasUsed"], 16),
            "gas_limit": int(b["gasLimit"], 16),
            "base_fee_per_gas": int(b["baseFeePerGas"], 16),
        })
        for t in b["transactions"]:
            data = bytes.fromhex(t["input"][2:])
            txs.append([int(b["number"], 16), int(t["transactionIndex"], 16),
                        int(t.get("type", "0x0"), 16), None,  # raw_bytes filled below
                        len(data), sum(1 for x in data if x)])
            hashes.append(t["hash"])

    # 2. Raw signed encoding of every transaction.
    for i in range(0, len(hashes), TX_BATCH):
        raws = rpc_batch(a.rpc, [("eth_getRawTransactionByHash", [h]) for h in hashes[i:i + TX_BATCH]])
        for j, raw in enumerate(raws):
            assert raw is not None, f"no raw encoding for {hashes[i + j]}"
            txs[i + j][3] = nbytes(raw)
        print(f"raw txs {i + len(raws)}/{len(hashes)}", file=sys.stderr)

    # Sanity check: a block's transactions fit inside the block's RLP size.
    for blk in blocks:
        assert sum(t[3] for t in txs if t[0] == blk["number"]) < blk["size"], blk["number"]

    raw = [t[3] for t in txs]
    cd = [t[4] for t in txs]
    summary = {
        "blocks": f"{numbers[0]}-{numbers[-1]}",
        "tx_count": len(txs),
        "raw_bytes": {"mean": st.mean(raw), "median": st.median(raw),
                      **{f"p{p}": pct(raw, p) for p in (10, 25, 75, 90)}},
        "calldata_bytes": {"mean": st.mean(cd), "median": st.median(cd)},
        "mean_txs_per_block": st.mean(b["tx_count"] for b in blocks),
        "mean_gas_used": st.mean(b["gas_used"] for b in blocks),
        "mean_base_fee_gwei": st.mean(b["base_fee_per_gas"] for b in blocks) / 1e9,
    }
    out = {
        "rpc": a.rpc,
        "fetched_at_utc": fetched_at,
        "size_convention": "raw_bytes = len(eth_getRawTransactionByHash): EIP-2718 "
                           "typed envelope as broadcast, excluding blob sidecars",
        "summary": summary,
        "blocks": blocks,
        "tx_columns": ["block", "index", "type", "raw_bytes", "calldata_bytes", "calldata_nonzero"],
        "txs": txs,
    }
    with open(a.out, "w") as f:  # one tx row per line keeps the file small and diffable
        body = json.dumps({k: v for k, v in out.items() if k != "txs"}, indent=1)[:-2]
        f.write(body + ',\n "txs": [\n' + ",\n".join(json.dumps(t) for t in txs) + "\n ]\n}\n")

    r = summary["raw_bytes"]
    print(f"blocks {summary['blocks']} ({len(blocks)} blocks, {len(txs)} txs), fetched {fetched_at}")
    print(f"raw tx bytes: mean {r['mean']:.1f}, median {r['median']:g}, "
          f"p10/p25/p75/p90 {r['p10']:g}/{r['p25']:g}/{r['p75']:g}/{r['p90']:g}")
    print(f"calldata bytes: mean {summary['calldata_bytes']['mean']:.1f}, "
          f"median {summary['calldata_bytes']['median']:g}")
    print(f"per block: {summary['mean_txs_per_block']:.1f} txs, "
          f"gasUsed {summary['mean_gas_used'] / 1e6:.2f}M, "
          f"base fee {summary['mean_base_fee_gwei']:.4f} gwei")


if __name__ == "__main__":
    main()
