#!/usr/bin/env bash
# End-to-end demo on a local anvil chain:
#   1. a plaintext swap is sandwiched by a searcher watching the mempool;
#   2. the same swap sealed with leanSeal is ordered blind, revealed, executed;
#   3. a sender that withholds its key loses its deposit; a solver publishes the
#      key and the keeper executes the ticket late, in its new queue position.
set -euo pipefail
cd "$(dirname "$0")"
PORT=${PORT:-8545}
RPC=http://127.0.0.1:$PORT
# anvil's well-known development keys
DEPLOYER=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ALICE=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
SEARCHER=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
KEEPER=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
SOLVER=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
ALICE_ADDR=$(cast wallet address $ALICE)

(cd contracts && forge build -q)
(cd node && cargo build --release -q)
BIN=node/target/release/sealnet

anvil --port $PORT --hardfork prague --block-time 2 --silent &
PIDS=($!)
cleanup() {
  kill "${PIDS[@]}" 2>/dev/null || true
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sleep 1

out=$(cd contracts && DEPLOYER=$DEPLOYER ALICE=$ALICE SEARCHER=$SEARCHER \
  forge script script/Deploy.s.sol --rpc-url $RPC --broadcast 2>&1)
get() { echo "$out" | awk -v k="$1" '$1==k {print $2}'; }
INBOX=$(get INBOX); ACCOUNT=$(get ACCOUNT); POOL=$(get POOL); TOKEN_B=$(get TOKEN_B)
$BIN delegate --rpc $RPC --key $ALICE --to $ACCOUNT
echo "inbox $INBOX, pool $POOL; alice's account delegates to $ACCOUNT"

$BIN keeper --rpc $RPC --key $KEEPER --inbox $INBOX & PIDS+=($!)
$BIN solver --rpc $RPC --key $SOLVER --inbox $INBOX & PIDS+=($!)
$BIN sandwich --rpc $RPC --key $SEARCHER --pool $POOL --inbox $INBOX --size 50 & PIDS+=($!)
sleep 2

bal() { cast call --rpc-url $RPC $TOKEN_B "balanceOf(address)(uint256)" $ALICE_ADDR | awk '{print $1}'; }
quote() { cast call --rpc-url $RPC $POOL "quote(bool,uint256)(uint256)" true 10000000000000000000 | awk '{print $1}'; }
swap=$(cast calldata "swap(bool,uint256,uint256)" true 10000000000000000000 0)
report() {
  python3 -c "q,b0,b1=$1,$2,$3; got=b1-b0; print(f'   alice got {got/1e18:.4f} B for 10 A; fair price {q/1e18:.4f} B; lost {100*(q-got)/q:.2f}%')"
}
# Wait until the keeper has executed everything up to the current block.
settle() { sleep ${1:-10}; }
# Wait up to $2 seconds for alice's B balance to move from $1.
await_bal() {
  local t0=$SECONDS
  while [ "$(bal)" = "$1" ] && [ $((SECONDS - t0)) -lt $2 ]; do sleep 2; done
  echo "   (waited $((SECONDS - t0))s for the late execution)"
}

echo; echo "== 1. plaintext swap in the public mempool"
q=$(quote); b0=$(bal)
$BIN send --rpc $RPC --key $ALICE --to $POOL --data $swap --plain
settle 4; report $q $b0 $(bal)

echo; echo "== 2. the same swap sealed with leanSeal"
q=$(quote); b0=$(bal)
$BIN send --rpc $RPC --key $ALICE --inbox $INBOX --to $POOL --data $swap --chains 8 --steps 2^26
settle 8; report $q $b0 $(bal)

echo; echo "== 3. a sealed swap whose sender withholds the key"
q=$(quote); b0=$(bal)
$BIN send --rpc $RPC --key $ALICE --inbox $INBOX --to $POOL --data $swap --chains 8 --steps 2^26 --withhold
await_bal $b0 ${FORCE_WAIT:-300}; report $q $b0 $(bal)
