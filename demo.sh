#!/bin/sh
# End-to-end demo: time-lock a signed Ethereum transaction.
#
#   sh demo.sh [CHAINS STEPS [PATH_TO_CHAINSEAL]]
#                               default: 512 chains of 2^18 steps (about 3 s to solve)
#   sh demo.sh 512 2^25           Vitalik's example: about 6.5 minutes on an Apple M4
#
# The sender builds the puzzle ahead of time, encrypts the transaction when it
# is ready, and can open it instantly by revealing the key. Anyone else has to
# solve the puzzle, which takes n*m hash steps one after another.
set -eu
N=${1:-512}
M=${2:-2^18}
CS=${3:-$(cd "$(dirname "$0")" && pwd)/target/release/chainseal}
[ -x "$CS" ] || { echo "build first: make" >&2; exit 1; }
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# The signed transaction from EIP-155 (nonce 9, 1 ETH to 0x3535...35, chain id 1).
TX=f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83
printf '%s' "$TX" | xxd -r -p > "$T/tx"

ms() { perl -MTime::HiRes=time -e 'printf "%.0f", time * 1000'; }

echo "== 1. Sender builds a puzzle in advance (n = $N, m = $M, 16-byte links)"
"$CS" gen -n "$N" -m "$M" -o "$T/secret"

echo
echo "== 2. Sender encrypts the $(wc -c < "$T/tx" | tr -d ' ')-byte transaction under it"
"$CS" encrypt -s "$T/secret" -i "$T/tx" -o "$T/envelope"

echo
echo "== 3. Fast path: the sender reveals the key; anyone checks it and opens"
KEY=$("$CS" key "$T/secret")
t0=$(ms)
"$CS" open "$T/envelope" -k "$KEY" -o "$T/fast"
echo "opened in $(($(ms) - t0)) ms with key $KEY"
cmp "$T/tx" "$T/fast"

echo
echo "== 4. Slow path: without the key, anyone solves the puzzle"
"$CS" open "$T/envelope" --solve -o "$T/slow"
cmp "$T/tx" "$T/slow"
echo "recovered transaction: $(xxd -p "$T/slow" | tr -d '\n')"
[ "$(xxd -p "$T/slow" | tr -d '\n')" = "$TX" ] && echo "matches the original"
