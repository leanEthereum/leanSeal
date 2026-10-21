#!/bin/sh
# End-to-end tests of the command-line tool. Usage: sh tests/cli.sh ./chainseal
set -eu
CS=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
cd "$T"
fail() { echo "cli test failed: $*" >&2; exit 1; }
expect_exit() {  # expect_exit CODE command...
  want=$1; shift
  set +e; "$@" >/dev/null 2>&1; got=$?; set -e
  [ "$got" = "$want" ] || fail "'$*' exited $got, wanted $want"
}
flip() {  # flip FILE OFFSET: XOR one bit of the byte at OFFSET, so the file always changes
  v=$(dd if="$1" bs=1 skip="$2" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
  printf "\\$(printf %03o $((v ^ 1)))" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}

printf 'the vote is 7 to 2' > msg

# A stored puzzle: gen, encrypt with it, reveal the key, open three ways.
"$CS" gen -q -n 8 -m 2000 -o sec
[ "$(stat -f %Lp sec 2>/dev/null || stat -c %a sec)" = 600 ] || fail "secret file is not private"
"$CS" encrypt -q -s sec -i msg -o env
KEY=$("$CS" key sec)
"$CS" open env -k "$KEY" -o out1 && cmp msg out1
"$CS" open env -s sec -o out2 && cmp msg out2
"$CS" open env --solve -q -o out3 && cmp msg out3
SOLVED=$("$CS" solve -q env | cut -d' ' -f1)
[ "$SOLVED" = "$KEY" ] || fail "solved key differs from the stored key"
[ ! -e env.ckpt ] || fail "checkpoint left behind after solving"
"$CS" info env > info.txt && grep -q 'chains n       8' info.txt || fail "info"

# Envelope sizes: 128 + n*b + len (SPEC.md section 6.2).
[ "$(wc -c < env | tr -d ' ')" = $((128 + 8 * 12 + 18)) ] || fail "envelope size"

# Fresh puzzle in one go, from stdin, with --delay; empty message.
printf '' | "$CS" encrypt -q -n 4 -d 0.01 --step-ns 25 --secret-out sec2 -o env2
"$CS" open env2 -s sec2 -o out4 && [ ! -s out4 ] || fail "empty message"

# Failures: wrong key, tampered envelope, malformed key, wrong secret.
BAD=0000000000000000000000000000000000000000000000000000000000000000
expect_exit 3 "$CS" open env -k "$BAD"
expect_exit 3 "$CS" open env -s sec2
cp env env.bad && flip env.bad $(( $(wc -c < env) - 1 ))
cmp -s env env.bad && fail "tampering did not change the envelope"
expect_exit 3 "$CS" open env.bad -k "$KEY"
"$CS" open env.bad -k "$KEY" -o out5 2>/dev/null || true
[ ! -e out5 ] || fail "plaintext written for a tampered envelope"
expect_exit 2 "$CS" open env -k nothex
expect_exit 2 "$CS" open env
expect_exit 2 "$CS" gen -n 0 -m 5 -o x
expect_exit 2 "$CS" gen -b 33 -m 5 -o x
expect_exit 2 "$CS" gen -d inf -o x
expect_exit 2 "$CS" gen -d 1e308h -o x
expect_exit 2 "$CS" gen -d 1 --step-ns inf -o x
expect_exit 2 "$CS" gen -d nan -o x
expect_exit 1 "$CS" open msg -k "$KEY"

# Several puzzles solved in parallel.
"$CS" encrypt -q -n 2 -m 50000 -i msg -o p1 --secret-out s1
"$CS" encrypt -q -n 2 -m 50000 -i msg -o p2 --secret-out s2
"$CS" solve -q p1 p2 > keys
[ "$(sed -n 1p keys | cut -d' ' -f1)" = "$("$CS" key s1)" ] || fail "parallel solve 1"
[ "$(sed -n 2p keys | cut -d' ' -f1)" = "$("$CS" key s2)" ] || fail "parallel solve 2"

# A malformed puzzle among several: the others' keys are still printed.
cp p2 p2.bad && flip p2.bad $((8 + 68 + 12))
set +e; "$CS" solve -q p1 p2.bad > keys 2>/dev/null; code=$?; set -e
[ "$code" = 1 ] || fail "solve with a malformed puzzle exited $code, wanted 1"
[ "$(cut -d' ' -f1 keys)" = "$("$CS" key s1)" ] || fail "key lost when another puzzle was malformed"
[ ! -e p1.ckpt ] && [ ! -e p2.bad.ckpt ] || fail "checkpoint left after a finished solve"

# Interrupt a solve, then resume it from the checkpoint. 2^27 steps take about
# 3 s on an Apple M4; the interrupt comes after 0.5 s, so this needs a solver
# at least 6 times faster than an M4 core to finish first.
"$CS" encrypt -q -n 4 -m 2^25 -i msg -o long --secret-out slong
"$CS" solve -q long > /dev/null 2>&1 &
PID=$!
sleep 0.5
kill -INT $PID || fail "the solve finished before it could be interrupted"
set +e; wait $PID; code=$?; set -e
[ "$code" = 130 ] || fail "interrupted solve exited $code, wanted 130"
[ -s long.ckpt ] || fail "no checkpoint after interrupt"
"$CS" info long.ckpt | grep -q checkpoint || fail "checkpoint info"
cp long.ckpt bad.ckpt && printf '\002' | dd of=bad.ckpt bs=1 seek=4 conv=notrunc 2>/dev/null
expect_exit 1 "$CS" info bad.ckpt
"$CS" solve long > keys 2> log
grep -q resuming log || fail "solve did not resume"
[ "$(cut -d' ' -f1 keys)" = "$("$CS" key slong)" ] || fail "resumed solve key"
[ ! -e long.ckpt ] || fail "checkpoint left after resumed solve"

# A checkpoint of another puzzle is refused.
"$CS" solve -q long > /dev/null 2>&1 &
PID=$!; sleep 0.5; kill -INT $PID; wait $PID || true
mv long.ckpt p1.ckpt
expect_exit 1 "$CS" solve -q p1
echo "cli tests: ok"
