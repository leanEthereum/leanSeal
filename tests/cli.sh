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
cp env env.bad && printf '\001' | dd of=env.bad bs=1 seek=$(( $(wc -c < env) - 1 )) conv=notrunc 2>/dev/null
expect_exit 3 "$CS" open env.bad -k "$KEY"
"$CS" open env.bad -k "$KEY" -o out5 2>/dev/null || true
[ ! -e out5 ] || fail "plaintext written for a tampered envelope"
expect_exit 2 "$CS" open env -k nothex
expect_exit 2 "$CS" open env
expect_exit 2 "$CS" gen -n 0 -m 5 -o x
expect_exit 2 "$CS" gen -b 33 -m 5 -o x
expect_exit 1 "$CS" open msg -k "$KEY"

# Several puzzles solved in parallel.
"$CS" encrypt -q -n 2 -m 50000 -i msg -o p1 --secret-out s1
"$CS" encrypt -q -n 2 -m 50000 -i msg -o p2 --secret-out s2
"$CS" solve -q p1 p2 > keys
[ "$(sed -n 1p keys | cut -d' ' -f1)" = "$("$CS" key s1)" ] || fail "parallel solve 1"
[ "$(sed -n 2p keys | cut -d' ' -f1)" = "$("$CS" key s2)" ] || fail "parallel solve 2"

# Interrupt a solve, then resume it from the checkpoint.
"$CS" encrypt -q -n 4 -m 15000000 -i msg -o long --secret-out slong
"$CS" solve -q long > /dev/null 2>&1 &
PID=$!
sleep 1
kill -INT $PID
set +e; wait $PID; code=$?; set -e
[ "$code" = 130 ] || fail "interrupted solve exited $code, wanted 130"
[ -s long.ckpt ] || fail "no checkpoint after interrupt"
"$CS" info long.ckpt | grep -q checkpoint || fail "checkpoint info"
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
