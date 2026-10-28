#!/bin/sh
# End-to-end tests of the command-line tool. Usage: sh tests/cli.sh [PATH_TO_LEANSEAL]
set -eu
set -- "${1:-./target/release/leanseal}"
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
poke() {  # poke FILE OFFSET FORMAT VALUE...: overwrite bytes with struct.pack(FORMAT, VALUE...)
  python3 -c 'import struct, sys
f = open(sys.argv[1], "r+b"); f.seek(int(sys.argv[2])); f.write(struct.pack(sys.argv[3], *map(int, sys.argv[4:])))' "$@"
}
flip() {  # flip FILE OFFSET: XOR one bit of the byte at OFFSET, so the file always changes
  v=$(dd if="$1" bs=1 skip="$2" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
  printf "\\$(printf %03o $((v ^ 1)))" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}

printf 'the vote is 7 to 2' > msg

# A stored puzzle: gen, encrypt with it, reveal the key, open three ways.
"$CS" gen -q -n 8 -m 2000 -b 24 -o sec
[ "$(stat -c %a sec 2>/dev/null || stat -f %Lp sec)" = 600 ] || fail "secret file is not private"
"$CS" encrypt -q -s sec -i msg -o env
KEY=$("$CS" key sec)
"$CS" open env -k "$KEY" -o out1 && cmp msg out1
printf '%s\n' "$KEY" | "$CS" open env -k - -o out1s && cmp msg out1s || fail "open with the key on stdin"
expect_exit 2 "$CS" open - -k - < env
"$CS" open env -s sec -o out2 && cmp msg out2
"$CS" open env --solve -q -o out3 && cmp msg out3
SOLVED=$("$CS" solve -q env | cut -d' ' -f1)
[ "$SOLVED" = "$KEY" ] || fail "solved key differs from the stored key"
[ ! -e env.ckpt ] || fail "checkpoint left behind after solving"
"$CS" info env > info.txt && grep -q 'chains n       8' info.txt || fail "info"

# Envelope sizes: 128 + n*b + len (SPEC.md section 6.2).
[ "$(wc -c < env | tr -d ' ')" = $((128 + 8 * 24 + 18)) ] || fail "envelope size"

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
# The secret may not share the envelope's destination, even through stdout.
expect_exit 2 "$CS" encrypt -q -m 5 -i msg -o env3 --secret-out ./env3
set +e; "$CS" encrypt -q -m 5 -i msg -o - --secret-out same > same 2>/dev/null; code=$?; set -e
[ "$code" = 2 ] || fail "encrypt with stdout on the secret file exited $code, wanted 2"
[ ! -s same ] || fail "encrypt wrote to the file that is both envelope and secret"

# Several puzzles solved in parallel.
"$CS" encrypt -q -n 2 -m 50000 -i msg -o p1 --secret-out s1
"$CS" encrypt -q -n 2 -m 50000 -i msg -o p2 --secret-out s2
"$CS" solve -q p1 p2 > keys
[ "$(sed -n 1p keys | cut -d' ' -f1)" = "$("$CS" key s1)" ] || fail "parallel solve 1"
[ "$(sed -n 2p keys | cut -d' ' -f1)" = "$("$CS" key s2)" ] || fail "parallel solve 2"

# A malformed puzzle among several: the others' keys are still printed.
cp p2 p2.bad && flip p2.bad $((8 + 68 + 16))
set +e; "$CS" solve -q p1 p2.bad > keys 2>/dev/null; code=$?; set -e
[ "$code" = 1 ] || fail "solve with a malformed puzzle exited $code, wanted 1"
[ "$(cut -d' ' -f1 keys)" = "$("$CS" key s1)" ] || fail "key lost when another puzzle was malformed"
[ ! -e p1.ckpt ] && [ ! -e p2.bad.ckpt ] || fail "checkpoint left after a finished solve"

# A real SIGINT stops a solve and saves a checkpoint. The puzzle's m is
# patched to 2^40, so the solve cannot finish before the signal arrives. The
# signal is sent once the solver says its handler is installed, and a
# watchdog kills the solver if the signal is lost.
cp p1 endless && poke endless $((8 + 12)) '>Q' $((1 << 40))
rm -f ready
LEANSEAL_TEST_READY=ready "$CS" solve -q endless > /dev/null 2>&1 &
PID=$!
python3 -c 'import os, sys, time
time.sleep(60)
try: os.kill(int(sys.argv[1]), 9)
except ProcessLookupError: pass' $PID &
WATCHDOG=$!
trap 'kill $WATCHDOG $PID 2>/dev/null; rm -rf "$T"' EXIT
tries=0
until [ -e ready ]; do
  tries=$((tries + 1))
  [ $tries -le 600 ] || fail "the solve never installed its signal handler"
  sleep 0.1
done
kill -INT $PID || fail "could not signal the solve"
set +e; wait $PID; code=$?; set -e
kill $WATCHDOG 2>/dev/null || true
wait $WATCHDOG 2>/dev/null || true
trap 'rm -rf "$T"' EXIT
rm -f ready
[ "$code" = 130 ] || fail "interrupted solve exited $code, wanted 130"
[ -s endless.ckpt ] || fail "no checkpoint after SIGINT"
rm -f endless endless.ckpt

# Stop a solve partway, then resume it from the checkpoint. The test hook
# stops the solve after 2^21 of its 2^24 steps, as an interrupt would.
"$CS" encrypt -q -n 4 -m 2^22 -i msg -o long --secret-out slong
set +e; LEANSEAL_TEST_STOP_AFTER=2^21 "$CS" solve -q long > /dev/null 2>&1; code=$?; set -e
[ "$code" = 130 ] || fail "stopped solve exited $code, wanted 130"
[ -s long.ckpt ] || fail "no checkpoint after stop"
"$CS" info long.ckpt | grep -q checkpoint || fail "checkpoint info"
cp long.ckpt bad.ckpt && printf '\002' | dd of=bad.ckpt bs=1 seek=4 conv=notrunc 2>/dev/null
expect_exit 1 "$CS" info bad.ckpt
# Position (4097, 2^48) fits each field's range but no puzzle with n*m <= 2^60.
cp long.ckpt bad.ckpt && poke bad.ckpt 40 '>IQ' 4097 $((1 << 48))
expect_exit 1 "$CS" info bad.ckpt
# The plaintext output may not be the checkpoint file.
expect_exit 2 "$CS" open long --solve -q -o long.ckpt
[ -s long.ckpt ] || fail "open removed the checkpoint it was asked to write over"
# Nor may stdout, here appended to the checkpoint so that it stays valid.
cp long.ckpt saved.ckpt
set +e; "$CS" open long --solve -q >> long.ckpt 2>/dev/null; code=$?; set -e
[ "$code" = 2 ] || fail "open with stdout on the checkpoint exited $code, wanted 2"
cmp -s long.ckpt saved.ckpt || fail "open changed the checkpoint that stdout pointed at"
# A damaged checkpoint state is not authenticated: the solve fails the key
# check, and the message must point at the checkpoint, not at the puzzle.
cp long dmg && cp long.ckpt dmg.ckpt
printf '\377' | dd of=dmg.ckpt bs=1 seek=60 conv=notrunc 2>/dev/null
set +e; "$CS" solve -q dmg > /dev/null 2> log; code=$?; set -e
[ "$code" = 1 ] || fail "solve from a damaged checkpoint exited $code, wanted 1"
grep -q "checkpoint may be damaged" log || fail "damaged checkpoint reported as a malformed puzzle"
"$CS" solve -q --no-checkpoint dmg > /dev/null || fail "solve from the start after a damaged checkpoint"
rm -f dmg dmg.ckpt
"$CS" solve long > keys 2> log
grep -q resuming log || fail "solve did not resume"
[ "$(cut -d' ' -f1 keys)" = "$("$CS" key slong)" ] || fail "resumed solve key"
[ ! -e long.ckpt ] || fail "checkpoint left after resumed solve"

# A checkpoint of another puzzle is refused.
set +e; LEANSEAL_TEST_STOP_AFTER=2^21 "$CS" solve -q long > /dev/null 2>&1; set -e
mv long.ckpt p1.ckpt
expect_exit 1 "$CS" solve -q p1
rm -f p1.ckpt

# A huge but finite step time is converted without overflow: 1e300 s at
# 1e307 ns per step over 64 chains is m = ceil(100 / 64) = 2.
"$CS" gen -n 64 -d 1e300 --step-ns 1e307 -o big.sec 2> log
grep -q "m = 2 steps" log || fail "delay with a huge step time: $(head -1 log)"
# Tiny times are converted without underflow. These are the stored values of
# the decimals: 5e-324 s at 3e-315 ns per step is m = ceil(1.647) = 2, and
# 1e-320 s at 1e-314 ns per step is m = ceil(999.989) = 1000.
"$CS" gen -n 1 -d 5e-324 --step-ns 3e-315 -o tiny.sec 2> log
grep -q "m = 2 steps" log || fail "delay with a tiny step time: $(head -1 log)"
"$CS" gen -n 1 -d 1e-320 --step-ns 1e-314 -o tiny.sec 2> log
grep -q "m = 1000 steps" log || fail "delay with tiny times: $(head -1 log)"

# On a case-insensitive filesystem, an output named like the checkpoint in
# another case is the checkpoint file. The solve must keep its output.
touch casetest
if [ -e CASETEST ]; then
  "$CS" encrypt -q -n 2 -m 1000 -i msg -o alias.env
  "$CS" open alias.env --solve -q -o ALIAS.ENV.CKPT
  cmp -s msg ALIAS.ENV.CKPT || fail "open removed its own output"
fi
rm -f casetest

echo "cli tests: ok"
