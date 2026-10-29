#!/bin/sh
# Cross-check leanseal against the independent Python reference (ref/), both
# ways: each opens envelopes the other made. Usage: sh tests/cross.sh [PATH_TO_LEANSEAL]
set -eu
set -- "${1:-./target/release/leanseal}"
CS=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
PY="python3 $(cd "$(dirname "$0")/.." && pwd)/ref/leanseal_ref.py"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
cd "$T"
fail() { echo "cross test failed: $*" >&2; exit 1; }
head -c 1000 /dev/urandom > msg

for b in 1 12 24 32; do
  # Python builds, leanseal solves and opens.
  $PY encrypt --chains 5 --steps 400 --link-bytes $b --in msg --out py.env --secret-out py.sec
  [ "$("$CS" solve -q --no-checkpoint py.env | cut -d' ' -f1)" = "$($PY key py.sec)" ] || fail "leanseal solve of a Python envelope, b=$b"
  "$CS" open py.env -s py.sec -o out && cmp msg out || fail "leanseal open of a Python envelope, b=$b"
  # leanseal builds, Python solves and opens.
  "$CS" encrypt -q -n 5 -m 400 -b $b -i msg -o c.env --secret-out c.sec
  KEY=$($PY solve c.env)
  [ "$KEY" = "$("$CS" key c.sec)" ] || fail "Python solve of a leanseal envelope, b=$b"
  $PY open c.env --key "$KEY" > out && cmp msg out || fail "Python open of a leanseal envelope, b=$b"
  [ "$($PY key c.sec)" = "$KEY" ] || fail "Python reads a leanseal secret, b=$b"
done
# The Python CLI refuses to write the secret over the envelope.
if $PY encrypt --chains 2 --steps 10 --link-bytes 24 --in msg --out same --secret-out ./same 2> log; then
  fail "Python wrote the secret over the envelope"
fi
grep -q "the secret file is the envelope file" log || fail "Python refused the secret path for another reason"
[ ! -e same ] || fail "Python left a file after refusing the secret path"
# On a case-insensitive file system, two new names can name one file.
: > case-probe
if [ -e CASE-PROBE ]; then
  if $PY encrypt --chains 2 --steps 10 --link-bytes 24 --in msg --out alias.env --secret-out ALIAS.env 2> log; then
    fail "Python wrote the secret over the envelope through a case alias"
  fi
  grep -q "the secret file is the envelope file" log || fail "Python refused the case alias for another reason"
  [ "$(head -c 4 alias.env)" = LSEN ] || fail "Python replaced the envelope through a case alias"
fi
echo "cross tests: ok"
