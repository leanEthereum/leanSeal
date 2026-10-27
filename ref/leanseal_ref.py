#!/usr/bin/env python3
"""Independent, deliberately straightforward leanseal v1 reference.

All format rules and cryptographic formulas come from SPEC.md. Decoders parse
fields directly; they never use an encoder to decide whether bytes are valid.
Only the Python standard library is required (Python 3.11 or newer).
"""

import argparse
import hashlib
import hmac
import json
import os


MAX_CHAINS = 1 << 20
MAX_STEPS = 1 << 48
MAX_WORK = 1 << 60
MAX_MESSAGE = 1 << 24


class Invalid(ValueError):
    """Malformed encoding, invalid parameters, or failed authentication."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def parameters(n, m, b):
    require(type(n) is int and 1 <= n <= MAX_CHAINS, "n out of range")
    require(type(m) is int and 1 <= m <= MAX_STEPS, "m out of range")
    require(n * m <= MAX_WORK, "n*m out of range")
    require(type(b) is int and 1 <= b <= 32, "b out of range")


def fixed(value, length, name):
    require(isinstance(value, bytes) and len(value) == length,
            f"{name} must be {length} bytes")


def th(label, value):
    label = label.encode("ascii")
    require(len(label) <= 255, "hash label too long")
    return hashlib.sha256(bytes([len(label)]) + label + value).digest()


def mac(key, value):
    return hmac.digest(key, value, "sha256")


def xor(a, b):
    require(len(a) == len(b), "XOR length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def context(n, m, b, salt):
    parameters(n, m, b)
    fixed(salt, 16, "salt")
    return b"\x01" + bytes([b]) + b"\0\0" + n.to_bytes(4, "big") + m.to_bytes(8, "big") + salt


def start(ctx, i, link):
    return th("leanseal/v1/start", ctx + i.to_bytes(4, "big") + link)


def chain(state, salt, i, steps):
    suffix = salt + i.to_bytes(4, "big")
    for _ in range(steps):
        state = hashlib.sha256(state + suffix).digest()
    return state


def mask(ctx, end):
    return th("leanseal/v1/mask", ctx + end)


def absorb(acc, end):
    return th("leanseal/v1/acc", acc + end)


def derive_key(ctx, ends):
    """K = TH(key, ctx || a_n), where a_0 = ctx and a_i = TH(acc, a_(i-1) || y_i)."""
    acc = ctx
    accs = []
    for end in ends:
        acc = absorb(acc, end)
        accs.append(acc)
    return th("leanseal/v1/key", ctx + acc), accs


def commitment(ctx, key):
    return th("leanseal/v1/commit", ctx + key)


def check_key(puzzle, key):
    fixed(key, 32, "key")
    require(hmac.compare_digest(commitment(puzzle["ctx"], key), puzzle["commit"]),
            "key commitment mismatch")


# Encoders are intentionally separate from all parsing below.
def encode_puzzle(n, m, b, salt, commit, links):
    ctx = context(n, m, b, salt)
    fixed(commit, 32, "commitment")
    require(len(links) == n, "wrong number of encoded links")
    for link in links:
        fixed(link, b, "link")
    return b"LSPZ" + ctx + commit + b"".join(links)


def generate(n, m, b, salt, links):
    """Generate deterministically from explicit random inputs (section 4)."""
    ctx = context(n, m, b, salt)
    require(len(links) == n, "wrong number of input links")
    for link in links:
        fixed(link, b, "input link")
    starts = [start(ctx, i, link) for i, link in enumerate(links, 1)]
    # Serial computation keeps this reference simple; chain independence is
    # preserved even though section 4 recommends parallel generation.
    ends = [chain(s, salt, i, m) for i, s in enumerate(starts, 1)]
    key, accs = derive_key(ctx, ends)
    commit = commitment(ctx, key)
    hidden = [links[0]] + [xor(mask(ctx, ends[i])[:b], links[i + 1]) for i in range(n - 1)]
    raw = encode_puzzle(n, m, b, salt, commit, hidden)
    return {"start": starts, "y": ends, "acc": accs, "key": key, "commit": commit,
            "puzzle": raw, "puzzle_id": puzzle_id(raw)}


def puzzle_id(raw):
    return th("leanseal/v1/puzzle-id", raw)


def encode_secret(raw_puzzle, key):
    fixed(key, 32, "key")
    return b"LSSK\x01\0\0\0" + key + raw_puzzle


def encode_checkpoint(raw_puzzle, i, j, state, acc):
    fixed(state, 32, "checkpoint state")
    fixed(acc, 32, "checkpoint accumulator")
    return (b"LSCK\x01\0\0\0" + puzzle_id(raw_puzzle)
            + i.to_bytes(4, "big") + j.to_bytes(8, "big") + state + acc)


def crypt(message, key, nonce):
    """The same XOR operation encrypts and decrypts."""
    k_enc = th("leanseal/v1/enc", key + nonce)
    output = bytearray()
    for offset in range(0, len(message), 32):
        block = mac(k_enc, (offset // 32).to_bytes(8, "big"))
        part = message[offset:offset + 32]
        output.extend(xor(part, block[:len(part)]))
    return bytes(output)


def encode_envelope(raw_puzzle, key, nonce, message):
    fixed(key, 32, "key")
    fixed(nonce, 16, "nonce")
    require(len(message) <= MAX_MESSAGE, "message too long")
    ciphertext = crypt(message, key, nonce)
    prefix = (b"LSEN\x01\0\0\0" + raw_puzzle + nonce
              + len(ciphertext).to_bytes(4, "big") + ciphertext)
    k_mac = th("leanseal/v1/mac", key + nonce)
    return prefix + mac(k_mac, prefix)


# Decoders inspect original bytes, including bytes used by MACs and puzzle IDs.
def header(data, magic, reserved_start=5):
    require(len(data) >= 8, "truncated header")
    require(data[:4] == magic, "bad magic")
    require(data[4] == 1, "bad version")
    require(not any(data[reserved_start:8]), "nonzero reserved bytes")


def parse_puzzle_at(data, offset):
    """Parse one embedded puzzle, returning its fields and ending offset.

    Enclosing decoders, or decode_puzzle, enforce the entire input length.
    """
    raw = data[offset:]
    header(raw, b"LSPZ", 6)
    require(len(raw) >= 68, "truncated puzzle header")
    b = raw[5]
    n = int.from_bytes(raw[8:12], "big")
    m = int.from_bytes(raw[12:20], "big")
    parameters(n, m, b)
    length = 68 + n * b
    require(len(raw) >= length, "truncated puzzle links")
    raw = raw[:length]
    puzzle = {"n": n, "m": m, "b": b, "salt": raw[20:36],
              "ctx": raw[4:36], "commit": raw[36:68],
              "links": [raw[k:k + b] for k in range(68, length, b)],
              "raw": raw}
    return puzzle, offset + length


def decode_puzzle(data):
    puzzle, end = parse_puzzle_at(data, 0)
    require(end == len(data), "trailing puzzle bytes")
    return puzzle


def decode_envelope(data):
    header(data, b"LSEN")
    puzzle, p = parse_puzzle_at(data, 8)
    require(len(data) >= p + 52, "truncated envelope")
    length = int.from_bytes(data[p + 16:p + 20], "big")
    require(length <= MAX_MESSAGE, "ciphertext length out of range")
    require(len(data) == p + 52 + length, "incorrect envelope length")
    return {"puzzle": puzzle, "nonce": data[p:p + 16],
            "ciphertext": data[p + 20:p + 20 + length],
            "tag": data[p + 20 + length:], "authenticated": data[:-32]}


def decode_secret(data):
    header(data, b"LSSK")
    require(len(data) >= 40, "truncated secret key")
    key = data[8:40]
    puzzle, end = parse_puzzle_at(data, 40)
    require(len(data) == end, "trailing secret bytes")
    check_key(puzzle, key)
    return {"key": key, "puzzle": puzzle}


def checkpoint_position(puzzle, i, j):
    require(type(i) is int and 1 <= i <= puzzle["n"], "checkpoint i out of range")
    require(type(j) is int and 0 <= j <= puzzle["m"], "checkpoint j out of range")


def decode_checkpoint(data, puzzle):
    header(data, b"LSCK")
    require(len(data) == 116, "incorrect checkpoint length")
    require(hmac.compare_digest(data[8:40], puzzle_id(puzzle["raw"])),
            "checkpoint puzzle id mismatch")
    i = int.from_bytes(data[40:44], "big")
    j = int.from_bytes(data[44:52], "big")
    checkpoint_position(puzzle, i, j)
    # SPEC: Section 6.4 specifies ID/position checks but no authentication or
    # recomputation of the stored state and accumulator. Decode them literally;
    # a resumed solve still MUST pass the final commitment check (section 5).
    return {"puzzle_id": data[8:40], "i": i, "j": j, "state": data[52:84],
            "acc": data[84:116]}


def solve_puzzle(puzzle, checkpoint=None):
    if checkpoint is None:
        i, j = 1, 0
        state = start(puzzle["ctx"], i, puzzle["links"][0])
        acc = puzzle["ctx"]
    else:
        require(hmac.compare_digest(checkpoint["puzzle_id"], puzzle_id(puzzle["raw"])),
                "checkpoint puzzle id mismatch")
        i, j, state = checkpoint["i"], checkpoint["j"], checkpoint["state"]
        acc = checkpoint["acc"]
        checkpoint_position(puzzle, i, j)
        fixed(state, 32, "checkpoint state")
        fixed(acc, 32, "checkpoint accumulator")
    while True:
        y = chain(state, puzzle["salt"], i, puzzle["m"] - j)
        acc = absorb(acc, y)
        if i == puzzle["n"]:
            break
        link = xor(mask(puzzle["ctx"], y)[:puzzle["b"]], puzzle["links"][i])
        i, j = i + 1, 0
        state = start(puzzle["ctx"], i, link)
    key = th("leanseal/v1/key", puzzle["ctx"] + acc)
    check_key(puzzle, key)
    return key


def open_envelope(envelope, key):
    check_key(envelope["puzzle"], key)
    k_mac = th("leanseal/v1/mac", key + envelope["nonce"])
    require(hmac.compare_digest(mac(k_mac, envelope["authenticated"]), envelope["tag"]),
            "envelope authentication failed")
    # No plaintext is produced before BOTH commitment and tag checks succeed.
    return crypt(envelope["ciphertext"], key, envelope["nonce"])


def unhex(value):
    require(isinstance(value, str) and len(value) % 2 == 0
            and all(c in "0123456789abcdef" for c in value),
            "expected lowercase hexadecimal bytes")
    return bytes.fromhex(value)


def read_file(path):
    with open(path, "rb") as stream:
        return stream.read()


def write_file(path, value, private=False):
    """Write through a new temporary file, then rename it over path.

    Private files (secrets) are created with mode 0600. Writing a fresh file
    never follows a symlink at path or keeps an existing file's permissions.
    """
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def emit(value, fd=1):
    """Write bytes completely, even if an OS write is partial."""
    value = memoryview(value)
    while value:
        count = os.write(fd, value)
        if count == 0:
            raise OSError("zero-length output write")
        value = value[count:]


def check_vectors(path):
    with open(path, encoding="utf-8") as stream:
        vectors = json.load(stream)
    require(isinstance(vectors, dict), "vectors must be an object")
    cases, invalid = vectors["cases"], vectors["invalid"]
    require(isinstance(cases, list) and isinstance(invalid, list), "expected vector lists")
    failures = 0

    def fail(where, reason):
        nonlocal failures
        failures += 1
        print(f"FAIL {where}: {reason}")

    def equal(where, actual, expected):
        if isinstance(actual, bytes) and isinstance(expected, bytes):
            matches = hmac.compare_digest(actual, expected)
        elif isinstance(actual, str) and isinstance(expected, str):
            matches = hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8"))
        else:
            matches = actual == expected
        if not matches:
            fail(where, "mismatch")

    def attempt(where, operation):
        try:
            return operation()
        except (ValueError, KeyError, TypeError, IndexError, OverflowError) as error:
            fail(where, str(error))
            return None

    def check_case(index, case):
        where = f"cases[{index}]"
        n, m, b = case["n"], case["m"], case["b"]
        salt = unhex(case["salt"])
        links = [unhex(x) for x in case["x"]]
        nonce, message = unhex(case["nonce"]), unhex(case["message"])
        derived = generate(n, m, b, salt, links)
        derived["secret"] = encode_secret(derived["puzzle"], derived["key"])
        derived["envelope"] = encode_envelope(derived["puzzle"], derived["key"], nonce, message)
        for field, value in derived.items():
            expected = [v.hex() for v in value] if isinstance(value, list) else value.hex()
            equal(f"{where}.{field}", expected, case[field])

        # Decode vector bytes, not our newly encoded output. Compare every
        # decoded field to independently computed inputs/values as well.
        def verify_puzzle(puzzle, label):
            for field, expected in (("n", n), ("m", m), ("b", b), ("salt", salt),
                                    ("commit", derived["commit"]),
                                    ("ctx", context(n, m, b, salt)),
                                    ("raw", derived["puzzle"])):
                equal(f"{label}.{field}", puzzle[field], expected)
            expected_links = [links[0]] + [xor(mask(context(n, m, b, salt), derived["y"][i])[:b], links[i + 1])
                                            for i in range(n - 1)]
            equal(f"{label}.links", puzzle["links"], expected_links)

        puzzle = attempt(f"{where}.decode puzzle", lambda: decode_puzzle(unhex(case["puzzle"])))
        if puzzle is not None:
            verify_puzzle(puzzle, f"{where}.decoded puzzle")
            solved = attempt(f"{where}.solve", lambda: solve_puzzle(puzzle))
            equal(f"{where}.solved key", solved, derived["key"])

        secret = attempt(f"{where}.decode secret", lambda: decode_secret(unhex(case["secret"])))
        if secret is not None:
            equal(f"{where}.decoded secret key", secret["key"], derived["key"])
            verify_puzzle(secret["puzzle"], f"{where}.decoded secret puzzle")

        envelope = attempt(f"{where}.decode envelope", lambda: decode_envelope(unhex(case["envelope"])))
        if envelope is not None:
            verify_puzzle(envelope["puzzle"], f"{where}.decoded envelope puzzle")
            equal(f"{where}.decoded nonce", envelope["nonce"], nonce)
            key = attempt(f"{where}.solve envelope puzzle", lambda: solve_puzzle(envelope["puzzle"]))
            if key is not None:
                equal(f"{where}.envelope solved key", key, derived["key"])
                plaintext = attempt(f"{where}.open", lambda: open_envelope(envelope, key))
                equal(f"{where}.opened message", plaintext, message)

        cp = case["checkpoint"]
        # Validate position against the input parameters, independently of any
        # decoded checkpoint, before indexing the independently computed starts.
        checkpoint_position({"n": n, "m": m}, cp["i"], cp["j"])
        state = chain(derived["start"][cp["i"] - 1], salt, cp["i"], cp["j"])
        equal(f"{where}.checkpoint.state", state.hex(), cp["state"])
        acc = derived["acc"][cp["i"] - 2] if cp["i"] > 1 else context(n, m, b, salt)
        equal(f"{where}.checkpoint.acc", acc.hex(), cp["acc"])
        raw_cp = encode_checkpoint(derived["puzzle"], cp["i"], cp["j"], state, acc)
        equal(f"{where}.checkpoint.hex", raw_cp.hex(), cp["hex"])
        if puzzle is not None:
            decoded = attempt(f"{where}.decode checkpoint",
                              lambda: decode_checkpoint(unhex(cp["hex"]), puzzle))
            if decoded is not None:
                for field, expected in (("i", cp["i"]), ("j", cp["j"]),
                                        ("state", state), ("acc", acc),
                                        ("puzzle_id", derived["puzzle_id"])):
                    equal(f"{where}.decoded checkpoint.{field}", decoded[field], expected)
                resumed = attempt(f"{where}.resume", lambda: solve_puzzle(puzzle, decoded))
                equal(f"{where}.resumed key", resumed, derived["key"])

    for index, case in enumerate(cases):
        attempt(f"cases[{index}]", lambda: check_case(index, case))

    for index, entry in enumerate(invalid):
        where = f"invalid[{index}]"
        # Malformed test metadata is a checker failure, never evidence that a
        # format decoder rejected the supplied byte string.
        def prepare():
            raw = unhex(entry["hex"])
            kind, case_index = entry["kind"], entry["case"]
            require(kind in ("puzzle", "envelope", "secret", "checkpoint"), "unknown invalid kind")
            require(type(case_index) is int and 0 <= case_index < len(cases), "invalid case index")
            case = cases[case_index]
            key = unhex(case["key"])
            puzzle = decode_puzzle(unhex(case["puzzle"]))
            return raw, kind, key, puzzle

        prepared = attempt(where, prepare)
        if prepared is None:
            continue
        raw, kind, key, puzzle = prepared
        try:
            if kind == "puzzle":
                decode_puzzle(raw)
            elif kind == "envelope":
                open_envelope(decode_envelope(raw), key)
            elif kind == "secret":
                decode_secret(raw)
            else:
                decode_checkpoint(raw, puzzle)
        except Invalid:
            continue
        fail(where, f"accepted {kind} ({entry.get('why', '')})")

    print(f"{len(cases)} cases, {len(invalid)} invalid inputs: {failures} failure(s)")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    checker = commands.add_parser("check", help="verify deterministic JSON vectors")
    checker.add_argument("file")
    encrypt = commands.add_parser("encrypt", help="generate a puzzle and seal a message")
    encrypt.add_argument("--chains", type=int, required=True)
    encrypt.add_argument("--steps", type=int, required=True)
    encrypt.add_argument("--link-bytes", type=int, required=True)
    encrypt.add_argument("--in", dest="input", required=True)
    encrypt.add_argument("--out", dest="output", required=True)
    encrypt.add_argument("--secret-out")
    solver = commands.add_parser("solve", help="solve an envelope or bare puzzle")
    solver.add_argument("file")
    key_parser = commands.add_parser("key", help="check and reveal a secret's key")
    key_parser.add_argument("file")
    opener = commands.add_parser("open", help="authenticate and open an envelope")
    opener.add_argument("file")
    opener.add_argument("--key", required=True)
    args = parser.parse_args()
    try:
        if args.command == "check":
            return check_vectors(args.file)
        if args.command == "encrypt":
            parameters(args.chains, args.steps, args.link_bytes)
            with open(args.input, "rb") as stream:
                message = stream.read(MAX_MESSAGE + 1)
            require(len(message) <= MAX_MESSAGE, "message too long")
            generated = generate(args.chains, args.steps, args.link_bytes, os.urandom(16),
                                 [os.urandom(args.link_bytes) for _ in range(args.chains)])
            envelope = encode_envelope(generated["puzzle"], generated["key"], os.urandom(16), message)
            write_file(args.output, envelope)
            if args.secret_out is not None:
                write_file(args.secret_out, encode_secret(generated["puzzle"], generated["key"]), private=True)
        elif args.command == "solve":
            raw = read_file(args.file)
            puzzle = decode_envelope(raw)["puzzle"] if raw[:4] == b"LSEN" else decode_puzzle(raw)
            emit(solve_puzzle(puzzle).hex().encode("ascii") + b"\n")
        elif args.command == "key":
            secret = decode_secret(read_file(args.file))
            emit(secret["key"].hex().encode("ascii") + b"\n")
        elif args.command == "open":
            require(len(args.key) == 64 and all(c in "0123456789abcdefABCDEF" for c in args.key),
                    "key must be 64 hexadecimal digits")
            key = bytes.fromhex(args.key)
            fixed(key, 32, "key")
            envelope = decode_envelope(read_file(args.file))
            plaintext = open_envelope(envelope, key)
            emit(plaintext)
        return 0
    except (ValueError, OSError, KeyError, TypeError, IndexError, OverflowError) as error:
        emit(f"leanseal: {error}\n".encode("utf-8", "replace"), 2)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
