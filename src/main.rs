#![deny(unsafe_code)]
use leanseal::{backend::Backend, benchmark, runtime::*, *};
use std::{
    ffi::{OsStr, OsString},
    io::{self, IsTerminal, Write},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
    sync::{atomic::AtomicBool, Arc},
    time::Instant,
};
const USAGE:&str="usage: leanseal <command> [options]\n\nSender:\n  gen -o SECRET (-m STEPS | -d DELAY) [-n CHAINS] [-b BYTES]\n        build a puzzle in advance and keep it, with its key, in SECRET\n  encrypt -o ENVELOPE (-s SECRET | -m STEPS | -d DELAY) [-i MESSAGE] [--secret-out FILE]\n        encrypt MESSAGE (default stdin) under a stored or freshly built puzzle\n  key SECRET            print the key, to open an envelope early\n\nReceiver:\n  solve FILE...         solve puzzles (envelopes or bare puzzles), one thread each,\n                        saving progress to FILE.ckpt; print each key\n  open ENVELOPE (-k KEY | -s SECRET | --solve) [-o MESSAGE]\n        check the key and the tag, then write the message (default stdout).\n        KEY is 64 hex digits, a file holding them, or - for stdin. Other local\n        users can read command-line arguments, so pass an unpublished key in a\n        file or on stdin\n  info FILE             describe a puzzle, envelope, secret or checkpoint\n\nMeasurement:\n  bench [latency | throughput | build | attack | all]\n  selftest              check every backend against plain SHA-256, then a round trip\n  vectors               print the test vectors as JSON\n\nPuzzle options:\n  -n, --chains N        chains (default 16)\n  -m, --steps M         hash steps per chain, e.g. 2^28\n  -d, --delay T         or: choose m for a delay of T (90, 10m, 2h) ...\n      --step-ns L       ... against a solver taking L ns per step (default: this machine)\n  -b, --link-bytes B    link width (default 24; see SPEC.md section 8)\n  -j, --threads J       build threads (default: all cores)\n  -q, --quiet\n\nBackends: set LEANSEAL_BACKEND=portable|armv8-sha2|x86-sha-ni to override.\n";

enum CliError {
    Message(String, i32),
    Usage(Option<String>),
    Failure(Failure),
}
type CliResult<T> = std::result::Result<T, CliError>;
impl From<Failure> for CliError {
    fn from(e: Failure) -> Self {
        Self::Failure(e)
    }
}
fn usage(msg: &str) -> CliError {
    CliError::Usage(Some(msg.into()))
}
fn code(what: impl AsRef<OsStr>, e: Error) -> CliError {
    Failure::code(what, e).into()
}
fn output(s: &str) -> CliResult<()> {
    let mut o = io::stdout().lock();
    o.write_all(s.as_bytes())
        .and_then(|_| o.flush())
        .map_err(|e| Failure::io("stdout", e))?;
    Ok(())
}
// Parse strtod's finite numeric syntax without calling into libc.
fn float_prefix(text: &str) -> CliResult<(f64, &str)> {
    let bad = || CliError::Usage(None);
    let s = text.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let bytes = s.as_bytes();
    let mut at = 0;
    let mut negative = false;
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        negative = bytes[0] == b'-';
        at += 1;
    }
    if bytes
        .get(at..at + 2)
        .is_some_and(|p| p == b"0x" || p == b"0X")
    {
        at += 2;
        let mut digits = Vec::new();
        let mut fractional = 0i64;
        let mut dot = false;
        while let Some(&b) = bytes.get(at) {
            if b == b'.' && !dot {
                dot = true;
                at += 1;
                continue;
            }
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => break,
            };
            digits.push(d);
            if dot {
                fractional += 1;
            }
            at += 1;
        }
        if digits.is_empty() {
            return Err(bad());
        }
        let mut exponent = 0i64;
        if matches!(bytes.get(at), Some(b'p' | b'P')) {
            let marker = at;
            at += 1;
            let mut neg = false;
            if matches!(bytes.get(at), Some(b'+' | b'-')) {
                neg = bytes[at] == b'-';
                at += 1;
            }
            let start = at;
            while let Some(b @ b'0'..=b'9') = bytes.get(at) {
                exponent = exponent
                    .saturating_mul(10)
                    .saturating_add(i64::from(b - b'0'));
                at += 1;
            }
            if at == start {
                at = marker;
                exponent = 0;
            } else if neg {
                exponent = -exponent;
            }
        }
        let mut top = 0u64;
        let mut count = 0i64;
        let mut sticky = false;
        for d in digits {
            for bit in (0..4).rev() {
                let b = (d >> bit) & 1;
                if count == 0 && b == 0 {
                    continue;
                }
                if count < 64 {
                    top = (top << 1) | u64::from(b);
                } else {
                    sticky |= b != 0;
                }
                count += 1;
            }
        }
        let sign = if negative { 1u64 << 63 } else { 0 };
        if count == 0 {
            return Ok((f64::from_bits(sign), &s[at..]));
        }
        let e = (count - 1).saturating_add(exponent.saturating_sub(fractional * 4));
        if e > 1023 {
            return Ok((
                if negative {
                    f64::NEG_INFINITY
                } else {
                    f64::INFINITY
                },
                &s[at..],
            ));
        }
        if e < -1075 {
            return Ok((f64::from_bits(sign), &s[at..]));
        }
        if count < 64 {
            top <<= 64 - count;
        }
        let keep = if e >= -1022 { 53 } else { (e + 1075) as u32 };
        let mut significand = if keep == 0 { 0 } else { top >> (64 - keep) };
        let guard = (top >> (63 - keep)) & 1;
        let rest = sticky || (top & ((1u64 << (63 - keep)) - 1)) != 0;
        if guard != 0 && (rest || significand & 1 != 0) {
            significand += 1;
        }
        let bits = if e < -1022 {
            significand
        } else {
            let mut e = e;
            if significand == 1u64 << 53 {
                significand >>= 1;
                e += 1;
            }
            if e > 1023 {
                0x7ff0000000000000
            } else {
                ((e + 1023) as u64) << 52 | (significand & ((1u64 << 52) - 1))
            }
        };
        return Ok((f64::from_bits(sign | bits), &s[at..]));
    }
    let start = at;
    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    let mut digits = at - start;
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        digits += at - start;
    }
    if digits == 0 {
        return Err(bad());
    }
    if matches!(bytes.get(at), Some(b'e' | b'E')) {
        let marker = at;
        at += 1;
        if matches!(bytes.get(at), Some(b'+' | b'-')) {
            at += 1;
        }
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if start == at {
            at = marker;
        }
    }
    let value = s[..at].parse::<f64>().map_err(|_| bad())?;
    Ok((value, &s[at..]))
}
fn float(s: &str) -> CliResult<f64> {
    let (x, rest) = float_prefix(s)?;
    if rest.is_empty() {
        Ok(x)
    } else {
        Err(CliError::Usage(None))
    }
}
fn number(s: &str) -> CliResult<u64> {
    let bad = || CliError::Usage(None);
    if let Some(e) = s.strip_prefix("2^") {
        let e = e.trim_start_matches(|c: char| c.is_ascii_whitespace());
        let e = if e == "-0" {
            0
        } else {
            e.parse::<u32>().map_err(|_| bad())?
        };
        return if e <= 63 { Ok(1 << e) } else { Err(bad()) };
    }
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().map_err(|_| bad());
    }
    let f = float(s)?;
    if !f.is_finite() || !(0. ..18446744073709551616.).contains(&f) || f.floor() != f {
        return Err(bad());
    }
    Ok(f as u64)
}
fn positive(s: &str) -> CliResult<f64> {
    let x = float(s)?;
    if x > 0. && x.is_finite() {
        Ok(x)
    } else {
        Err(CliError::Usage(None))
    }
}
fn seconds(s: &str) -> CliResult<f64> {
    let (d, suffix) = float_prefix(s)?;
    if !(d > 0. && d.is_finite()) {
        return Err(CliError::Usage(None));
    }
    let x = match suffix {
        "" | "s" => d,
        "ms" => d / 1e3,
        "m" | "min" => d * 60.,
        "h" => d * 3600.,
        "d" => d * 86400.,
        _ => return Err(CliError::Usage(None)),
    };
    if x.is_finite() {
        Ok(x)
    } else {
        Err(CliError::Usage(None))
    }
}
#[derive(Clone, Copy)]
struct Opt {
    name: &'static str,
    short: char,
    value: bool,
}
const PARAM: &[Opt] = &[
    Opt {
        name: "chains",
        short: 'n',
        value: true,
    },
    Opt {
        name: "steps",
        short: 'm',
        value: true,
    },
    Opt {
        name: "delay",
        short: 'd',
        value: true,
    },
    Opt {
        name: "step-ns",
        short: 'L',
        value: true,
    },
    Opt {
        name: "link-bytes",
        short: 'b',
        value: true,
    },
    Opt {
        name: "threads",
        short: 'j',
        value: true,
    },
    Opt {
        name: "quiet",
        short: 'q',
        value: false,
    },
];
fn opt(name: &'static str, short: char, value: bool) -> Opt {
    Opt { name, short, value }
}
struct Args {
    opts: Vec<(char, OsString)>,
    pos: Vec<OsString>,
}
fn text(value: &OsStr) -> CliResult<&str> {
    value
        .to_str()
        .ok_or_else(|| usage("option value is not valid UTF-8"))
}
fn parse(args: &[OsString], spec: &[Opt], shorts: &str) -> CliResult<Args> {
    let mut r = Args {
        opts: Vec::new(),
        pos: Vec::new(),
    };
    let mut i = 0;
    let mut end = false;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        let bytes = a.as_bytes();
        if end || bytes == b"-" || !bytes.starts_with(b"-") {
            r.pos.push(a.clone());
            continue;
        }
        if bytes == b"--" {
            end = true;
            continue;
        }
        if let Some(long) = bytes.strip_prefix(b"--") {
            let split = long.iter().position(|b| *b == b'=');
            let (name, value) =
                split.map_or((long, None), |at| (&long[..at], Some(&long[at + 1..])));
            let name = text(OsStr::from_bytes(name))?;
            let exact: Vec<_> = spec.iter().filter(|s| s.name == name).collect();
            let candidates: Vec<_> = if exact.is_empty() {
                spec.iter().filter(|s| s.name.starts_with(name)).collect()
            } else {
                exact
            };
            if candidates.is_empty() {
                return Err(usage(&format!("unrecognized option '--{name}'")));
            }
            if candidates.len() != 1 {
                let names = candidates
                    .iter()
                    .map(|o| format!(" '--{}'", o.name))
                    .collect::<String>();
                return Err(usage(&format!(
                    "option '--{name}' is ambiguous; possibilities:{names}"
                )));
            }
            let o = candidates[0];
            let v = if o.value {
                if let Some(v) = value {
                    OsString::from_vec(v.to_vec())
                } else {
                    let v = args
                        .get(i)
                        .ok_or_else(|| usage(&format!("option '--{name}' requires an argument")))?
                        .clone();
                    i += 1;
                    v
                }
            } else {
                if value.is_some() {
                    return Err(usage(&format!(
                        "option '--{name}' doesn't allow an argument"
                    )));
                }
                OsString::new()
            };
            r.opts.push((o.short, v));
        } else {
            for (at, &b) in bytes[1..].iter().enumerate() {
                let c = char::from(b);
                let o = spec
                    .iter()
                    .find(|o| o.short == c && shorts.contains(c))
                    .ok_or_else(|| usage(&format!("invalid option -- '{c}'")))?;
                let v = if o.value {
                    let rest = &bytes[at + 2..];
                    if !rest.is_empty() {
                        OsString::from_vec(rest.to_vec())
                    } else {
                        let v = args
                            .get(i)
                            .ok_or_else(|| usage(&format!("option requires an argument -- '{c}'")))?
                            .clone();
                        i += 1;
                        v
                    }
                } else {
                    OsString::new()
                };
                r.opts.push((c, v));
                if o.value {
                    break;
                }
            }
        }
    }
    Ok(r)
}

struct Params {
    n: u32,
    m: u64,
    b: u8,
    delay: f64,
    step_ns: f64,
    threads: usize,
    quiet: bool,
}
impl Default for Params {
    fn default() -> Self {
        Self {
            n: 16,
            m: 0,
            b: 24,
            delay: 0.,
            step_ns: 0.,
            threads: 0,
            quiet: false,
        }
    }
}
fn bounded(s: &str, lo: u64, hi: u64) -> CliResult<u64> {
    let n = number(s)?;
    if (lo..=hi).contains(&n) {
        Ok(n)
    } else {
        Err(CliError::Usage(None))
    }
}
impl Params {
    fn option(&mut self, c: char, v: &str) -> CliResult<()> {
        match c {
            'n' => self.n = bounded(v, 1, MAX_N as u64)? as u32,
            'm' => self.m = bounded(v, 1, MAX_M)?,
            'b' => self.b = bounded(v, 1, 32)? as u8,
            'j' => self.threads = bounded(v, 1, 4096)? as usize,
            'd' => self.delay = seconds(v)?,
            'L' => self.step_ns = positive(v)?,
            'q' => self.quiet = true,
            _ => return Err(CliError::Usage(None)),
        }
        Ok(())
    }
    fn build(&mut self, be: Backend) -> CliResult<(Puzzle, [u8; 32])> {
        let mut measured = false;
        if self.m == 0 {
            if self.delay <= 0. {
                return Err(usage(
                    "give the work per chain (-m STEPS) or a delay (-d SECONDS)",
                ));
            }
            if self.step_ns <= 0. {
                self.step_ns = benchmark::latency_ns(be, 0.3);
                measured = true;
            }
            let m = (self.delay / self.step_ns * 1e9 / self.n as f64).ceil();
            if m > MAX_M as f64 {
                return Err(code("delay", Error::Range));
            }
            self.m = (m as u64).max(1);
        }
        let t0 = Instant::now();
        let show = !self.quiet && io::stderr().is_terminal();
        let progress = |done: u64, total: u64| {
            let el = t0.elapsed().as_secs_f64();
            eprint!(
                "\r  building: {:5.1}%  {} steps/s  {} ",
                100. * done as f64 / total as f64,
                fmt_si(done as f64 / el),
                fmt_duration(el)
            );
        };
        let (p, key) = generate(
            self.n,
            self.m,
            self.b,
            &GenOptions {
                threads: self.threads,
                backend: Some(be),
                progress: if show { Some(&progress) } else { None },
            },
        )
        .map_err(|e| code("building the puzzle", e))?;
        let dt = t0.elapsed().as_secs_f64();
        if show {
            eprintln!();
        }
        if !self.quiet {
            if self.step_ns <= 0. {
                self.step_ns = benchmark::latency_ns(be, 0.2);
                measured = true;
            }
            let work = self.n as f64 * self.m as f64;
            eprintln!("puzzle: n = {} chains, m = {} steps each, b = {}-byte links, {} bytes\nbuilt in {} on {} threads ({}), {} steps/s\nsolving takes n*m = {} steps: {} at {:.1} ns/step{}",
                self.n,self.m,self.b,68+p.links().len(),fmt_duration(dt),if self.threads==0 {cpu_count()} else {self.threads},be.name(),fmt_si(work/dt),fmt_si(work),fmt_duration(work*self.step_ns*1e-9),self.step_ns,if measured {" (one chain on this machine)"} else {""});
            if self.b < 24 {
                eprintln!(
                    "warning: with {}-byte links the proved bound is weak; SPEC.md section 8 recommends 24 bytes or more",
                    self.b
                );
            }
        }
        Ok((p, key))
    }
}
fn gen_or_encrypt(command: &str, args: &[OsString], be: Backend) -> CliResult<i32> {
    let mut spec = PARAM.to_vec();
    spec.push(opt("out", 'o', true));
    if command == "encrypt" {
        spec.extend([
            opt("in", 'i', true),
            opt("secret", 's', true),
            opt("secret-out", 'S', true),
        ]);
    }
    let parsed = parse(
        args,
        &spec,
        if command == "gen" {
            "nmdbjqo"
        } else {
            "nmdbjqois"
        },
    )?;
    let mut p = Params::default();
    let (mut out, mut input, mut secret, mut secret_out) = (None, None, None, None);
    for (c, v) in &parsed.opts {
        match c {
            'o' => out = Some(v.as_os_str()),
            'i' => input = Some(v.as_os_str()),
            's' => secret = Some(v.as_os_str()),
            'S' => secret_out = Some(v.as_os_str()),
            _ => p.option(*c, text(v)?)?,
        }
    }
    if p.m > 0 && p.delay > 0. {
        return Err(usage("give -m STEPS or -d DELAY, not both"));
    }
    let out = out.ok_or_else(|| {
        usage(if command == "gen" {
            "gen needs -o SECRET and no other arguments"
        } else {
            "encrypt needs -o ENVELOPE and at most one message file"
        })
    })?;
    if command == "gen" {
        if !parsed.pos.is_empty() {
            return Err(usage("gen needs -o SECRET and no other arguments"));
        }
        let (puzzle, mut key) = p.build(be)?;
        save_secret(out, &puzzle, &key)?;
        key.fill(0);
        if !p.quiet {
            eprintln!(
                "wrote {} (keep it private until you use it)",
                Path::new(out).display()
            );
        }
        return Ok(0);
    }
    let mut pos = parsed.pos.iter();
    if input.is_none() {
        input = pos.next().map(OsString::as_os_str);
    }
    if pos.next().is_some() {
        return Err(usage(
            "encrypt needs -o ENVELOPE and at most one message file",
        ));
    }
    if secret.is_some() && (p.m > 0 || p.delay > 0. || secret_out.is_some()) {
        return Err(usage("-s uses a stored puzzle: no -m, -d or --secret-out"));
    }
    if let Some(path) = secret_out {
        // A secret written into the envelope's stream would publish the key.
        if out == "-" && path == "-" {
            return Err(usage(
                "the envelope and the secret cannot both go to stdout; choose a file for --secret-out",
            ));
        }
        let (first, second) = if path == "-" {
            (path, out)
        } else {
            (out, path)
        };
        if is_output(first, second) {
            return Err(usage(
                "the secret file is the envelope file; choose another --secret-out",
            ));
        }
    }
    let input = input.unwrap_or(OsStr::new("-"));
    let mut msg = read_file(input).map_err(|e| Failure::io(input, e))?;
    if msg.len() > MAX_MSG {
        return Err(code(
            if input == "-" {
                OsStr::new("stdin")
            } else {
                input
            },
            Error::Range,
        ));
    }
    let (puzzle, mut key) = if let Some(s) = secret {
        load_secret(s)?
    } else {
        p.build(be)?
    };
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| code("encrypting", Error::Rng))?;
    let env = seal(&puzzle, &key, &nonce, &msg).map_err(|e| code("encrypting", e))?;
    write_file(out, &env, false).map_err(|e| Failure::io(out, e))?;
    if let Some(path) = secret_out {
        save_secret(path, &puzzle, &key)?;
    }
    if !p.quiet {
        eprintln!(
            "wrote {}: {} bytes (puzzle {} + message {} + 60)",
            Path::new(out).display(),
            env.len(),
            68 + puzzle.links().len(),
            msg.len()
        );
    }
    key.fill(0);
    msg.fill(0);
    Ok(0)
}
fn load_job(path: &OsStr, checkpoints: bool) -> CliResult<SolveJob> {
    let job = SolveJob::load(path, checkpoints).map_err(|e| {
        if e.code == Some(Error::Mismatch) {
            CliError::Message(
                format!(
                    "{} belongs to a different puzzle; remove it or pass --no-checkpoint",
                    e.what
                ),
                1,
            )
        } else {
            e.into()
        }
    })?;
    if job.resumed {
        eprintln!(
            "{}: resuming at chain {} of {}, {} steps done",
            Path::new(path).display(),
            job.cursor.i,
            job.puzzle.n(),
            fmt_si(job.start_done as f64)
        );
    }
    Ok(job)
}
fn run_jobs(
    jobs: &mut [SolveJob],
    be: Backend,
    stop_after: u64,
    ready: Option<&Path>,
    quiet: bool,
) -> CliResult<i32> {
    let show = !quiet && io::stderr().is_terminal();
    let count = jobs.len();
    let p = jobs.first().map(|j| (j.puzzle.n(), j.puzzle.m()));
    // The solver checkpoints and stops on SIGINT or SIGTERM. The handlers are
    // installed before the ready file appears and stay until the process exits.
    let signalled = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(sig, signalled.clone())
            .map_err(|e| Failure::io("signal handler", e))?;
    }
    solve_jobs(jobs, be, &signalled, stop_after, ready, |s| {
        if !show {
            return;
        }
        let rate = if s.elapsed > 0. {
            s.fresh / s.elapsed
        } else {
            0.
        };
        if let Some((n, m)) = p.filter(|_| count == 1) {
            let chain = ((s.done / m as f64) as u32 + 1).min(n);
            eprint!(
                "\r  chain {chain}/{n}  {:5.1}%  {} steps/s ({:.1} ns/step)  {}, about {} left ",
                100. * s.done / s.total,
                fmt_si(rate),
                if rate > 0. { 1e9 / rate } else { 0. },
                fmt_duration(s.elapsed),
                fmt_duration(if rate > 0. {
                    (s.total - s.done) / rate
                } else {
                    0.
                })
            );
        } else {
            eprint!(
                "\r  {} of {count} puzzles running  {:5.1}%  {} steps/s in all  {} ",
                s.running,
                100. * s.done / s.total,
                fmt_si(rate),
                fmt_duration(s.elapsed)
            );
        }
    })
    .map_err(|e| {
        let message = e.to_string();
        if message != format!("could not start {count} solver threads") {
            return CliError::Failure(Failure::io("solve", e));
        }
        for job in jobs.iter_mut() {
            if let Some(path) = &job.checkpoint {
                if let Some(error) = job.save_error.take() {
                    eprintln!("leanseal: {}", Failure::io(path, error));
                } else {
                    eprintln!(
                        "{}: stopped; progress saved to {}",
                        job.path.display(),
                        path.display()
                    );
                }
            }
        }
        CliError::Message(message, 1)
    })?;
    if show {
        eprintln!();
    }
    let mut rc = 0;
    for j in jobs {
        match &j.result {
            Some(Err(Error::Stopped)) => {
                if let Some(e) = j.save_error.take() {
                    let e = Failure::io(j.checkpoint.as_deref().unwrap_or(&j.path), e);
                    eprintln!("leanseal: {e}");
                    rc = e.exit_code();
                } else {
                    if let Some(path) = &j.checkpoint {
                        eprintln!(
                            "{}: stopped; progress saved to {}",
                            j.path.display(),
                            path.display()
                        );
                    } else {
                        eprintln!("{}: stopped", j.path.display());
                    }
                    if rc == 0 {
                        rc = 130;
                    }
                }
            }
            Some(Err(e)) => {
                let resumed_from = j.checkpoint.as_ref().filter(|_| j.resumed);
                let e = Failure::code(&j.path, *e);
                match resumed_from {
                    // Nothing authenticates a checkpoint, so a damaged one also
                    // ends here; do not report the puzzle as malformed.
                    Some(ck) if e.code == Some(Error::Puzzle) => eprintln!(
                        "leanseal: {}: the solve resumed from {} does not yield the committed key; \
                         the checkpoint may be damaged. Remove it, or pass --no-checkpoint, and \
                         solve from the start before concluding that the puzzle is malformed",
                        j.path.display(),
                        ck.display()
                    ),
                    _ => eprintln!("leanseal: {e}"),
                }
                rc = e.exit_code();
            }
            Some(Ok(_)) if !quiet => {
                let steps = j.done() - j.start_done;
                eprintln!(
                    "{}: solved in {}, {:.2} ns/step",
                    j.path.display(),
                    fmt_duration(j.elapsed),
                    if steps > 0 {
                        j.elapsed * 1e9 / steps as f64
                    } else {
                        0.
                    }
                );
            }
            Some(Ok(_)) | None => {}
        }
    }
    Ok(rc)
}
fn solve(args: &[OsString], be: Backend, stop: u64, ready: Option<&Path>) -> CliResult<i32> {
    let a = parse(
        args,
        &[opt("no-checkpoint", 'N', false), opt("quiet", 'q', false)],
        "q",
    )?;
    if a.pos.is_empty() {
        return Err(usage("solve needs at least one file"));
    }
    let checkpoint = !a.opts.iter().any(|(c, _)| *c == 'N');
    let quiet = a.opts.iter().any(|(c, _)| *c == 'q');
    let mut jobs = a
        .pos
        .iter()
        .map(|p| load_job(p, checkpoint))
        .collect::<CliResult<Vec<_>>>()?;
    let mut rc = run_jobs(&mut jobs, be, stop, ready, quiet)?;
    for j in jobs {
        if let Some(Ok(key)) = j.result {
            if let Err(e) = output(&format!("{}  {}\n", hex(&key), j.path.display())) {
                if let CliError::Failure(e) = &e {
                    eprintln!("leanseal: {e}");
                }
                rc = 1;
            } else if let Some(ck) = j.checkpoint {
                let _ = std::fs::remove_file(ck);
            }
        }
    }
    Ok(rc)
}
fn read_key(arg: &OsStr) -> CliResult<[u8; 32]> {
    if let Some(k) = arg.to_str().and_then(|s| unhex(s).ok()) {
        return Ok(k);
    }
    let bad = || usage("-k takes 64 hex digits, a file holding them, or - for stdin");
    let mut data = read_file(arg).map_err(|_| bad())?;
    let result = if data.len() < 80 {
        std::str::from_utf8(&data)
            .map_err(|_| bad())
            .and_then(|s| unhex(s).map_err(|_| bad()))
    } else {
        Err(bad())
    };
    data.fill(0);
    result
}
fn open(args: &[OsString], be: Backend, stop: u64, ready: Option<&Path>) -> CliResult<i32> {
    let a = parse(
        args,
        &[
            opt("out", 'o', true),
            opt("key", 'k', true),
            opt("secret", 's', true),
            opt("solve", 'X', false),
            opt("no-checkpoint", 'N', false),
            opt("quiet", 'q', false),
        ],
        "oksq",
    )?;
    let (mut out, mut keyarg, mut secret) = (OsStr::new("-"), None, None);
    let (mut solve, mut checkpoints, mut quiet) = (false, true, false);
    for (c, v) in &a.opts {
        match c {
            'o' => out = v,
            'k' => keyarg = Some(v.as_os_str()),
            's' => secret = Some(v.as_os_str()),
            'X' => solve = true,
            'N' => checkpoints = false,
            'q' => quiet = true,
            _ => {}
        }
    }
    if a.pos.len() != 1
        || usize::from(keyarg.is_some()) + usize::from(secret.is_some()) + usize::from(solve) != 1
    {
        return Err(usage(
            "open takes one ENVELOPE and exactly one of -k KEY, -s SECRET, --solve",
        ));
    }
    if a.pos[0] == "-" && keyarg == Some(OsStr::new("-")) {
        return Err(usage(
            "the envelope and the key cannot both come from stdin",
        ));
    }
    let mut j = load_job(&a.pos[0], solve && checkpoints)?;
    if !j.envelope {
        return Err(CliError::Message(
            format!("{} is a bare puzzle, not an envelope", j.path.display()),
            1,
        ));
    }
    if j.checkpoint.as_ref().is_some_and(|ck| is_output(out, ck)) {
        return Err(usage(
            "the output file is the checkpoint file; choose another -o or use --no-checkpoint",
        ));
    }
    let mut key = if solve {
        let rc = run_jobs(std::slice::from_mut(&mut j), be, stop, ready, quiet)?;
        if rc != 0 {
            return Ok(rc);
        }
        match j.result {
            Some(Ok(key)) => key,
            _ => return Err(code(&j.path, Error::Puzzle)),
        }
    } else if let Some(k) = keyarg {
        read_key(k)?
    } else if let Some(s) = secret {
        load_secret(s)?.1
    } else {
        return Err(CliError::Usage(None));
    };
    let mut msg = Envelope::decode(&j.data)
        .and_then(|e| e.open(&key))
        .map_err(|e| code(&j.path, e))?;
    write_file(out, &msg, false).map_err(|e| Failure::io(out, e))?;
    if let Some(ck) = j.checkpoint {
        if !is_output(out, &ck) {
            let _ = std::fs::remove_file(ck);
        }
    }
    key.fill(0);
    msg.fill(0);
    Ok(0)
}
fn print_puzzle(p: &Puzzle, be: Backend) -> CliResult<()> {
    let ns = benchmark::latency_ns(be, 0.1);
    let work = p.n() as f64 * p.m() as f64;
    output(&format!("  chains n       {}\n  steps/chain m  {}\n  link bytes b   {}\n  salt           {}\n  commitment     {}\n  puzzle id      {}\n  puzzle size    {} bytes\n  work n*m       {} steps: {} here at {:.1} ns/step\n",
        p.n(),p.m(),p.b(),hex(p.salt()),hex(p.commitment()),hex(&p.id()),68+p.links().len(),fmt_si(work),fmt_duration(work*ns*1e-9),ns))?;
    // With one chain the only link is public, so there is no link to guess.
    if p.n() > 1 {
        output(&format!(
            "  last-link guess  each costs m steps, succeeds with chance 2^-{}\n",
            8 * u32::from(p.b())
        ))?;
    }
    Ok(())
}
fn info(args: &[OsString], be: Backend) -> CliResult<i32> {
    if args.len() != 1 {
        return Err(usage("info takes one file"));
    }
    let path = Path::new(&args[0]);
    let d = read_file(path).map_err(|e| Failure::io(path, e))?;
    if d.starts_with(b"LSPZ") {
        let p = Puzzle::decode(&d).map_err(|e| code(path, e))?;
        output(&format!("{}: puzzle\n", path.display()))?;
        print_puzzle(&p, be)?;
    } else if d.starts_with(b"LSEN") {
        let e = Envelope::decode(&d).map_err(|e| code(path, e))?;
        output(&format!(
            "{}: envelope, {} bytes\n  message        {} bytes\n  nonce          {}\n",
            path.display(),
            d.len(),
            e.message_len(),
            hex(&e.nonce)
        ))?;
        print_puzzle(&e.puzzle, be)?;
    } else if d.starts_with(b"LSSK") {
        let (p, _) = secret_decode(&d).map_err(|e| code(path, e))?;
        output(&format!(
            "{}: secret (puzzle with its key; the key matches the commitment)\n",
            path.display()
        ))?;
        print_puzzle(&p, be)?;
    } else if d.starts_with(b"LSCK") {
        let (id, i, j) = checkpoint_peek(&d).map_err(|e| code(path, e))?;
        output(&format!(
            "{}: checkpoint\n  puzzle id      {}\n  chain i        {i}\n  steps done j   {j}\n",
            path.display(),
            hex(&id)
        ))?;
    } else {
        return Err(code(path, Error::Format));
    }
    Ok(0)
}
fn bench(args: &[OsString], be: Backend) -> CliResult<i32> {
    let spec = [
        opt("seconds", 's', true),
        opt("threads", 'j', true),
        opt("work", 'w', true),
        opt("link-bytes", 'b', true),
        opt("steps", 'm', true),
        opt("chains", 'n', true),
        opt("trials", 't', true),
        opt("fraction", 'f', true),
    ];
    let a = parse(args, &spec, "sjwbmntf")?;
    let (
        mut secs,
        mut threads,
        mut work,
        mut b,
        mut attack_b,
        mut m,
        mut n,
        mut trials,
        mut fraction,
    ) = (2., cpu_count(), 1u64 << 28, 16, 1, 16, 4, 20000, 0.25);
    for (c, v) in &a.opts {
        let r = (|| -> CliResult<()> {
            let v = text(v)?;
            match c {
                's' => secs = seconds(v)?,
                'j' => threads = bounded(v, 1, 4096)? as usize,
                'w' => work = bounded(v, 1, u64::MAX)?,
                'b' => {
                    b = bounded(v, 1, 32)? as u8;
                    attack_b = b;
                }
                'm' => m = bounded(v, 1, u64::MAX)?,
                'n' => n = bounded(v, 1, MAX_N as u64)? as u32,
                't' => trials = bounded(v, 1, 1000000)?,
                'f' => {
                    fraction = positive(v)?;
                    if fraction > 1. {
                        return Err(CliError::Usage(None));
                    }
                }
                _ => return Err(CliError::Usage(None)),
            }
            Ok(())
        })();
        if r.is_err() {
            return Err(CliError::Message("bad bench option".into(), 2));
        }
    }
    let what = a.pos.first().map(|v| text(v)).transpose()?.unwrap_or("all");
    let all = what == "all";
    let mut rc = 0;
    let uname = std::process::Command::new("uname")
        .args(["-s", "-m"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let model=std::process::Command::new("sh").args(["-c","sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2"]).output().ok().map(|o|String::from_utf8_lossy(&o.stdout).trim_end().to_owned()).unwrap_or_default();
    output(&format!(
        "# host {uname}, {} cpus, cpu:{model}\n",
        cpu_count()
    ))?;
    if all || what == "latency" {
        output(&format!(
            "## latency: one chain, steps one after another\n{:<12} {:>10} {:>10} {:>12}\n",
            "backend", "ns/step", "best", "M steps/s"
        ))?;
        for b in Backend::available() {
            let (median, best) = benchmark::latency_samples(b, secs);
            output(&format!(
                "{:<12} {:10.2} {:10.2} {:12.1}\n",
                b.name(),
                median,
                best,
                1e3 / median
            ))?;
        }
    }
    if all || what == "throughput" {
        let result = (|| -> CliResult<()> {
            output(&format!(
                "## throughput: independent chains in parallel ({})\n{:>8} {:>6} {:>14} {:>16}\n",
                be.name(),
                "threads",
                "lanes",
                "M steps/s",
                "per thread"
            ))?;
            for lanes in 1..=be.lanes() {
                let r = benchmark::throughput(be, 1, lanes, secs / 4.)
                    .map_err(|e| Failure::io("throughput", e))?;
                output(&format!(
                    "{:8} {lanes:6} {:14.1} {:16.1}\n",
                    1,
                    r / 1e6,
                    r / 1e6
                ))?;
            }
            for count in [2, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128]
                .into_iter()
                .filter(|c| *c < threads)
            {
                let r = benchmark::throughput(be, count, be.lanes(), secs / 4.)
                    .map_err(|e| Failure::io("throughput", e))?;
                output(&format!(
                    "{count:8} {:6} {:14.1} {:16.1}\n",
                    be.lanes(),
                    r / 1e6,
                    r / 1e6 / count as f64
                ))?;
            }
            let r = benchmark::throughput(be, threads, be.lanes(), secs)
                .map_err(|e| Failure::io("throughput", e))?;
            output(&format!(
                "{threads:8} {:6} {:14.1} {:16.1}   <- all cores\n",
                be.lanes(),
                r / 1e6,
                r / 1e6 / threads as f64
            ))?;
            Ok(())
        })();
        if let Err(error) = result {
            match error {
                CliError::Failure(e) if e.what == "throughput" => eprintln!("leanseal: {e}"),
                other => return Err(other),
            }
            rc = 1;
        }
    }
    if all || what == "build" {
        let ns = benchmark::latency_ns(be, 0.5);
        output(&format!("## build: total work n*m = {} steps, {threads} threads, {}, {ns:.2} ns/step for one chain\n{:>6} {:>12} {:>10} {:>12} {:>12} {:>10} {:>8}\n",fmt_si(work as f64),be.name(),"n","m","build s","M steps/s","solve s","ratio","bytes"))?;
        let mut count = 1;
        while count <= 4096 && u64::from(count) <= work {
            let r = match benchmark::build(work, count, threads, b, be) {
                Ok(row) => row,
                Err(e) => {
                    eprintln!("leanseal: build: {e}");
                    rc = 1;
                    break;
                }
            };
            let solve = r.n as f64 * r.m as f64 * ns * 1e-9;
            output(&format!(
                "{:6} {:12} {:10.3} {:12.1} {:12.3} {:10.2} {:8}\n",
                r.n,
                r.m,
                r.seconds,
                r.n as f64 * r.m as f64 / r.seconds / 1e6,
                solve,
                solve / r.seconds,
                r.bytes
            ))?;
            count *= 2;
        }
    }
    if all || what == "attack" {
        if attack_b > 3 {
            eprintln!("leanseal: attack needs -b 1, 2 or 3");
            return Ok(1);
        }
        let r = benchmark::attack(attack_b, n, m, trials, fraction, be)
            .map_err(|e| code("attack", e))?;
        output(&format!("## guessing ahead by one chain, b = {attack_b} (2^{} values), n = {n}, m = {m}\nbudget per puzzle   {} guesses = {:.3} of all values, {} steps (honest solve: {})\nlast link guessed   {} of {trials} puzzles = {:.3}; this strategy expects {:.3} = {:.1} +- {:.1}\ntime                {:.2} s\n",8*attack_b,r.budget,r.expected,r.budget.wrapping_mul(m),u64::from(n).wrapping_mul(m),r.wins,r.wins as f64/trials as f64,r.expected,trials as f64*r.expected,r.sd,r.seconds))?;
        if (r.wins as f64 - trials as f64 * r.expected).abs() > 4. * r.sd + 1. {
            return Ok(1);
        }
    }
    if !["all", "latency", "throughput", "build", "attack"].contains(&what) {
        return Err(CliError::Message(
            "bench latency|throughput|build|attack|all".into(),
            2,
        ));
    }
    Ok(rc)
}
fn report_selftest(
    tests: impl IntoIterator<Item = (&'static str, bool)>,
    mut write: impl FnMut(&str) -> CliResult<()>,
) -> CliResult<i32> {
    for (name, pass) in tests {
        write(&format!(
            "backend {name:<12} {}\n",
            if pass { "ok" } else { "MISMATCH" }
        ))?;
        if !pass {
            return Ok(1);
        }
    }
    write("round trip           ok\n")?;
    Ok(0)
}
fn run() -> CliResult<i32> {
    fast_qos();
    let stop = match std::env::var("LEANSEAL_TEST_STOP_AFTER") {
        Ok(s) => number(&s).map_err(|_| usage("bad LEANSEAL_TEST_STOP_AFTER"))?,
        Err(_) => 0,
    };
    let ready = std::env::var_os("LEANSEAL_TEST_READY").map(std::path::PathBuf::from);
    let be = Backend::best().map_err(|_| {
        let name = std::env::var_os("LEANSEAL_BACKEND").unwrap_or_default();
        let name = name.to_string_lossy();
        CliError::Message(
            format!(
                "LEANSEAL_BACKEND={name} is not available on this machine; available:{}",
                Backend::available()
                    .iter()
                    .map(|b| format!(" {}", b.name()))
                    .collect::<String>()
            ),
            2,
        )
    })?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let command = args.first().ok_or(CliError::Usage(None))?;
    let a = &args[1..];
    match text(command)? {
        "help" | "--help" | "-h" => {
            output(USAGE)?;
            Ok(0)
        }
        "gen" | "encrypt" => gen_or_encrypt(text(command)?, a, be),
        "key" => {
            if a.len() != 1 {
                return Err(usage("key takes one SECRET file"));
            }
            let (_, mut key) = load_secret(&a[0])?;
            let r = output(&format!("{}\n", hex(&key)));
            key.fill(0);
            r?;
            Ok(0)
        }
        "solve" => solve(a, be, stop, ready.as_deref()),
        "open" => open(a, be, stop, ready.as_deref()),
        "info" => info(a, be),
        "bench" => bench(a, be),
        "vectors" => {
            let s = vectors::generate_vectors().map_err(|e| code("vectors", e))?;
            output(&s)?;
            Ok(0)
        }
        "selftest" => report_selftest(
            benchmark::selftest().map_err(|e| code("selftest", e))?,
            output,
        ),
        _ => Err(usage("unknown command")),
    }
}
fn main() {
    let rc = match run() {
        Ok(code) => code,
        Err(CliError::Message(msg, code)) => {
            eprintln!("leanseal: {msg}");
            code
        }
        Err(CliError::Usage(msg)) => {
            if let Some(msg) = msg {
                eprintln!("leanseal: {msg}");
            }
            eprintln!("run 'leanseal help' for usage");
            2
        }
        Err(CliError::Failure(err)) => {
            eprintln!("leanseal: {err}");
            err.exit_code()
        }
    };
    std::process::exit(rc);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selftest_mismatch_prints_and_returns_immediately() {
        let mut output = String::new();
        let mut visited = 0;
        let results = [("bad", false), ("later", true)]
            .into_iter()
            .inspect(|_| visited += 1);
        let result = report_selftest(results, |s| {
            output.push_str(s);
            Ok(())
        });
        assert!(matches!(result, Ok(1)));
        assert_eq!(visited, 1);
        assert_eq!(output, "backend bad          MISMATCH\n");
    }
}
