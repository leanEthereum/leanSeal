use crate::backend::{Backend, Tail};
use crate::hash::{bytes_to_words, ct_equal, th, words_to_bytes};
use crate::{array, bytes, Error, Result, MAX_M, MAX_N, MAX_WORK};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

/// Check the complete v1 parameter bounds.
pub fn params_ok(n: u32, m: u64, b: u8) -> bool {
    (1..=MAX_N).contains(&n)
        && (1..=MAX_M).contains(&m)
        && m <= MAX_WORK / u64::from(n)
        && (1..=32).contains(&b)
}
/// A validated puzzle owning its encoded links.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Puzzle {
    pub(crate) n: u32,
    pub(crate) m: u64,
    pub(crate) b: u8,
    pub(crate) salt: [u8; 16],
    pub(crate) commit: [u8; 32],
    pub(crate) links: Vec<u8>,
}
impl Puzzle {
    /// Number of chains.
    pub fn n(&self) -> u32 {
        self.n
    }
    /// Steps per chain.
    pub fn m(&self) -> u64 {
        self.m
    }
    /// Link width in bytes.
    pub fn b(&self) -> u8 {
        self.b
    }
    /// Puzzle salt.
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }
    /// Key commitment.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commit
    }
    /// First link and the masked remaining links.
    pub fn links(&self) -> &[u8] {
        &self.links
    }
    /// Fixed 32-byte context.
    pub fn context(&self) -> [u8; 32] {
        let mut c = [0; 32];
        c[0] = 1;
        c[1] = self.b;
        c[4..8].copy_from_slice(&self.n.to_be_bytes());
        c[8..16].copy_from_slice(&self.m.to_be_bytes());
        c[16..].copy_from_slice(&self.salt);
        c
    }
    pub(crate) fn encoded_len_from_header(data: &[u8]) -> Result<usize> {
        if data.len() < 68 || &data[..4] != b"CSPZ" || data[4] != 1 || data[6] != 0 || data[7] != 0
        {
            return Err(Error::Format);
        }
        let n = u32::from_be_bytes(array(&data[8..12])?);
        let m = u64::from_be_bytes(array(&data[12..20])?);
        if !params_ok(n, m, data[5]) {
            return Err(Error::Range);
        }
        Ok(68 + n as usize * data[5] as usize)
    }
    /// Decode a canonical puzzle, rejecting truncation and trailing bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != Self::encoded_len_from_header(data)? {
            return Err(Error::Format);
        }
        let mut links = bytes(data.len() - 68)?;
        links.copy_from_slice(&data[68..]);
        Ok(Self {
            n: u32::from_be_bytes(array(&data[8..12])?),
            m: u64::from_be_bytes(array(&data[12..20])?),
            b: data[5],
            salt: array(&data[20..36])?,
            commit: array(&data[36..68])?,
            links,
        })
    }
    /// Encode a puzzle in the normative v1 format.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut v = bytes(68 + self.links.len())?;
        v[..4].copy_from_slice(b"CSPZ");
        v[4..36].copy_from_slice(&self.context());
        v[36..68].copy_from_slice(&self.commit);
        v[68..].copy_from_slice(&self.links);
        Ok(v)
    }
    /// Identifier bound to every byte of this puzzle.
    pub fn id(&self) -> [u8; 32] {
        th(
            "chainseal/v1/puzzle-id",
            &[b"CSPZ", &self.context(), &self.commit, &self.links],
        )
    }
    /// Test a revealed key against the commitment.
    pub fn check_key(&self, key: &[u8; 32]) -> bool {
        ct_equal(
            &self.commit,
            &th("chainseal/v1/commit", &[&self.context(), key]),
        )
    }
    /// Compute the start value of a chain from its clear link.
    pub fn chain_start(&self, i: u32, x: &[u8]) -> Result<[u8; 32]> {
        if !(1..=self.n).contains(&i) || x.len() != self.b as usize {
            return Err(Error::Range);
        }
        Ok(th(
            "chainseal/v1/start",
            &[&self.context(), &i.to_be_bytes(), x],
        ))
    }
    /// Compute the mask derived from a chain end.
    pub fn chain_mask(&self, y: &[u8; 32]) -> [u8; 32] {
        th("chainseal/v1/mask", &[&self.context(), y])
    }
    /// Run an individual chain from a clear link.
    pub fn run_chain(&self, i: u32, x: &[u8], backend: Backend) -> Result<[u8; 32]> {
        let mut st = bytes_to_words(self.chain_start(i, x)?);
        backend.run(&mut st, &Tail::new(&self.salt, i), self.m);
        Ok(words_to_bytes(st))
    }
    /// Derive and check a key from all chain ends in order.
    pub fn key_from_ends(&self, y: &[[u8; 32]]) -> Result<[u8; 32]> {
        if y.len() != self.n as usize {
            return Err(Error::Range);
        }
        let mut a = self.context();
        for end in y {
            a = th("chainseal/v1/acc", &[&a, end]);
        }
        let k = th("chainseal/v1/key", &[&self.context(), &a]);
        if self.check_key(&k) {
            Ok(k)
        } else {
            Err(Error::Puzzle)
        }
    }
    /// Start a resumable solve.
    pub fn cursor(&self) -> Cursor {
        // The first link exists because construction validates n and b.
        let st = th(
            "chainseal/v1/start",
            &[
                &self.context(),
                &1u32.to_be_bytes(),
                &self.links[..self.b as usize],
            ],
        );
        Cursor {
            i: 1,
            j: 0,
            state: bytes_to_words(st),
            acc: self.context(),
        }
    }
    /// Solve from a cursor, calling progress after at most every requested steps.
    /// Returning true from progress preserves the cursor and returns Stopped.
    pub fn solve(
        &self,
        cur: &mut Cursor,
        backend: Backend,
        every: u64,
        mut progress: impl FnMut(&Cursor) -> bool,
    ) -> Result<[u8; 32]> {
        if cur.i < 1 || cur.i > self.n || cur.j > self.m {
            return Err(Error::Range);
        }
        loop {
            let tail = Tail::new(&self.salt, cur.i);
            while cur.j < self.m {
                let remaining = self.m - cur.j;
                let steps = if every == 0 {
                    remaining
                } else {
                    remaining.min(every)
                };
                backend.run(&mut cur.state, &tail, steps);
                cur.j += steps;
                if progress(cur) {
                    return Err(Error::Stopped);
                }
            }
            if cur.i == self.n {
                break;
            }
            let y = words_to_bytes(cur.state);
            cur.acc = th("chainseal/v1/acc", &[&cur.acc, &y]);
            let mut x = self.chain_mask(&y);
            let off = cur.i as usize * self.b as usize;
            for (v, z) in x.iter_mut().zip(&self.links[off..off + self.b as usize]) {
                *v ^= z;
            }
            cur.i += 1;
            cur.j = 0;
            cur.state = bytes_to_words(self.chain_start(cur.i, &x[..self.b as usize])?);
        }
        let a = th("chainseal/v1/acc", &[&cur.acc, &words_to_bytes(cur.state)]);
        let k = th("chainseal/v1/key", &[&self.context(), &a]);
        if self.check_key(&k) {
            Ok(k)
        } else {
            Err(Error::Puzzle)
        }
    }
}
/// Resumable state; the accumulator excludes the current chain even when finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// Current chain, one based.
    pub i: u32,
    /// Completed steps of the current chain.
    pub j: u64,
    /// Current SHA-256 digest words.
    pub state: [u32; 8],
    /// Accumulator of preceding chain ends.
    pub acc: [u8; 32],
}
impl Cursor {
    /// Total number of completed steps.
    pub fn done(&self, p: &Puzzle) -> u64 {
        u64::from(self.i.saturating_sub(1)) * p.m + self.j
    }
    /// Encode a checkpoint bound to a puzzle.
    pub fn encode(&self, p: &Puzzle) -> Result<Vec<u8>> {
        if self.i < 1 || self.i > p.n || self.j > p.m {
            return Err(Error::Range);
        }
        let mut v = bytes(116)?;
        v[..8].copy_from_slice(b"CSCK\x01\0\0\0");
        v[8..40].copy_from_slice(&p.id());
        v[40..44].copy_from_slice(&self.i.to_be_bytes());
        v[44..52].copy_from_slice(&self.j.to_be_bytes());
        v[52..84].copy_from_slice(&words_to_bytes(self.state));
        v[84..].copy_from_slice(&self.acc);
        Ok(v)
    }
    /// Decode a checkpoint for this puzzle.
    pub fn decode(p: &Puzzle, data: &[u8]) -> Result<Self> {
        let (id, i, j) = checkpoint_fields(data)?;
        if id != p.id() {
            return Err(Error::Mismatch);
        }
        checkpoint_range(i, j)?;
        if i > p.n || j > p.m {
            return Err(Error::Range);
        }
        Ok(Self {
            i,
            j,
            state: bytes_to_words(array(&data[52..84])?),
            acc: array(&data[84..])?,
        })
    }
}
fn checkpoint_fields(data: &[u8]) -> Result<([u8; 32], u32, u64)> {
    if data.len() != 116 || &data[..8] != b"CSCK\x01\0\0\0" {
        return Err(Error::Format);
    }
    Ok((
        array(&data[8..40])?,
        u32::from_be_bytes(array(&data[40..44])?),
        u64::from_be_bytes(array(&data[44..52])?),
    ))
}
fn checkpoint_range(i: u32, j: u64) -> Result<()> {
    if !(1..=MAX_N).contains(&i) || j > MAX_M || j > MAX_WORK / u64::from(i) {
        Err(Error::Range)
    } else {
        Ok(())
    }
}
/// Inspect a checkpoint without its puzzle, validating global position bounds.
pub fn checkpoint_peek(data: &[u8]) -> Result<([u8; 32], u32, u64)> {
    let fields = checkpoint_fields(data)?;
    checkpoint_range(fields.1, fields.2)?;
    Ok(fields)
}
/// Generation options. Zero threads uses all available CPUs.
#[derive(Default)]
pub struct GenOptions<'a> {
    /// Worker count; capped to the number of chain groups.
    pub threads: usize,
    /// Explicit backend; otherwise use runtime selection.
    pub backend: Option<Backend>,
    /// Optional progress callback, invoked on the calling thread.
    pub progress: Option<&'a dyn Fn(u64, u64)>,
}
/// Number of online CPUs available to this process.
pub fn cpu_count() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}
/// Generate from OS randomness.
pub fn generate(n: u32, m: u64, b: u8, opts: &GenOptions<'_>) -> Result<(Puzzle, [u8; 32])> {
    if !params_ok(n, m, b) {
        return Err(Error::Range);
    }
    let mut salt = [0; 16];
    let mut x = bytes(n as usize * b as usize)?;
    getrandom::getrandom(&mut salt).map_err(|_| Error::Rng)?;
    getrandom::getrandom(&mut x).map_err(|_| Error::Rng)?;
    let (p, k, _) = generate_from(n, m, b, salt, &x, opts)?;
    Ok((p, k))
}
/// Generate deterministically from a salt and clear links, also returning all chain ends.
pub fn generate_from(
    n: u32,
    m: u64,
    b: u8,
    salt: [u8; 16],
    x: &[u8],
    opts: &GenOptions<'_>,
) -> Result<(Puzzle, [u8; 32], Vec<[u8; 32]>)> {
    if !params_ok(n, m, b) || x.len() != n as usize * b as usize {
        return Err(Error::Range);
    }
    let be = match opts.backend {
        Some(b) => b,
        None => Backend::best()?,
    };
    let mut p = Puzzle {
        n,
        m,
        b,
        salt,
        commit: [0; 32],
        links: bytes(x.len())?,
    };
    let next = AtomicUsize::new(0);
    let done = AtomicU64::new(0);
    let threads = if opts.threads == 0 {
        cpu_count()
    } else {
        opts.threads
    }
    .min((n as usize).div_ceil(be.lanes()));
    let y = std::thread::scope(|scope| -> Result<Vec<[u8; 32]>> {
        let mut jobs = Vec::new();
        for _ in 0..threads {
            let p = &p;
            let next = &next;
            let done = &done;
            jobs.push(scope.spawn(move || -> Result<Vec<(usize, [u8; 32])>> {
                crate::backend::fast_qos();
                let mut ends = Vec::new();
                loop {
                    let start = next.fetch_add(be.lanes(), Ordering::Relaxed);
                    if start >= n as usize {
                        break;
                    }
                    let lanes = be.lanes().min(n as usize - start);
                    let mut st = [[0; 8]; 2];
                    let mut tails = [Tail::new(&salt, 0); 2];
                    for l in 0..lanes {
                        let i = (start + l + 1) as u32;
                        tails[l] = Tail::new(&salt, i);
                        let off = (start + l) * b as usize;
                        st[l] = bytes_to_words(p.chain_start(i, &x[off..off + b as usize])?);
                    }
                    let mut j = 0;
                    while j < m {
                        let steps = (m - j).min(1 << 22);
                        be.run_lanes(&mut st[..lanes], &tails[..lanes], steps);
                        j += steps;
                        done.fetch_add(steps * lanes as u64, Ordering::Relaxed);
                    }
                    for (l, s) in st[..lanes].iter().enumerate() {
                        ends.push((start + l, words_to_bytes(*s)));
                    }
                }
                Ok(ends)
            }));
        }
        if let Some(f) = opts.progress {
            while jobs.iter().any(|j| !j.is_finished()) {
                f(done.load(Ordering::Relaxed), u64::from(n) * m);
                std::thread::sleep(Duration::from_millis(100));
            }
            f(u64::from(n) * m, u64::from(n) * m);
        }
        let mut y = Vec::new();
        y.try_reserve_exact(n as usize).map_err(|_| Error::Memory)?;
        y.resize(n as usize, [0; 32]);
        for job in jobs {
            for (i, end) in job.join().map_err(|_| Error::Memory)?? {
                y[i] = end;
            }
        }
        Ok(y)
    })?;
    p.links[..b as usize].copy_from_slice(&x[..b as usize]);
    let mut a = p.context();
    for (i, end) in y.iter().enumerate() {
        a = th("chainseal/v1/acc", &[&a, end]);
        if i + 1 < n as usize {
            let mask = p.chain_mask(end);
            let off = (i + 1) * b as usize;
            for (j, v) in mask[..b as usize].iter().enumerate() {
                p.links[off + j] = v ^ x[off + j];
            }
        }
    }
    let key = th("chainseal/v1/key", &[&p.context(), &a]);
    p.commit = th("chainseal/v1/commit", &[&p.context(), &key]);
    Ok((p, key, y))
}
