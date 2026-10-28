// Property test of the decoder invariants, on stable and without new
// dependencies. The invariants and seeds are shared with the fuzz crate,
// which includes them by path, so `cargo test` and `cargo fuzz` check the same things.
#[path = "support/alloc_count.rs"]
mod alloc_count;
#[path = "support/checks.rs"]
mod checks;
#[path = "support/seeds.rs"]
mod seeds;

use leanseal::{Error, Puzzle, MAX_MSG, MAX_N};
use std::time::Instant;

#[global_allocator]
static ALLOC: alloc_count::Counting = alloc_count::Counting;

/// Mutated cases per format and seed.
const CASES: usize = 10_000;

/// Fixed-seed xorshift64* generator.
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Puzzle,
    Envelope,
    Secret,
    Checkpoint,
}

/// Offset of the embedded puzzle, or of the checkpoint fields.
fn puzzle_at(kind: Kind) -> usize {
    match kind {
        Kind::Puzzle => 0,
        Kind::Envelope => 8,
        Kind::Secret => 40,
        Kind::Checkpoint => checks::CHECKPOINT_LEN,
    }
}

/// Big-endian length and count fields: `(offset, width)`.
fn length_fields(kind: Kind, d: &[u8]) -> Vec<(usize, usize)> {
    let at = puzzle_at(kind);
    let mut v = vec![(at + 5, 1), (at + 8, 4), (at + 12, 8)];
    if let Kind::Envelope = kind {
        if d.len() >= 8 + 68 {
            let nb =
                u32::from_be_bytes(d[16..20].try_into().unwrap()) as usize * usize::from(d[13]);
            v.push((76 + nb + 16, 4));
        }
    }
    if let Kind::Checkpoint = kind {
        v.extend([(40, 4), (44, 8)]);
    }
    v
}

fn read_be(d: &[u8]) -> u64 {
    d.iter().fold(0, |a, &b| (a << 8) | u64::from(b))
}

fn write_be(d: &mut [u8], v: u64) {
    let w = d.len();
    for (k, b) in d.iter_mut().enumerate() {
        *b = (v >> (8 * (w - 1 - k))) as u8;
    }
}

/// Edit a length or count field, sometimes resizing the input to match.
fn edit_length(r: &mut XorShift, kind: Kind, d: &mut Vec<u8>) {
    let fields = length_fields(kind, d);
    let (off, w) = fields[r.below(fields.len())];
    if off + w > d.len() {
        return;
    }
    let old = read_be(&d[off..off + w]);
    let max = if w == 8 {
        u64::MAX
    } else {
        (1u64 << (8 * w)) - 1
    };
    let delta = 1 + r.below(40) as u64;
    let new = match r.below(8) {
        0 => 0,
        1 => max,
        2 => old.wrapping_add(delta) & max,
        3 => old.wrapping_sub(delta) & max,
        4 => u64::from(MAX_N),
        5 => MAX_MSG as u64 + r.below(2) as u64,
        6 => r.next() & max,
        _ => (old ^ (1 << r.below(8 * w))) & max,
    };
    write_be(&mut d[off..off + w], new);
    // Make the total length agree with the edit half the time, so that
    // decoding reaches the checks behind the length check.
    if r.below(2) == 0 && new > old && new - old <= 64 * 32 {
        let at = puzzle_at(kind);
        // A count of links grows the input by b bytes each.
        let width = if off == at + 8 {
            usize::from(d[at + 5])
        } else {
            1
        };
        let grow = (new - old) as usize * width;
        let at = r.below(d.len() + 1);
        let fill: Vec<u8> = (0..grow).map(|_| r.byte()).collect();
        d.splice(at..at, fill);
    } else if r.below(2) == 0 && old > new && old - new <= 64 {
        let cut = (old - new) as usize;
        d.truncate(d.len().saturating_sub(cut));
    }
}

fn mutate(r: &mut XorShift, kind: Kind, seed: &[u8]) -> Vec<u8> {
    let mut d = seed.to_vec();
    for _ in 0..1 + r.below(3) {
        match r.below(7) {
            0 if !d.is_empty() => {
                let off = r.below(d.len());
                d[off] ^= 1 << r.below(8);
            }
            1 => {
                let at = r.below(d.len() + 1);
                let b = r.byte();
                d.insert(at, b);
            }
            2 if !d.is_empty() => {
                let at = r.below(d.len());
                d.remove(at);
            }
            3 => {
                let n = r.below(d.len() + 1);
                d.truncate(n);
            }
            4 => {
                for _ in 0..1 + r.below(40) {
                    d.push(r.byte());
                }
            }
            5 if !d.is_empty() => {
                let off = r.below(d.len());
                d[off] = r.byte();
            }
            _ => edit_length(r, kind, &mut d),
        }
    }
    d
}

#[test]
fn decoders_hold_their_invariants_under_mutation() {
    assert!(alloc_count::installed());
    let start = Instant::now();
    let seeds = seeds::all();
    let mut r = XorShift(0x9e37_79b9_7f4a_7c15);
    let (mut cases, mut accepted, mut opened) = (0usize, [0usize; 4], 0usize);
    for s in &seeds {
        // The unmodified encodings satisfy every invariant and decode.
        let enc = s.puzzle.encode().unwrap();
        assert_eq!(checks::puzzle(&enc), Some(s.puzzle.clone()));
        assert_eq!(checks::secret(&s.secret), Some((s.puzzle.clone(), s.key)));
        let (ok, open) = checks::envelope(&s.envelope, Some(&s.key));
        assert!(ok && open.is_some_and(|o| o.is_ok()), "{}", s.name);
        assert!(checks::envelope(&s.envelope, None).0);
        assert!(checks::checkpoint(&s.checkpoint).is_some());
        assert_eq!(checks::solve_small(&s.puzzle), Some(s.key));

        for (kind, seed) in [
            (Kind::Puzzle, &enc),
            (Kind::Envelope, &s.envelope),
            (Kind::Secret, &s.secret),
            (Kind::Checkpoint, &s.checkpoint),
        ] {
            for _ in 0..CASES {
                let d = mutate(&mut r, kind, seed);
                cases += 1;
                let ok = match kind {
                    Kind::Puzzle => checks::puzzle(&d).is_some(),
                    Kind::Secret => checks::secret(&d).is_some(),
                    Kind::Checkpoint => checks::checkpoint(&d).is_some(),
                    Kind::Envelope => {
                        let (ok, open) = checks::envelope(&d, Some(&s.key));
                        if d != s.envelope {
                            // With the right key, any change is rejected.
                            if let Some(o) = &open {
                                assert!(o.is_err(), "changed envelope opened: {d:02x?}");
                            }
                        }
                        opened += usize::from(open.is_some());
                        ok
                    }
                };
                accepted[kind as usize] += usize::from(ok);
            }
        }
    }
    assert!(cases >= 20_000, "{cases} cases");
    // Each format accepts some mutations and rejects others.
    for a in accepted {
        assert!(a > 0 && a < seeds.len() * CASES, "{accepted:?} of {cases}");
    }
    assert!(opened > 0);
    let took = start.elapsed();
    eprintln!("{cases} cases, accepted {accepted:?}, {opened} opened, in {took:?}");
}

#[test]
fn decoders_reject_oversized_headers_before_allocating() {
    // A header claiming the largest puzzle, with no links behind it.
    let s = &seeds::all()[0];
    let mut enc = s.puzzle.encode().unwrap();
    enc[5] = 32;
    enc[8..12].copy_from_slice(&MAX_N.to_be_bytes());
    assert_eq!(Puzzle::decode(&enc), Err(Error::Format));
    assert_eq!(checks::puzzle(&enc), None);
    let mut env = s.envelope.clone();
    env[13] = 32;
    env[16..20].copy_from_slice(&MAX_N.to_be_bytes());
    assert!(!checks::envelope(&env, Some(&s.key)).0);
    // An envelope claiming the largest message, with no ciphertext.
    let mut env = s.envelope.clone();
    let at = 8 + 68 + s.puzzle.links().len() + 16;
    env[at..at + 4].copy_from_slice(&(MAX_MSG as u32).to_be_bytes());
    assert!(!checks::envelope(&env, Some(&s.key)).0);
    let mut sk = s.secret.clone();
    sk[45] = 32;
    sk[48..52].copy_from_slice(&MAX_N.to_be_bytes());
    assert_eq!(checks::secret(&sk), None);
}
