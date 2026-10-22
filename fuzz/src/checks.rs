//! Decoder invariants, checked for every input.
//!
//! 1. No decoder panics, and none holds more than `2 * len + SLACK` heap
//!    bytes while deciding.
//! 2. Accepted puzzles, secrets and checkpoints re-encode to the input.
//! 3. `Envelope::open` returns plaintext only for an envelope that is exactly
//!    the sealing of that plaintext under that key; a wrong key gets
//!    `Commit` or `Tag`.
//! 4. `checkpoint_peek` agrees with `Cursor::decode` on id and position.
use crate::alloc_count::measure;
use chainseal::{
    backend::Backend, checkpoint_peek, seal, secret_decode, secret_encode, Cursor, Envelope, Error,
    Puzzle, MAX_N,
};

/// Constant allowance on top of twice the input length.
pub const SLACK: usize = 1024;
/// Largest `n * m` that the checks solve to learn an envelope's key.
pub const SOLVE_LIMIT: u64 = 4096;
/// Length of a checkpoint encoding.
pub const CHECKPOINT_LEN: usize = 116;

/// Run a decoder on `data` and check its allocation bound.
fn bounded<R>(data: &[u8], f: impl FnOnce() -> R) -> R {
    let (r, peak) = measure(f);
    assert!(
        peak <= 2 * data.len() + SLACK,
        "decoder held {peak} bytes for a {}-byte input",
        data.len()
    );
    r
}

/// Solve a small puzzle; `None` if it is too large or does not solve.
pub fn solve_small(p: &Puzzle) -> Option<[u8; 32]> {
    if u64::from(p.n()) * p.m() > SOLVE_LIMIT {
        return None;
    }
    let mut cur = p.cursor();
    p.solve(&mut cur, Backend::PORTABLE, 0, |_| false).ok()
}

/// Puzzle invariants; returns the puzzle when `data` decodes.
pub fn puzzle(data: &[u8]) -> Option<Puzzle> {
    let p = bounded(data, || Puzzle::decode(data)).ok()?;
    assert_eq!(p.encode().expect("encode decoded puzzle"), data);
    assert_eq!(p.links().len(), p.n() as usize * p.b() as usize);
    let _ = (p.id(), p.cursor());
    Some(p)
}

/// Secret invariants; returns the puzzle and key when `data` decodes.
pub fn secret(data: &[u8]) -> Option<(Puzzle, [u8; 32])> {
    let (p, k) = bounded(data, || secret_decode(data)).ok()?;
    assert!(p.check_key(&k));
    assert_eq!(secret_encode(&p, &k).expect("encode decoded secret"), data);
    Some((p, k))
}

/// Open with `key` and check that plaintext comes only from an exact sealing.
fn open_checked(e: &Envelope<'_>, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let r = bounded(data, || e.open(key));
    match &r {
        Ok(pt) => {
            assert!(e.puzzle.check_key(key));
            let again = seal(&e.puzzle, key, &e.nonce, pt).expect("reseal");
            assert_eq!(again, data, "open accepted a non-canonical envelope");
        }
        Err(err) => assert!(matches!(err, Error::Commit | Error::Tag), "{err:?}"),
    }
    r
}

/// Envelope invariants. `key` is the key the input was sealed under, if known;
/// otherwise small puzzles are solved to find it. Returns whether `data`
/// decoded and the result of opening it with the key, when there is one.
pub fn envelope(data: &[u8], key: Option<&[u8; 32]>) -> (bool, Option<Result<Vec<u8>, Error>>) {
    let Ok(e) = bounded(data, || Envelope::decode(data)) else {
        return (false, None);
    };
    assert_eq!(
        data.len(),
        128 + e.puzzle.links().len() + e.message_len(),
        "envelope length"
    );
    let key = key.copied().or_else(|| solve_small(&e.puzzle));
    let mut wrong = key.unwrap_or([0; 32]);
    wrong[31] ^= 1;
    for w in [wrong, [0xa5; 32]] {
        if key != Some(w) && !e.puzzle.check_key(&w) {
            assert_eq!(open_checked(&e, data, &w), Err(Error::Commit));
        } else {
            let _ = open_checked(&e, data, &w);
        }
    }
    (true, key.map(|k| open_checked(&e, data, &k)))
}

/// Checkpoint invariants. The input is a checkpoint followed by the puzzle
/// encoding it is decoded against. Returns the cursor when both decode.
pub fn checkpoint(data: &[u8]) -> Option<Cursor> {
    let whole = bounded(data, || checkpoint_peek(data));
    if data.len() != CHECKPOINT_LEN {
        assert_eq!(whole, Err(Error::Format));
    }
    if data.len() < CHECKPOINT_LEN {
        return None;
    }
    let (ck, rest) = data.split_at(CHECKPOINT_LEN);
    let peek = bounded(ck, || checkpoint_peek(ck));
    if let Ok((_, i, j)) = peek {
        assert!((1..=MAX_N).contains(&i));
        assert!(j <= chainseal::MAX_M && u64::from(i) * j <= chainseal::MAX_WORK);
    }
    let p = puzzle(rest)?;
    match bounded(ck, || Cursor::decode(&p, ck)) {
        Ok(cur) => {
            assert_eq!(cur.encode(&p).expect("encode decoded checkpoint"), ck);
            let (id, i, j) = peek.expect("peek rejects a checkpoint that decodes");
            assert_eq!((id, i, j), (p.id(), cur.i, cur.j));
            assert!(cur.i <= p.n() && cur.j <= p.m());
            if u64::from(p.n()) * p.m() <= SOLVE_LIMIT {
                // Resuming from unauthenticated state must fail cleanly at worst.
                let mut c = cur.clone();
                let r = p.solve(&mut c, Backend::PORTABLE, 0, |_| false);
                assert!(r.is_ok() || r == Err(Error::Puzzle), "{r:?}");
            }
            Some(cur)
        }
        Err(err) => {
            match peek {
                Ok((id, _, _)) if id != p.id() => assert_eq!(err, Error::Mismatch),
                Ok(_) => assert_eq!(err, Error::Range),
                Err(e) => assert!(err == e || err == Error::Mismatch, "{err:?} vs {e:?}"),
            }
            None
        }
    }
}
