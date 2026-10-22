//! Small valid encodings: the fuzz seeds and the property test's starting points.
use chainseal::{generate_from, rng::TestRng, seal, secret_encode, GenOptions, Puzzle};

/// Puzzle shapes `(n, m, b)`: n from 1 to 5, m from 1 to 100, b of 1, 16 and 32.
pub const SHAPES: [(u32, u64, u8); 12] = [
    (1, 1, 1),
    (1, 37, 16),
    (1, 100, 32),
    (2, 1, 16),
    (2, 7, 32),
    (3, 20, 1),
    (3, 100, 16),
    (4, 3, 1),
    (4, 50, 32),
    (5, 1, 1),
    (5, 13, 16),
    (5, 100, 32),
];

/// One puzzle with its key and the four encodings built from it.
pub struct Seed {
    /// File-name stem, such as `n3-m20-b1`.
    pub name: String,
    /// The puzzle.
    pub puzzle: Puzzle,
    /// Its key.
    pub key: [u8; 32],
    /// An envelope sealed to the puzzle.
    pub envelope: Vec<u8>,
    /// The secret encoding of the puzzle and key.
    pub secret: Vec<u8>,
    /// A checkpoint of a partial solve, followed by the puzzle encoding.
    pub checkpoint: Vec<u8>,
}

/// Build one seed per entry of [`SHAPES`], deterministically.
pub fn all() -> Vec<Seed> {
    let mut rng = TestRng::new(b"chainseal fuzz seeds");
    SHAPES
        .iter()
        .enumerate()
        .map(|(k, &(n, m, b))| {
            let mut salt = [0; 16];
            let mut x = vec![0; n as usize * b as usize];
            let mut nonce = [0; 16];
            let mut msg = vec![0; [0, 1, 31, 32, 33, 70][k % 6]];
            rng.fill(&mut salt);
            rng.fill(&mut x);
            rng.fill(&mut nonce);
            rng.fill(&mut msg);
            let (puzzle, key, _) =
                generate_from(n, m, b, salt, &x, &GenOptions::default()).expect("generate");
            // Positions: the start, the middle of some chain, and the very end.
            let (ti, tj) = match k % 3 {
                0 => (1, 0),
                1 => (1 + k as u32 % n, 1 + k as u64 % m),
                _ => (n, m),
            };
            let mut cur = puzzle.cursor();
            if tj > 0 {
                let be = chainseal::backend::Backend::PORTABLE;
                let r = puzzle.solve(&mut cur, be, 1, |c| c.i == ti && c.j == tj);
                assert_eq!(r, Err(chainseal::Error::Stopped));
            }
            let mut checkpoint = cur.encode(&puzzle).expect("encode checkpoint");
            checkpoint.extend(puzzle.encode().expect("encode puzzle"));
            Seed {
                name: format!("n{n}-m{m}-b{b}"),
                envelope: seal(&puzzle, &key, &nonce, &msg).expect("seal"),
                secret: secret_encode(&puzzle, &key).expect("encode secret"),
                checkpoint,
                puzzle,
                key,
            }
        })
        .collect()
}
