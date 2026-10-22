//! Deterministic randomness for reproducible test vectors.
use crate::hash::{sha256, th};
/// SHA-256 counter generator, for tests only.
pub struct TestRng {
    seed: [u8; 32],
    counter: u64,
}
impl TestRng {
    /// Hash a seed and start at counter zero.
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed: sha256(seed),
            counter: 0,
        }
    }
    /// Fill bytes; each call consumes complete 32-byte counter blocks.
    pub fn fill(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            let block = th(
                "chainseal/test-rng",
                &[&self.seed, &self.counter.to_be_bytes()],
            );
            self.counter = self.counter.wrapping_add(1);
            let take = out.len().min(32);
            out[..take].copy_from_slice(&block[..take]);
            out = &mut out[take..];
        }
    }
}
