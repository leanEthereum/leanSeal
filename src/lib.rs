//! Time-lock encryption using SHA-256 chains, implementing chainseal v1.
#![deny(unsafe_code)]
#![warn(missing_docs)]
pub mod backend;
pub mod benchmark;
mod envelope;
pub mod hash;
mod puzzle;
pub mod rng;
pub mod runtime;
mod signal;
pub mod vectors;
pub use envelope::*;
pub use puzzle::*;
use std::fmt;

/// Maximum number of chains.
pub const MAX_N: u32 = 1 << 20;
/// Maximum steps per chain.
pub const MAX_M: u64 = 1 << 48;
/// Maximum total work.
pub const MAX_WORK: u64 = 1 << 60;
/// Maximum plaintext length.
pub const MAX_MSG: usize = 1 << 24;
/// Errors corresponding to the C CS_E* codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Error {
    /// Malformed encoding (CS_EFORMAT).
    Format = 1,
    /// Parameter out of range (CS_ERANGE).
    Range = 2,
    /// Key commitment mismatch (CS_ECOMMIT).
    Commit = 3,
    /// Invalid authentication tag (CS_ETAG).
    Tag = 4,
    /// The puzzle solves to an uncommitted key (CS_EPUZZLE).
    Puzzle = 5,
    /// Checkpoint puzzle ID mismatch (CS_EMISMATCH).
    Mismatch = 6,
    /// Allocation failed (CS_ENOMEM).
    Memory = 7,
    /// Operating system entropy failed (CS_ERNG).
    Rng = 8,
    /// Progress callback requested a stop (CS_ESTOPPED).
    Stopped = 9,
    /// Requested backend is unavailable.
    Backend = 10,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Format => "malformed input",
            Self::Range => "parameter out of range",
            Self::Commit => "key does not match the puzzle's commitment",
            Self::Tag => "authentication failed: the envelope was modified or the key is wrong",
            Self::Puzzle => "puzzle is malformed: solving it does not yield the committed key",
            Self::Mismatch => "checkpoint belongs to a different puzzle",
            Self::Memory => "out of memory",
            Self::Rng => "random number generator failed",
            Self::Stopped => "stopped",
            Self::Backend => "backend is not available on this machine",
        })
    }
}
impl std::error::Error for Error {}
/// A chainseal operation result.
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn bytes(n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Memory)?;
    v.resize(n, 0);
    Ok(v)
}
pub(crate) fn array<const N: usize>(b: &[u8]) -> Result<[u8; N]> {
    b.try_into().map_err(|_| Error::Format)
}
