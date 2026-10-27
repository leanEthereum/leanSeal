//! Fuzz support for leanseal's decoders.
//!
//! `tests/decode_props.rs` includes these modules by path, so the fuzz
//! targets and the stable property test check the same invariants.
pub mod alloc_count;
pub mod checks;
pub mod seeds;

#[global_allocator]
static ALLOC: alloc_count::Counting = alloc_count::Counting;
