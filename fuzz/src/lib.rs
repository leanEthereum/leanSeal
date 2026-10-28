//! Fuzz support for leanseal's decoders.
//!
//! The modules live in `tests/support/`, which the published crate ships;
//! `tests/decode_props.rs` includes them too, so the fuzz targets and the
//! stable property test check the same invariants.
#[path = "../../tests/support/alloc_count.rs"]
pub mod alloc_count;
#[path = "../../tests/support/checks.rs"]
pub mod checks;
#[path = "../../tests/support/seeds.rs"]
pub mod seeds;

#[global_allocator]
static ALLOC: alloc_count::Counting = alloc_count::Counting;
