//! Write the seed corpora: `cargo run --example gen_corpus` from `fuzz/`.
use std::{fs, path::Path};

fn main() -> std::io::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    for s in chainseal_fuzz::seeds::all() {
        for (target, bytes) in [
            ("puzzle", s.puzzle.encode().expect("encode puzzle")),
            ("envelope", s.envelope),
            ("secret", s.secret),
            ("checkpoint", s.checkpoint),
        ] {
            let dir = root.join(target);
            fs::create_dir_all(&dir)?;
            fs::write(dir.join(format!("seed-{}", s.name)), bytes)?;
        }
    }
    Ok(())
}
