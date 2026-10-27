#![no_main]
// No key is known for an arbitrary input; the check solves small puzzles itself.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = leanseal_fuzz::checks::envelope(data, None);
});
