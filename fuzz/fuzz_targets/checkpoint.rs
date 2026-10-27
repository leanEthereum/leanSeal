#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = leanseal_fuzz::checks::checkpoint(data);
});
