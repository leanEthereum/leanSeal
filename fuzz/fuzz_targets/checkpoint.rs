#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = chainseal_fuzz::checks::checkpoint(data);
});
