#![no_main]
use libfuzzer_sys::fuzz_target;
use intakeguard_core::Claimed;
use intakeguard_fuzz::{run, with_magic};

fuzz_target!(|data: &[u8]| {
    let d = with_magic(data, b"%PDF-1.7\n");
    run(&d, &Claimed { filename: Some("f.pdf".into()), mime: Some("application/pdf".into()) });
});
