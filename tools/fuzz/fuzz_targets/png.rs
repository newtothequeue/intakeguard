#![no_main]
use libfuzzer_sys::fuzz_target;
use intakeguard_core::Claimed;
use intakeguard_fuzz::{run, with_magic};

fuzz_target!(|data: &[u8]| {
    let d = with_magic(data, b"\x89PNG\r\n\x1a\n");
    run(&d, &Claimed { filename: Some("f.png".into()), mime: Some("image/png".into()) });
});
