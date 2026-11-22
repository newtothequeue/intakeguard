#![no_main]
use libfuzzer_sys::fuzz_target;
use intakeguard_core::Claimed;
use intakeguard_fuzz::{run, with_magic};

fuzz_target!(|data: &[u8]| {
    let d = with_magic(data, b"\xFF\xD8\xFF");
    run(&d, &Claimed { filename: Some("f.jpg".into()), mime: Some("image/jpeg".into()) });
});
