#![no_main]
//! Inputs that aren't already RIFF/WEBP are wrapped in a RIFF container with a correct size, so
//! the fuzzer reaches the chunk walk and the decoder instead of stopping at the header.
use libfuzzer_sys::fuzz_target;
use intakeguard_core::Claimed;
use intakeguard_fuzz::run;

fuzz_target!(|data: &[u8]| {
    let d = if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        data.to_vec()
    } else {
        let mut v = b"RIFF".to_vec();
        v.extend_from_slice(&((data.len() + 4) as u32).to_le_bytes());
        v.extend_from_slice(b"WEBP");
        v.extend_from_slice(data);
        v
    };
    run(&d, &Claimed { filename: Some("f.webp".into()), mime: Some("image/webp".into()) });
});
