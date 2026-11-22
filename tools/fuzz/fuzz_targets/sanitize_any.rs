#![no_main]
//! Any bytes, no claimed type. Also checks that the in-memory and streaming APIs agree.
use libfuzzer_sys::fuzz_target;
use intakeguard_core::Claimed;
use intakeguard_fuzz::{check, codes, policy, run};

/// A reader that returns at most 7 bytes per call, to exercise the streaming path's chunking.
struct Trickle<'a>(&'a [u8]);
impl std::io::Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.len().min(buf.len()).min(7);
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

fuzz_target!(|data: &[u8]| {
    let claimed = Claimed::default();
    let a = run(data, &claimed);
    let b = intakeguard_core::sanitize_reader(Trickle(data), policy(), &claimed, None);
    check(&b, data, &claimed);
    assert_eq!(a.report["verdict"], b.report["verdict"], "bytes vs stream verdict differ");
    assert_eq!(codes(&a), codes(&b), "bytes vs stream reason codes differ");
    assert_eq!(a.output, b.output, "bytes vs stream output differ");
});
