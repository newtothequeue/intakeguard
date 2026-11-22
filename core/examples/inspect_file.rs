//! Bake-off helper: inspect one file N times natively and print JSON with latency and peak RSS.
//!   inspect_file <policy.json> <file> <filename> [claimed-mime|-] [iterations] [inspect|sanitize]
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let policy = intakeguard_core::Policy::from_json(&std::fs::read_to_string(&a[1]).unwrap()).unwrap();
    let data = std::fs::read(&a[2]).unwrap();
    let claimed = intakeguard_core::Claimed {
        filename: Some(a[3].clone()),
        mime: a.get(4).filter(|m| *m != "-").cloned(),
    };
    let n: usize = a.get(5).map(|s| s.parse().unwrap()).unwrap_or(1);
    let mode = if a.get(6).map(String::as_str) == Some("sanitize") { intakeguard_core::Mode::Sanitize } else { intakeguard_core::Mode::Inspect };
    let rss0 = peak_kib();
    let mut ts = Vec::with_capacity(n);
    let mut verdict = String::new();
    for _ in 0..n {
        let t = Instant::now();
        let o = intakeguard_core::process_bytes(&data, &policy, &claimed, None, mode);
        ts.push(t.elapsed().as_secs_f64() * 1000.0);
        verdict = o.report["verdict"].as_str().unwrap().to_string();
    }
    ts.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let q = |p: f64| ts[((p / 100.0) * (ts.len() - 1) as f64).round() as usize];
    println!("{{\"verdict\":\"{verdict}\",\"p50\":{:.5},\"p95\":{:.5},\"n\":{n},\"rssBeforeKiB\":{rss0},\"rssPeakKiB\":{}}}",
             q(50.0), q(95.0), peak_kib());
}

/// Peak resident memory of this process in KiB (0 if it can't be measured on this platform).
fn peak_kib() -> u64 {
    platform::peak_kib()
}

#[cfg(target_os = "linux")]
mod platform {
    pub fn peak_kib() -> u64 {
        std::fs::read_to_string("/proc/self/status").ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok())))
            .unwrap_or(0)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    // struct rusage: two struct timeval (16 bytes each on 64-bit), then 14 longs; ru_maxrss is the
    // first long and is in BYTES on macOS.
    #[repr(C)]
    struct RUsage { times: [u8; 32], longs: [i64; 14] }
    extern "C" { fn getrusage(who: i32, usage: *mut RUsage) -> i32; }
    pub fn peak_kib() -> u64 {
        let mut u = RUsage { times: [0; 32], longs: [0; 14] };
        // RUSAGE_SELF = 0
        if unsafe { getrusage(0, &mut u) } == 0 { (u.longs[0] as u64) / 1024 } else { 0 }
    }
}

#[cfg(windows)]
mod platform {
    #[repr(C)]
    struct Pmc {
        cb: u32, page_fault_count: u32, peak_working_set_size: usize, working_set_size: usize,
        quota_peak_paged_pool_usage: usize, quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize, quota_non_paged_pool_usage: usize,
        pagefile_usage: usize, peak_pagefile_usage: usize,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn K32GetProcessMemoryInfo(p: *mut core::ffi::c_void, c: *mut Pmc, cb: u32) -> i32;
    }
    pub fn peak_kib() -> u64 {
        let mut c: Pmc = unsafe { core::mem::zeroed() };
        c.cb = core::mem::size_of::<Pmc>() as u32;
        if unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) } != 0 {
            (c.peak_working_set_size / 1024) as u64
        } else { 0 }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    pub fn peak_kib() -> u64 { 0 }
}
