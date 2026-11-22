//! Shared harness for the IntakeGuard fuzz targets.
//!
//! The engine catches panics at its API boundary and reports them as verdict `error` with an
//! "engine panic" detail (fail closed). For fuzzing that would hide crashes, so `check()` turns any
//! engine panic or ENGINE_INTERNAL_ERROR back into a real panic. It also asserts the report contract
//! on every input:
//! - verdict and policyDecision are valid, and every reason code is registered in spec/reasons.yaml;
//! - output bytes exist if and only if the verdict is `transformed`, with a new sha256 that matches
//!   the report;
//! - `accepted` has no failed check and no skipped check other than `scanner` (no scanners configured)
//!   and `type.mismatch` when no filename or claimed MIME was given (nothing to compare);
//! - idempotence (spec 0.1.4): sanitizing an output within maxBytes again is accepted or transformed
//!   and finds no metadata; an output over maxBytes is rejected with exactly LIMIT_BYTES_EXCEEDED.
//!
//! Any violation panics, so libFuzzer records the input as a crash.

use std::sync::OnceLock;

use intakeguard_core::{Claimed, Outcome, Policy};
use sha2::{Digest, Sha256};

/// The strict corpus policy with smaller limits, so each execution stays fast and well inside
/// libFuzzer's memory limit. Limit hits are normal verdicts, not crashes.
pub fn policy() -> &'static Policy {
    static P: OnceLock<Policy> = OnceLock::new();
    P.get_or_init(|| {
        Policy::from_json(r#"{
            "version": "0.1", "name": "fuzz",
            "allow": ["image/jpeg", "image/png", "image/webp", "application/pdf"],
            "typeMismatch": "reject",
            "limits": { "maxBytes": 1048576, "maxImagePixels": 4000000, "maxImageDimension": 4096,
                        "maxPdfPages": 100, "maxPdfObjects": 20000,
                        "maxDecompressedBytes": 33554432, "maxProcessingMs": 4000 },
            "images": { "mode": "decode-reencode", "metadata": "remove", "outputFormat": "same" }
        }"#).expect("fuzz policy is valid")
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Sanitize `data` and assert the contract. `claimed` should name the format being fuzzed.
pub fn run(data: &[u8], claimed: &Claimed) -> Outcome {
    let o = intakeguard_core::sanitize_bytes(data, policy(), claimed, None);
    check(&o, data, claimed);
    if let Some(out) = &o.output {
        // Idempotence (spec 0.1.2): the output must pass the same policy again, metadata-free.
        let mime = o.report["output"]["mime"].as_str().unwrap().to_string();
        let c2 = Claimed { filename: None, mime: Some(mime) };
        let again = intakeguard_core::sanitize_bytes(out, policy(), &c2, None);
        check(&again, out, &c2);
        let v = again.report["verdict"].as_str().unwrap();
        // Idempotence holds for outputs within maxBytes (spec 0.1.4, ADR 0007): maxBytes limits inputs,
        // not outputs, so an output larger than maxBytes must be rejected on a second pass, and only for
        // its size. Any other rejection, or a larger output that is not rejected for its size, fails.
        if out.len() as u64 > policy().limits.max_bytes {
            assert!(v == "rejected" && codes(&again) == ["LIMIT_BYTES_EXCEEDED"],
                    "re-sanitizing an output over maxBytes gave {v}: {}", again.report);
        } else {
            assert!(v == "accepted" || v == "transformed", "re-sanitizing an output gave {v}: {}", again.report);
        }
        assert!(!codes(&again).iter().any(|c| c == "IMAGE_METADATA_PRESENT"),
                "metadata found in an output: {}", again.report);
    }
    o
}

pub fn codes(o: &Outcome) -> Vec<String> {
    o.report["reasonCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect()
}

pub fn check(o: &Outcome, input: &[u8], claimed: &Claimed) {
    let nothing_claimed = claimed.filename.is_none() && claimed.mime.is_none();
    let r = &o.report;
    let checks = r["checks"].as_array().expect("checks array");
    for c in checks {
        if let Some(d) = c["detail"].as_str() {
            assert!(!d.starts_with("engine panic"), "engine panic: {d}");
        }
    }
    let codes = codes(o);
    assert!(!codes.iter().any(|c| c == "ENGINE_INTERNAL_ERROR"), "ENGINE_INTERNAL_ERROR: {r}");
    let reg = intakeguard_core::report::registry();
    for c in &codes {
        assert!(reg.contains_key(c), "unregistered reason code {c}");
    }
    let verdict = r["verdict"].as_str().expect("verdict");
    assert!(["accepted", "transformed", "rejected", "error"].contains(&verdict), "verdict {verdict}");
    let decision = r["policyDecision"].as_str().expect("policyDecision");
    assert!(["accept", "transform", "reject", "error"].contains(&decision), "policyDecision {decision}");
    assert_eq!(decision, o.decision.as_str());
    if matches!(decision, "reject" | "error") {
        assert!(verdict == "rejected" || verdict == "error", "decision {decision} but verdict {verdict}");
    }
    if verdict == "rejected" {
        assert!(!codes.is_empty(), "rejected without reason codes: {r}");
    }
    assert_eq!(r["original"]["sha256"].as_str().unwrap(), hex(&Sha256::digest(input)));
    match (&o.output, verdict) {
        (Some(out), "transformed") => {
            assert!(!out.is_empty());
            let sha = hex(&Sha256::digest(out));
            assert_eq!(r["output"]["sha256"].as_str().unwrap(), sha, "output sha256 mismatch");
            assert_eq!(r["output"]["bytes"].as_u64().unwrap(), out.len() as u64);
            assert_ne!(sha, r["original"]["sha256"].as_str().unwrap(), "output equals original");
        }
        (None, "transformed") => panic!("transformed without output"),
        (Some(_), v) => panic!("output bytes with verdict {v}"),
        (None, _) => assert!(r["output"].is_null(), "report.output set without bytes"),
    }
    if verdict == "accepted" {
        for c in checks {
            let (id, st) = (c["id"].as_str().unwrap(), c["status"].as_str().unwrap());
            assert!(st != "failed", "accepted with failed check {id}: {r}");
            let not_applicable = id == "scanner" || (id == "type.mismatch" && nothing_claimed);
            assert!(st != "skipped" || not_applicable, "accepted with skipped check {id}: {r}");
        }
    }
}

/// Make sure the input starts with `magic`, so the fuzzer spends its time inside one format's parser.
pub fn with_magic(data: &[u8], magic: &[u8]) -> Vec<u8> {
    if data.starts_with(magic) { data.to_vec() } else { [magic, data].concat() }
}
