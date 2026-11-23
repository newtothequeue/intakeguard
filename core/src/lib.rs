//! IntakeGuard core (native Rust, ADR 0002).
//!
//! Two entry points per input kind:
//! - `inspect_*`: every check, no output artifact. An image the policy would transform is reported
//!   `rejected` (UNSUPPORTED_FEATURE: no artifact) with `policyDecision: "transform"`.
//! - `sanitize_*`: the same checks, then decode-reencode for JPEG/PNG/WebP when the policy says
//!   so. The output is new bytes, re-inspected under the same policy before it is returned.

pub mod policy;
pub mod report;
mod detect;
mod exif;
mod images;
mod pdf;
mod transform;

use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use sha2::{Digest, Sha256};

pub use policy::Policy;
use report::{Abort, Ctx, Decision, ReportInput};

pub const ENGINE_VERSION: &str = concat!("intakeguard-core/", env!("CARGO_PKG_VERSION"));
/// Largest single read when streaming.
pub const STREAM_CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, Default)]
pub struct Claimed {
    pub filename: Option<String>,
    pub mime: Option<String>,
}

pub struct Outcome {
    /// The report, valid against spec/verdict.schema.json.
    pub report: serde_json::Value,
    /// Policy decision before any transformation. Differs from the report verdict only when the
    /// policy asks for a transformation this release cannot perform.
    pub decision: Decision,
    /// Bytes actually pulled from the input (equals the input size unless the stream was cut off).
    pub bytes_read: u64,
    /// The sanitized artifact. Present if and only if the report verdict is `transformed`.
    pub output: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode { Inspect, Sanitize }

/// Inspect an in-memory buffer (no output artifact).
pub fn inspect_bytes(data: &[u8], policy: &Policy, claimed: &Claimed, cancel: Option<&AtomicBool>) -> Outcome {
    process_bytes(data, policy, claimed, cancel, Mode::Inspect)
}

/// Inspect and, where the policy says so, produce a sanitized artifact.
pub fn sanitize_bytes(data: &[u8], policy: &Policy, claimed: &Claimed, cancel: Option<&AtomicBool>) -> Outcome {
    process_bytes(data, policy, claimed, cancel, Mode::Sanitize)
}

pub fn inspect_reader<R: Read>(r: R, policy: &Policy, claimed: &Claimed, cancel: Option<&AtomicBool>) -> Outcome {
    process_reader(r, policy, claimed, cancel, Mode::Inspect)
}

pub fn sanitize_reader<R: Read>(r: R, policy: &Policy, claimed: &Claimed, cancel: Option<&AtomicBool>) -> Outcome {
    process_reader(r, policy, claimed, cancel, Mode::Sanitize)
}

pub fn process_bytes(data: &[u8], policy: &Policy, claimed: &Claimed, cancel: Option<&AtomicBool>, mode: Mode) -> Outcome {
    let start = Instant::now();
    let total = data.len() as u64;
    guarded(policy, claimed, cancel, start, data, total, hex256(data), total > policy.limits.max_bytes, true, mode)
}

/// Process a stream. Pulls at most `maxBytes + 1` bytes from the reader; never buffers more.
/// When the limit is exceeded the reported sha256/bytes describe only the prefix that was read
/// (the rest is never pulled from the stream).
pub fn process_reader<R: Read>(mut r: R, policy: &Policy, claimed: &Claimed, cancel: Option<&AtomicBool>,
                               mode: Mode) -> Outcome {
    let start = Instant::now();
    let cap = policy.limits.max_bytes;
    let mut buf: Vec<u8> = Vec::new();
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; STREAM_CHUNK];
    let mut probe = Ctx::new(policy.limits.max_processing_ms, cancel);
    probe.start = start;
    loop {
        if let Err(a) = probe.check_now() {
            let read = buf.len() as u64;
            apply_abort(&mut probe, "limit.bytes", a);
            let sha = policy::hex(&hasher.finalize());
            let dec = if probe.errored { Decision::Error } else { Decision::Reject };
            return finish(probe, policy, claimed, None, sha, read, read, dec, false, None);
        }
        // Never ask for more than one byte past the limit: the overshoot is at most 1 byte.
        let want = (cap + 1 - buf.len() as u64).min(STREAM_CHUNK as u64) as usize;
        match r.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&chunk[..n]);
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() as u64 > cap { break; }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let read = buf.len() as u64;
                let sha = policy::hex(&hasher.finalize());
                return error_outcome(policy, claimed, start, sha, read, &format!("read error: {e}"), false);
            }
        }
    }
    let read = buf.len() as u64;
    let sha = policy::hex(&hasher.finalize());
    // complete=false when the limit stopped reading: the rest of the stream was never pulled.
    guarded(policy, claimed, cancel, start, &buf, read, sha, read > cap, read <= cap, mode)
}

fn hex256(d: &[u8]) -> String { policy::hex(&Sha256::digest(d)) }

#[allow(clippy::too_many_arguments)]
fn guarded(policy: &Policy, claimed: &Claimed, cancel: Option<&AtomicBool>, start: Instant,
           data: &[u8], bytes: u64, sha: String, limited: bool, complete: bool, mode: Mode) -> Outcome {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let mut ctx = Ctx::new(policy.limits.max_processing_ms, cancel);
        ctx.start = start;
        let (det, dec) = run(&mut ctx, policy, claimed, data, bytes, limited);
        let art = match (dec, mode, det) {
            (Decision::Transform, Mode::Sanitize, Some((mime, _))) => Some(sanitize(&mut ctx, policy, mime, data, cancel)),
            _ => None,
        };
        (ctx, det, dec, art)
    }));
    match res {
        Ok((ctx, det, dec, art)) => finish(ctx, policy, claimed, det, sha, bytes, bytes, dec, complete, art),
        Err(p) => {
            let msg = p.downcast_ref::<&str>().map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_else(|| "panic".into());
            error_outcome(policy, claimed, start, sha, bytes, &format!("engine panic: {msg}"), complete)
        }
    }
}

/// decode-reencode, then re-inspect the output under the same policy (format-guarantees: the
/// output "passes the same policy when re-inspected").
fn sanitize(ctx: &mut Ctx, policy: &Policy, mime: &'static str, data: &[u8], cancel: Option<&AtomicBool>)
            -> Result<transform::Artifact, transform::Failure> {
    use transform::Failure;
    let a = transform::run(ctx, policy, mime, data)?;
    let mut rc = Ctx::new(policy.limits.max_processing_ms, cancel);
    rc.start = ctx.start;
    let claimed = Claimed { filename: None, mime: Some(a.mime.to_string()) };
    // maxBytes limits the input only (spec 0.1.2): the output is never rejected for its size.
    let (det, dec) = run(&mut rc, policy, &claimed, &a.bytes, a.bytes.len() as u64, false);
    let mut problems: Vec<String> = Vec::new();
    if det.map(|d| d.0) != Some(a.mime) { problems.push(format!("re-detected as {:?}", det.map(|d| d.0))); }
    if !matches!(dec, Decision::Transform | Decision::Accept) { problems.push(format!("re-inspection decision {}", dec.as_str())); }
    for c in &rc.codes { problems.push(format!("re-inspection reported {c}")); }
    match rc.checks.iter().find(|c| c.id == "image.dimensions").and_then(|c| c.detail.clone()) {
        Some(d) if d.starts_with(&format!("{}x{} ", a.w, a.h)) => {}
        other => problems.push(format!("re-inspected dimensions {other:?}, expected {}x{}", a.w, a.h)),
    }
    if !problems.is_empty() {
        return Err(Failure::Failed(format!("output failed re-inspection: {}", problems.join("; "))));
    }
    Ok(a)
}

const GENERIC_CHECKS: &[&str] = &["input.nonempty", "limit.bytes", "type.detect", "type.polyglot",
                                  "type.allowlist", "type.mismatch"];

/// The check pipeline. Returns the detected type (if reportable) and the policy decision.
fn run(ctx: &mut Ctx, policy: &Policy, claimed: &Claimed, data: &[u8], bytes: u64, limited: bool)
       -> (Option<(&'static str, &'static str)>, Decision) {
    let short = |ctx: &mut Ctx, ids: &[&'static str]| {
        for id in ids { ctx.skip(id, "short-circuited after rejection"); }
    };
    if bytes == 0 {
        ctx.fail("input.nonempty", "INPUT_EMPTY", "input has zero bytes");
        short(ctx, &GENERIC_CHECKS[1..]);
        return (None, Decision::Reject);
    }
    ctx.pass("input.nonempty");
    if limited {
        ctx.fail("limit.bytes", "LIMIT_BYTES_EXCEEDED",
                 format!("stopped after {bytes} bytes; maxBytes={}", policy.limits.max_bytes));
        short(ctx, &GENERIC_CHECKS[2..]);
        return (None, Decision::Reject);
    }
    ctx.pass("limit.bytes");

    // --- type detection
    let det = detect::detect(data);
    let Some(mime) = det.mime else {
        ctx.fail("type.detect", "TYPE_UNKNOWN", "no supported signature in the first bytes");
        short(ctx, &GENERIC_CHECKS[3..]);
        return (None, Decision::Reject);
    };
    ctx.pass_detail("type.detect", format!("{mime} ({})", det.how));
    if let Some(why) = det.polyglot {
        ctx.fail("type.polyglot", "TYPE_POLYGLOT", why);
        short(ctx, &GENERIC_CHECKS[4..]);
        return (None, Decision::Reject);
    }
    ctx.pass("type.polyglot");
    if !policy.allow.iter().any(|a| a == mime) {
        ctx.fail("type.allowlist", "TYPE_NOT_ALLOWED", format!("{mime} not in policy allow list"));
        short(ctx, &GENERIC_CHECKS[5..]);
        return (Some((mime, "signature")), Decision::Reject);
    }
    ctx.pass("type.allowlist");
    detect::mismatch(ctx, policy, claimed, mime);

    // --- format checks
    let structural = match mime {
        "application/pdf" => pdf::inspect(ctx, policy, data),
        _ => images::inspect(ctx, policy, mime, data),
    };
    if let Err(a) = ctx.check_now() { apply_abort(ctx, "limit.time", a); } else { ctx.pass("limit.time"); }
    if policy.scanners.is_empty() {
        ctx.skip("scanner", "no scanners configured");
    } else {
        // Configured scanners are not implemented in this release; a check that wasn't run is not a pass.
        ctx.fail("scanner", "SCANNER_ERROR", "scanner hooks are not implemented in this release");
    }
    let conf = if structural { "structural" } else { "signature" };
    let decision = if ctx.errored { Decision::Error }
        else if ctx.rejected { Decision::Reject }
        else if mime.starts_with("image/") && policy.images.mode == "decode-reencode" { Decision::Transform }
        else { Decision::Accept };
    (Some((mime, conf)), decision)
}

/// Map an early stop to a failed check.
pub(crate) fn apply_abort(ctx: &mut Ctx, id: &'static str, a: Abort) {
    match a {
        Abort::Time => ctx.fail("limit.time", "LIMIT_TIME_EXCEEDED",
                                format!("exceeded maxProcessingMs={}", ctx.max_ms)),
        Abort::Cancelled => ctx.fail("engine.cancel", "ENGINE_CANCELLED", "cancelled by caller"),
        Abort::Truncated(d) => ctx.fail(id, "STRUCTURE_TRUNCATED", d),
        Abort::Malformed(d) => ctx.fail(id, "STRUCTURE_MALFORMED", d),
        Abort::Unsupported(d) => ctx.fail(id, "UNSUPPORTED_FEATURE", d),
        Abort::Decompressed(d) => ctx.fail("limit.decompressed", "LIMIT_DECOMPRESSED_BYTES_EXCEEDED", d),
        Abort::Objects(d) => ctx.fail("pdf.objects", "LIMIT_PDF_OBJECTS_EXCEEDED", d),
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(mut ctx: Ctx, policy: &Policy, claimed: &Claimed, det: Option<(&'static str, &'static str)>,
          sha: String, bytes: u64, bytes_read: u64, decision: Decision, complete: bool,
          art: Option<Result<transform::Artifact, transform::Failure>>) -> Outcome {
    let mut output: Option<Vec<u8>> = None;
    let mut out_meta: Option<(String, u64, &'static str, String)> = None;
    let mut transformations: Vec<(&'static str, Option<String>)> = Vec::new();
    let mut verdict = match decision {
        Decision::Accept => "accepted",
        Decision::Reject => "rejected",
        Decision::Error => "error",
        Decision::Transform => match art {
            None => {
                // inspect(): no artifact is produced, so the file can't be used as-is. Fail closed.
                ctx.fail("image.transform", "UNSUPPORTED_FEATURE",
                         "inspect() produces no output artifact; use sanitize() to get the re-encoded image");
                "rejected"
            }
            Some(Err(transform::Failure::Abort(a))) => {
                apply_abort(&mut ctx, "image.transform", a);
                if ctx.errored { "error" } else { "rejected" }
            }
            Some(Err(transform::Failure::Failed(why))) => {
                ctx.fail("image.transform", "TRANSFORM_FAILED", why);
                "error"
            }
            Some(Ok(a)) => {
                let osha = hex256(&a.bytes);
                if osha == sha {
                    // The input is already exactly what this engine emits (e.g. a previously sanitized
                    // lossless image). A transformed output must differ from the original, and the
                    // original already passes the policy, so it is accepted unchanged.
                    ctx.pass_detail("image.transform", "re-encoding reproduced the input byte-for-byte; \
                                     the input is already in sanitized form");
                    "accepted"
                } else {
                    let in_mime = det.map(|d| d.0).unwrap_or("");
                    ctx.pass_detail("image.transform", format!("{} -> {}, {}x{}, {} bytes", in_mime, a.mime, a.w, a.h, a.bytes.len()));
                    transformations.push(("image.decode-reencode", Some(a.notes.join("; ")).filter(|s| !s.is_empty())));
                    if ctx.codes.contains(&"IMAGE_METADATA_PRESENT") {
                        let what = ctx.checks.iter().find(|c| c.id == "image.metadata").and_then(|c| c.detail.clone());
                        transformations.push(("image.metadata-removed", what));
                    }
                    if a.mime != in_mime {
                        transformations.push(("image.format-converted", Some(format!("{in_mime} -> {}", a.mime))));
                    }
                    let handle = format!("o_{}", &osha[..16]);
                    out_meta = Some((osha, a.bytes.len() as u64, a.mime, handle));
                    output = Some(a.bytes);
                    "transformed"
                }
            }
        },
    };
    // A transformed verdict needs a clean report: any rejecting/error finding wins.
    if verdict == "transformed" && (ctx.rejected || ctx.errored) {
        verdict = if ctx.errored { "error" } else { "rejected" };
        output = None;
        out_meta = None;
        transformations.clear();
    }
    if !complete {
        ctx.warnings.push(format!("original.sha256 and original.bytes cover only the first {bytes} bytes read; \
                                   reading stopped before end of input"));
    }
    let mut ng = vec!["not scanned for malware"];
    if verdict == "transformed" {
        ng.push("pixel data is decoded and re-encoded; steganographic content in pixels is not removed");
        if out_meta.as_ref().map(|m| m.2) == Some("image/jpeg") { ng.push("JPEG output is not bit-identical to the input pixels"); }
        ng.push("ICC profiles and EXIF orientation are dropped, not applied");
    }
    if det.map(|d| d.0) == Some("application/pdf") {
        ng.push("not checked for viewer-specific exploits");
        ng.push("hidden-text detection is a heuristic, not a prompt-injection guarantee");
    }
    let (filename, extension) = detect::split_name(claimed.filename.as_deref());
    let ms = ctx.elapsed_ms();
    let report = report::render(&ctx, ReportInput {
        engine_version: ENGINE_VERSION,
        policy_digest: policy.digest(),
        verdict,
        detected: det,
        filename,
        extension,
        claimed_mime: claimed.mime.clone(),
        sha256: sha,
        bytes,
        complete,
        decision: decision.as_str(),
        transformations,
        output: out_meta,
        non_guarantees: ng,
        processing_ms: ms,
    });
    Outcome { report, decision, bytes_read, output }
}

fn error_outcome(policy: &Policy, claimed: &Claimed, start: Instant, sha: String, bytes: u64, why: &str,
                 complete: bool) -> Outcome {
    let mut ctx = Ctx::new(policy.limits.max_processing_ms, None);
    ctx.start = start;
    ctx.fail("engine", "ENGINE_INTERNAL_ERROR", why.to_string());
    finish(ctx, policy, claimed, None, sha, bytes, bytes, Decision::Error, complete, None)
}
