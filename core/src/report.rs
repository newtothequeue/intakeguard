//! Check bookkeeping and report serialization (spec/verdict.schema.json).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use serde_json::{json, Value};

/// Reason-code registry, read from spec/reasons.yaml at compile time so the engine can never
/// disagree with the spec about a code's existence or severity.
static REASONS_YAML: &str = include_str!("../../spec/reasons.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity { Reject, Warn, Error }

pub fn registry() -> &'static HashMap<String, (Severity, String)> {
    static REG: OnceLock<HashMap<String, (Severity, String)>> = OnceLock::new();
    REG.get_or_init(|| {
        let mut m = HashMap::new();
        let mut id: Option<String> = None;
        let mut sev: Option<Severity> = None;
        for line in REASONS_YAML.lines() {
            let t = line.trim();
            if let Some(v) = t.strip_prefix("- id:") {
                id = Some(v.trim().to_string());
                sev = None;
            } else if let Some(v) = t.strip_prefix("severity:") {
                let v = v.split('#').next().unwrap_or("").trim();
                sev = Some(match v {
                    "reject" => Severity::Reject,
                    "warn" => Severity::Warn,
                    "error" => Severity::Error,
                    other => panic!("reasons.yaml: unknown severity {other}"),
                });
            } else if let Some(v) = t.strip_prefix("message:") {
                if let (Some(i), Some(s)) = (id.take(), sev.take()) {
                    m.insert(i, (s, v.trim().trim_matches('"').to_string()));
                }
            }
        }
        m
    })
}

fn severity(code: &str) -> Severity {
    match registry().get(code) {
        Some((s, _)) => *s,
        // An unregistered code is an engine bug. Fail closed.
        None => Severity::Error,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status { Passed, Failed, Skipped }

#[derive(Debug, Clone)]
pub struct Check {
    pub id: &'static str,
    pub status: Status,
    pub reason_code: Option<&'static str>,
    pub detail: Option<String>,
}

/// Why processing stopped early. Parsers return this; the engine maps it to a check result.
#[derive(Debug, Clone)]
pub enum Abort {
    Time,
    Cancelled,
    Truncated(String),
    Malformed(String),
    Unsupported(String),
    Decompressed(String),
    Objects(String),
}

/// What the policy decided before any transformation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision { Accept, Transform, Reject, Error }

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Accept => "accept",
            Decision::Transform => "transform",
            Decision::Reject => "reject",
            Decision::Error => "error",
        }
    }
}

pub struct Ctx<'a> {
    pub checks: Vec<Check>,
    pub codes: Vec<&'static str>,
    pub warnings: Vec<String>,
    pub rejected: bool,
    pub errored: bool,
    pub start: Instant,
    pub max_ms: u64,
    pub cancel: Option<&'a AtomicBool>,
    ticks: u32,
}

impl<'a> Ctx<'a> {
    pub fn new(max_ms: u64, cancel: Option<&'a AtomicBool>) -> Self {
        Ctx { checks: vec![], codes: vec![], warnings: vec![], rejected: false, errored: false,
              start: Instant::now(), max_ms, cancel, ticks: 0 }
    }

    fn add_code(&mut self, code: &'static str) {
        if !self.codes.contains(&code) { self.codes.push(code); }
    }

    pub fn pass(&mut self, id: &'static str) {
        self.checks.push(Check { id, status: Status::Passed, reason_code: None, detail: None });
    }

    pub fn pass_detail(&mut self, id: &'static str, detail: impl Into<String>) {
        self.checks.push(Check { id, status: Status::Passed, reason_code: None, detail: Some(clip(detail.into())) });
    }

    pub fn skip(&mut self, id: &'static str, detail: impl Into<String>) {
        if self.checks.iter().any(|c| c.id == id) { return; }
        self.checks.push(Check { id, status: Status::Skipped, reason_code: None, detail: Some(clip(detail.into())) });
    }

    /// A finding whose effect follows the registry severity (reject / error).
    pub fn fail(&mut self, id: &'static str, code: &'static str, detail: impl Into<String>) {
        match severity(code) {
            Severity::Reject => self.rejected = true,
            Severity::Error => self.errored = true,
            Severity::Warn => {}
        }
        self.add_code(code);
        self.checks.push(Check { id, status: Status::Failed, reason_code: Some(code), detail: Some(clip(detail.into())) });
    }

    /// A finding reported as a warning: the check passes (the policy permits it), the code is listed.
    pub fn warn(&mut self, id: &'static str, code: &'static str, detail: impl Into<String>) {
        let d = clip(detail.into());
        self.add_code(code);
        let msg = registry().get(code).map(|(_, m)| m.clone()).unwrap_or_default();
        self.warnings.push(format!("{code}: {msg}"));
        self.checks.push(Check { id, status: Status::Passed, reason_code: Some(code), detail: Some(d) });
    }

    /// A finding that is not fatal in itself but that the policy handles by transforming
    /// (e.g. image metadata under metadata=remove). Recorded as a failed check plus a warning.
    pub fn fail_downgraded(&mut self, id: &'static str, code: &'static str, detail: impl Into<String>) {
        let d = clip(detail.into());
        self.add_code(code);
        let msg = registry().get(code).map(|(_, m)| m.clone()).unwrap_or_default();
        self.warnings.push(format!("{code}: {msg}"));
        self.checks.push(Check { id, status: Status::Failed, reason_code: Some(code), detail: Some(d) });
    }

    pub fn elapsed_ms(&self) -> f64 { self.start.elapsed().as_secs_f64() * 1000.0 }

    /// Called from every loop that walks untrusted data. Cheap: the clock is read every 64 calls.
    #[inline]
    pub fn tick(&mut self) -> Result<(), Abort> {
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks & 63 != 0 { return Ok(()); }
        self.check_now()
    }

    pub fn check_now(&self) -> Result<(), Abort> {
        if let Some(c) = self.cancel {
            if c.load(Ordering::Relaxed) { return Err(Abort::Cancelled); }
        }
        if self.start.elapsed().as_millis() as u64 > self.max_ms { return Err(Abort::Time); }
        Ok(())
    }
}

fn clip(mut s: String) -> String {
    if s.chars().count() > 500 {
        s = s.chars().take(497).collect::<String>() + "...";
    }
    s
}

pub struct ReportInput<'a> {
    pub engine_version: &'a str,
    pub policy_digest: String,
    pub verdict: &'static str,
    pub detected: Option<(&'static str, &'static str)>,
    pub filename: Option<String>,
    pub extension: Option<String>,
    pub claimed_mime: Option<String>,
    pub sha256: String,
    pub bytes: u64,
    pub complete: bool,
    pub decision: &'static str,
    pub transformations: Vec<(&'static str, Option<String>)>,
    /// (sha256, bytes, mime, handle)
    pub output: Option<(String, u64, &'static str, String)>,
    pub non_guarantees: Vec<&'static str>,
    pub processing_ms: f64,
}

pub fn render(ctx: &Ctx, r: ReportInput) -> Value {
    let checks: Vec<Value> = ctx.checks.iter().map(|c| {
        let mut o = serde_json::Map::new();
        o.insert("id".into(), json!(c.id));
        o.insert("status".into(), json!(match c.status {
            Status::Passed => "passed", Status::Failed => "failed", Status::Skipped => "skipped" }));
        if let Some(rc) = c.reason_code { o.insert("reasonCode".into(), json!(rc)); }
        if let Some(d) = &c.detail { o.insert("detail".into(), json!(d)); }
        Value::Object(o)
    }).collect();
    json!({
        "reportVersion": "0.2",
        "policyDecision": r.decision,
        "engineVersion": r.engine_version,
        "policyVersion": "0.1",
        "policyDigest": r.policy_digest,
        "verdict": r.verdict,
        "detectedType": r.detected.map(|(m, c)| json!({"mime": m, "confidence": c})),
        "claimed": {"filename": r.filename, "extension": r.extension, "mime": r.claimed_mime},
        "reasonCodes": ctx.codes,
        "checks": checks,
        "transformations": r.transformations.iter().map(|(id, d)| match d {
            Some(d) => json!({"id": id, "detail": clip(d.clone())}),
            None => json!({"id": id}),
        }).collect::<Vec<_>>(),
        "original": {"sha256": r.sha256, "bytes": r.bytes, "complete": r.complete, "quarantineHandle": null},
        "output": r.output.as_ref().map(|(sha, n, m, h)| json!({"sha256": sha, "bytes": n, "mime": m, "handle": h})),
        "warnings": ctx.warnings,
        "nonGuarantees": r.non_guarantees,
        "timing": {"processingMs": r.processing_ms},
    })
}
