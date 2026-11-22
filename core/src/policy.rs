//! Policy parsing (spec/policy.schema.json). Unknown fields are an error; missing fields take
//! the strict defaults. The effective (defaults-applied) policy is canonicalized and hashed for
//! `policyDigest`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub allow: Vec<String>,
    #[serde(default = "d_reject", rename = "typeMismatch")]
    pub type_mismatch: String,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub images: Images,
    #[serde(default)]
    pub pdf: Pdf,
    #[serde(default = "d_reject", rename = "unknownOrUnsupported")]
    pub unknown_or_unsupported: String,
    #[serde(default)]
    pub scanners: Vec<Scanner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Limits {
    #[serde(default = "d_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "d_max_pixels")]
    pub max_image_pixels: u64,
    #[serde(default = "d_max_dim")]
    pub max_image_dimension: u64,
    #[serde(default = "d_max_pages")]
    pub max_pdf_pages: u64,
    #[serde(default = "d_max_objects")]
    pub max_pdf_objects: u64,
    #[serde(default = "d_max_decompressed")]
    pub max_decompressed_bytes: u64,
    #[serde(default = "d_max_ms")]
    pub max_processing_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_bytes: d_max_bytes(),
            max_image_pixels: d_max_pixels(),
            max_image_dimension: d_max_dim(),
            max_pdf_pages: d_max_pages(),
            max_pdf_objects: d_max_objects(),
            max_decompressed_bytes: d_max_decompressed(),
            max_processing_ms: d_max_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Images {
    #[serde(default = "d_mode")]
    pub mode: String,
    #[serde(default = "d_remove")]
    pub metadata: String,
    #[serde(default = "d_same")]
    pub output_format: String,
    /// Apply EXIF orientation to the pixels before metadata is removed (spec 0.1.2).
    #[serde(default = "d_true")]
    pub apply_orientation: bool,
}

impl Default for Images {
    fn default() -> Self {
        Images { mode: d_mode(), metadata: d_remove(), output_format: d_same(), apply_orientation: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Pdf {
    #[serde(default = "d_reject")]
    pub active_content: String,
    #[serde(default = "d_reject")]
    pub embedded_files: String,
    #[serde(default = "d_reject")]
    pub encrypted: String,
    #[serde(default = "d_warn")]
    pub external_links: String,
    #[serde(default = "d_warn")]
    pub hidden_content: String,
    #[serde(default = "d_reject")]
    pub malformed: String,
}

impl Default for Pdf {
    fn default() -> Self {
        Pdf {
            active_content: d_reject(),
            embedded_files: d_reject(),
            encrypted: d_reject(),
            external_links: d_warn(),
            hidden_content: d_warn(),
            malformed: d_reject(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Scanner {
    pub id: String,
    #[serde(default = "d_reject")]
    pub on_error: String,
}

fn d_reject() -> String { "reject".into() }
fn d_warn() -> String { "warn".into() }
fn d_remove() -> String { "remove".into() }
fn d_mode() -> String { "decode-reencode".into() }
fn d_same() -> String { "same".into() }
fn d_true() -> bool { true }
fn d_max_bytes() -> u64 { 10_485_760 }
fn d_max_pixels() -> u64 { 40_000_000 }
fn d_max_dim() -> u64 { 12_000 }
fn d_max_pages() -> u64 { 100 }
fn d_max_objects() -> u64 { 100_000 }
fn d_max_decompressed() -> u64 { 104_857_600 }
fn d_max_ms() -> u64 { 5_000 }

const ALLOWED_TYPES: &[&str] = &["image/jpeg", "image/png", "image/webp", "application/pdf"];

fn one_of(field: &str, v: &str, opts: &[&str]) -> Result<(), String> {
    if opts.contains(&v) { Ok(()) } else { Err(format!("policy: {field} must be one of {opts:?}, got {v:?}")) }
}

impl Policy {
    /// Parse and validate. This mirrors policy.schema.json; anything it can't validate is an error.
    pub fn from_json(s: &str) -> Result<Policy, String> {
        let p: Policy = serde_json::from_str(s).map_err(|e| format!("policy: {e}"))?;
        p.validate()?;
        Ok(p)
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != "0.1" {
            return Err(format!("policy: unsupported version {:?}", self.version));
        }
        if let Some(n) = &self.name {
            if n.chars().count() > 100 { return Err("policy: name longer than 100".into()); }
        }
        if self.allow.is_empty() { return Err("policy: allow must not be empty".into()); }
        for (i, a) in self.allow.iter().enumerate() {
            one_of("allow[]", a, ALLOWED_TYPES)?;
            if self.allow[..i].contains(a) { return Err("policy: allow items must be unique".into()); }
        }
        one_of("typeMismatch", &self.type_mismatch, &["reject", "warn"])?;
        let l = &self.limits;
        for (k, v) in [("maxBytes", l.max_bytes), ("maxImagePixels", l.max_image_pixels),
                       ("maxImageDimension", l.max_image_dimension), ("maxPdfPages", l.max_pdf_pages),
                       ("maxPdfObjects", l.max_pdf_objects), ("maxDecompressedBytes", l.max_decompressed_bytes),
                       ("maxProcessingMs", l.max_processing_ms)] {
            if v < 1 { return Err(format!("policy: limits.{k} must be >= 1")); }
        }
        one_of("images.mode", &self.images.mode, &["inspect", "decode-reencode"])?;
        one_of("images.metadata", &self.images.metadata, &["remove", "reject", "keep"])?;
        one_of("images.outputFormat", &self.images.output_format, &["same", "png", "webp", "jpeg"])?;
        if self.images.metadata == "keep" && self.images.mode != "inspect" {
            return Err("policy: images.metadata=keep is only valid with mode=inspect".into());
        }
        one_of("pdf.activeContent", &self.pdf.active_content, &["reject"])?;
        one_of("pdf.embeddedFiles", &self.pdf.embedded_files, &["reject"])?;
        one_of("pdf.encrypted", &self.pdf.encrypted, &["reject"])?;
        one_of("pdf.externalLinks", &self.pdf.external_links, &["reject", "warn", "allow"])?;
        one_of("pdf.hiddenContent", &self.pdf.hidden_content, &["off", "warn", "reject"])?;
        one_of("pdf.malformed", &self.pdf.malformed, &["reject"])?;
        one_of("unknownOrUnsupported", &self.unknown_or_unsupported, &["reject"])?;
        for s in &self.scanners { one_of("scanners[].onError", &s.on_error, &["reject", "warn"])?; }
        Ok(())
    }

    /// sha256 of the canonical JSON of the effective policy: defaults applied, keys sorted,
    /// no insignificant whitespace. (serde_json's default Map is a BTreeMap, so keys are sorted.)
    pub fn digest(&self) -> String {
        let v = serde_json::to_value(self).expect("policy serializes");
        let canon = serde_json::to_string(&v).expect("value serializes");
        hex(&Sha256::digest(canon.as_bytes()))
    }
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}
