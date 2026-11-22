//! Content-based type detection, polyglot screening and claimed-type mismatch checks.

use crate::policy::Policy;
use crate::report::Ctx;
use crate::Claimed;

pub struct Detection {
    pub mime: Option<&'static str>,
    pub how: &'static str,
    /// Set when the bytes are plausibly valid as a second format.
    pub polyglot: Option<String>,
}

const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
/// PDF readers accept a `%PDF-` header anywhere in the first 1024 bytes.
const PDF_HEADER_WINDOW: usize = 1024;

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() { return None; }
    h.windows(n.len()).position(|w| w == n)
}

pub fn detect(d: &[u8]) -> Detection {
    let head = &d[..d.len().min(PDF_HEADER_WINDOW)];
    let pdf_at = find(head, b"%PDF-");
    let image = if d.starts_with(PNG_SIG) { Some("image/png") }
        else if d.starts_with(&[0xFF, 0xD8, 0xFF]) { Some("image/jpeg") }
        else if d.len() >= 12 && &d[0..4] == b"RIFF" && &d[8..12] == b"WEBP" { Some("image/webp") }
        else if d.starts_with(b"GIF87a") || d.starts_with(b"GIF89a") { Some("image/gif") }
        else { None };
    if let Some(m) = image {
        let polyglot = pdf_at.map(|o| format!("{m} signature at offset 0 and a %PDF- header at offset {o} \
                                               (within the {PDF_HEADER_WINDOW}-byte window PDF readers accept)"));
        return Detection { mime: Some(m), how: "magic bytes", polyglot };
    }
    match pdf_at {
        Some(0) => Detection { mime: Some("application/pdf"), how: "%PDF- header at offset 0", polyglot: None },
        Some(o) => Detection {
            mime: Some("application/pdf"),
            how: "%PDF- header (not at offset 0)",
            polyglot: Some(format!("{o} bytes of unidentified data before the %PDF- header")),
        },
        None => Detection { mime: None, how: "", polyglot: None },
    }
}

pub fn split_name(f: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(f) = f else { return (None, None) };
    let base = f.rsplit(['/', '\\']).next().unwrap_or(f);
    let ext = base.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).filter(|e| !e.is_empty());
    (Some(f.to_string()), ext)
}

fn ext_mime(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "jpg" | "jpeg" | "jpe" | "jfif" => "image/jpeg",
        "png" => "image/png",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "gif" => "image/gif",
        _ => return None,
    })
}

fn norm_mime(m: &str) -> String {
    let m = m.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match m.as_str() {
        "image/jpg" | "image/pjpeg" => "image/jpeg".into(),
        "application/x-pdf" => "application/pdf".into(),
        _ => m,
    }
}

pub fn mismatch(ctx: &mut Ctx, policy: &Policy, claimed: &Claimed, detected: &'static str) {
    let warn_only = policy.type_mismatch == "warn";
    let (_, ext) = split_name(claimed.filename.as_deref());
    let mut ran = false;
    let mut problems: Vec<(&'static str, String)> = vec![];
    if let Some(e) = &ext {
        ran = true;
        if ext_mime(e) != Some(detected) {
            problems.push(("TYPE_MISMATCH_EXTENSION", format!("extension .{e} vs detected {detected}")));
        }
    }
    if let Some(m) = &claimed.mime {
        ran = true;
        let n = norm_mime(m);
        if n != detected {
            problems.push(("TYPE_MISMATCH_CLAIMED_MIME", format!("claimed {n} vs detected {detected}")));
        }
    }
    if !ran {
        ctx.skip("type.mismatch", "no filename extension or claimed MIME supplied");
        return;
    }
    if problems.is_empty() {
        ctx.pass("type.mismatch");
        return;
    }
    for (code, d) in problems {
        if warn_only { ctx.warn("type.mismatch", code, d) } else { ctx.fail("type.mismatch", code, d) }
    }
}
