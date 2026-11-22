//! PDF inspection: strict xref-chain structure validation over every revision, object streams,
//! bounded stream decoding, active-content / embedded-file / link / hidden-text scans, page count.
//! v0.1 never modifies a PDF.

mod content;
mod filters;
mod syntax;

use std::collections::{HashMap, HashSet};

use filters::{Budget, Want};
use syntax::{Lexer, Obj, StreamLen};

use crate::policy::Policy;
use crate::report::{Abort, Ctx};

/// Names whose hex-escaped spelling is reported as PDF_OBFUSCATED_NAME.
const SENSITIVE: &[&[u8]] = &[b"JavaScript", b"JS", b"OpenAction", b"AA", b"Launch", b"SubmitForm",
                              b"ImportData", b"RichMedia", b"XFA", b"EmbeddedFile", b"EmbeddedFiles",
                              b"FileAttachment", b"URI", b"GoToR", b"Encrypt", b"Next", b"S", b"A"];
const EMBEDDED: &[&[u8]] = &[b"EmbeddedFile", b"EmbeddedFiles", b"FileAttachment"];
/// Spec 0.1.1 inert action allowlist (format-guarantees.md#pdf). Inert only if there is also no /JS key.
const INERT: &[&[u8]] = &[b"GoTo", b"Named", b"Thread", b"Hide", b"SetOCGState", b"Trans", b"ResetForm"];
/// Inert, but reported as PDF_EXTERNAL_LINK.
const EXTERNAL: &[&[u8]] = &[b"URI", b"GoToR"];
/// Action types flagged wherever a dict carries them as /S, even if no trigger reaches it
/// (defense in depth; these are never the /S of a non-action dictionary).
const ACTIVE_TYPES: &[&[u8]] = &[b"JavaScript", b"Launch", b"SubmitForm", b"ImportData", b"RichMediaExecute",
                                 b"Rendition", b"Movie", b"Sound", b"GoTo3DView", b"GoToE"];
const MAX_ACTION_CHAIN: usize = 1000;
const MAX_XREF_SECTIONS: usize = 1024;

#[derive(Clone, Copy, Debug)]
enum Entry { InUse { off: usize, gen: u16 }, Compressed { stm: u32, idx: u32 } }

struct Section { trailer: Obj, entries: Vec<(u32, Entry)>, end: usize }

struct Parsed {
    num: u32,
    obj: Obj,
    data: Option<(usize, usize)>,
    /// Location for findings, e.g. "object 6" or "object 6 (in ObjStm 7)".
    loc: String,
}

pub fn inspect(ctx: &mut Ctx, policy: &Policy, d: &[u8]) -> bool {
    const LATER: &[&str] = &["pdf.objects", "pdf.encryption", "limit.decompressed", "pdf.active-content",
                             "pdf.obfuscated-names", "pdf.embedded-files", "pdf.external-links",
                             "pdf.hidden-content", "pdf.pages", "pdf.trailing-data"];
    let skip_all = |ctx: &mut Ctx, why: &str| for id in LATER { ctx.skip(id, why.to_string()); };
    let mut budget = Budget { used: 0, max: policy.limits.max_decompressed_bytes };

    // ---- structure (every revision)
    let mut doc = match structure(ctx, policy, d, &mut budget) {
        Ok(doc) => doc,
        Err(a) => {
            crate::apply_abort(ctx, "pdf.structure", a);
            if !ctx.checks.iter().any(|c| c.id == "pdf.structure") { ctx.skip("pdf.structure", "aborted by a limit"); }
            skip_all(ctx, "short-circuited after rejection");
            return false;
        }
    };
    ctx.pass_detail("pdf.structure", format!("{} revision(s), {} objects", doc.sections.len(), doc.latest.len()));
    ctx.pass_detail("pdf.objects", format!("{} objects; maxPdfObjects={}", doc.latest.len(), policy.limits.max_pdf_objects));

    // ---- trailing data (raw bytes after the final %%EOF)
    let trailing = doc.trailing;

    // ---- encryption: any trailer in any revision
    if let Some(i) = doc.sections.iter().position(|s| s.trailer.get(b"Encrypt").is_some()) {
        ctx.fail("pdf.encryption", "PDF_ENCRYPTED", format!("/Encrypt in trailer of revision {}", doc.sections.len() - i));
        skip_all(ctx, "content is encrypted and cannot be inspected");
        return true;
    }
    ctx.pass("pdf.encryption");

    // ---- object streams, scans, stream decoding
    if let Err(a) = scan(ctx, &mut doc, d, &mut budget) {
        crate::apply_abort(ctx, "pdf.structure", a);
        skip_all(ctx, "short-circuited after rejection");
        return false;
    }
    ctx.pass_detail("limit.decompressed", format!("{} decoded bytes; maxDecompressedBytes={}", budget.used, budget.max));

    let f = &doc.findings;
    if f.active.is_empty() { ctx.pass("pdf.active-content"); }
    else { ctx.fail("pdf.active-content", "PDF_ACTIVE_CONTENT", f.active.join("; ")); }
    if f.obfuscated.is_empty() { ctx.pass("pdf.obfuscated-names"); }
    else { ctx.fail("pdf.obfuscated-names", "PDF_OBFUSCATED_NAME", f.obfuscated.join("; ")); }
    if f.embedded.is_empty() { ctx.pass("pdf.embedded-files"); }
    else { ctx.fail("pdf.embedded-files", "PDF_EMBEDDED_FILE", f.embedded.join("; ")); }
    if f.external.is_empty() { ctx.pass("pdf.external-links"); }
    else {
        let det = f.external.join("; ");
        match policy.pdf.external_links.as_str() {
            "reject" => ctx.fail("pdf.external-links", "PDF_EXTERNAL_LINK", det),
            "allow" => ctx.pass_detail("pdf.external-links", format!("allowed by policy: {det}")),
            _ => ctx.warn("pdf.external-links", "PDF_EXTERNAL_LINK", det),
        }
    }
    match policy.pdf.hidden_content.as_str() {
        "off" => ctx.skip("pdf.hidden-content", "disabled by policy"),
        mode => {
            if !f.hidden.is_empty() {
                let det = format!("heuristic: {}", f.hidden.join("; "));
                if mode == "reject" { ctx.fail("pdf.hidden-content", "PDF_HIDDEN_CONTENT_SUSPECTED", det) }
                else { ctx.warn("pdf.hidden-content", "PDF_HIDDEN_CONTENT_SUSPECTED", det) }
            } else {
                ctx.pass("pdf.hidden-content");
            }
        }
    }

    // ---- page count (latest revision's page tree)
    match pages(ctx, &doc, policy.limits.max_pdf_pages) {
        Ok(n) if n > policy.limits.max_pdf_pages =>
            ctx.fail("pdf.pages", "LIMIT_PDF_PAGES_EXCEEDED", format!("more than {} pages (counted {n}+)", policy.limits.max_pdf_pages)),
        Ok(n) => ctx.pass_detail("pdf.pages", format!("{n} page(s)")),
        Err(a) => crate::apply_abort(ctx, "pdf.pages", a),
    }

    if trailing > 0 {
        ctx.warn("pdf.trailing-data", "PDF_TRAILING_DATA", format!("{trailing} non-whitespace bytes after the final %%EOF"));
    } else {
        ctx.pass("pdf.trailing-data");
    }
    true
}

#[derive(Default)]
struct Findings {
    active: Vec<String>,
    embedded: Vec<String>,
    external: Vec<String>,
    obfuscated: Vec<String>,
    hidden: Vec<String>,
}

struct Doc {
    sections: Vec<Section>,
    objs: Vec<Parsed>,
    /// latest revision: object number -> index into objs (filled for compressed objects by scan()).
    latest: HashMap<u32, usize>,
    compressed: HashMap<u32, (u32, u32)>,
    trailing: usize,
    findings: Findings,
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if h.len() < n.len() { return None; }
    h.windows(n.len()).position(|w| w == n)
}

fn rfind(h: &[u8], n: &[u8]) -> Option<usize> {
    if h.len() < n.len() { return None; }
    (0..=h.len() - n.len()).rev().find(|&i| &h[i..i + n.len()] == n)
}

fn structure(ctx: &mut Ctx, policy: &Policy, d: &[u8], budget: &mut Budget) -> Result<Doc, Abort> {
    let eof = rfind(d, b"%%EOF").ok_or_else(|| Abort::Truncated("no %%EOF marker".into()))?;
    let after = &d[eof + 5..];
    let trailing = after.iter().filter(|b| !syntax::is_ws(**b)).count();
    // Trailing text is only a warning, but bytes that look like object/xref sections after the final
    // %%EOF are a damaged revision: a reader that reconstructs the xref may load them.
    for kw in [&b"endobj"[..], b"endstream", b"startxref", b"trailer"] {
        if find(after, kw).is_some() {
            return Err(Abort::Malformed(format!(
                "data after the final %%EOF contains '{}' (damaged or unreferenced revision)", String::from_utf8_lossy(kw))));
        }
    }
    let sx = rfind(&d[..eof], b"startxref").ok_or_else(|| Abort::Malformed("no startxref before %%EOF".into()))?;
    let mut lx = Lexer::new(d, sx + 9);
    let start = lx.uint().ok_or_else(|| Abort::Malformed("startxref has no offset".into()))? as usize;

    let max_objects = policy.limits.max_pdf_objects;
    let mut sections = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = vec![start];
    let mut total_entries: u64 = 0;
    let mut xref_spans: Vec<(usize, usize)> = Vec::new();
    while let Some(at) = queue.pop() {
        ctx.tick()?;
        if !seen.insert(at) { return Err(Abort::Malformed(format!("xref /Prev loop at offset {at}"))); }
        if sections.len() >= MAX_XREF_SECTIONS { return Err(Abort::Unsupported("too many xref sections".into())); }
        if at >= d.len() { return Err(Abort::Malformed(format!("xref offset {at} is past end of file"))); }
        let sec = if Lexer::new(d, at).peek_word() == b"xref" {
            xref_table(ctx, d, at, &mut total_entries, max_objects)?
        } else {
            xref_stream(ctx, d, at, budget, &mut total_entries, max_objects)?
        };
        xref_spans.push((at, sec.end));
        // Within one revision a hybrid /XRefStm is processed before /Prev.
        if let Some(p) = sec.trailer.get(b"Prev").and_then(Obj::int) {
            if p < 0 { return Err(Abort::Malformed("negative /Prev".into())); }
            queue.push(p as usize);
        }
        if let Some(p) = sec.trailer.get(b"XRefStm").and_then(Obj::int) {
            if p < 0 { return Err(Abort::Malformed("negative /XRefStm".into())); }
            queue.push(p as usize);
        }
        sections.push(sec);
    }

    // Latest-wins merge (sections are newest first).
    let mut merged: HashMap<u32, Entry> = HashMap::new();
    for s in &sections {
        for (n, e) in &s.entries { merged.entry(*n).or_insert(*e); }
    }
    if merged.len() as u64 > max_objects {
        return Err(Abort::Objects(format!("{} objects; maxPdfObjects={max_objects}", merged.len())));
    }

    // Parse every in-use object of every revision (dedup by offset).
    let mut objs: Vec<Parsed> = Vec::new();
    let mut by_off: HashMap<usize, usize> = HashMap::new();
    let mut pending_len: Vec<(usize, usize, u32, usize)> = Vec::new(); // (obj idx, data start, length obj num, obj offset)
    // Byte ranges accounted for by the xref chain (objects, xref sections, trailers).
    let mut spans: Vec<(usize, usize)> = xref_spans;
    for s in &sections {
        for (n, e) in &s.entries {
            ctx.tick()?;
            match *e {
                Entry::InUse { off, gen } => {
                    if by_off.contains_key(&off) { continue; }
                    if off >= d.len() { return Err(Abort::Malformed(format!("object {n} offset {off} past end of file"))); }
                    let ind = syntax::indirect(d, off)?;
                    if ind.num != *n || ind.gen != gen {
                        return Err(Abort::Malformed(format!("xref says object {n} {gen} at {off}, found {} {}", ind.num, ind.gen)));
                    }
                    let idx = objs.len();
                    let mut data = None;
                    match ind.stream {
                        Some((s0, StreamLen::Direct(len))) => {
                            let (a, b, e) = syntax::finish_stream_end(d, s0, len, *n)?;
                            data = Some((a, b));
                            spans.push((off, e));
                        }
                        Some((s0, StreamLen::Ref(r))) => pending_len.push((idx, s0, r, off)),
                        None => spans.push((off, ind.end)),
                    }
                    objs.push(Parsed { num: *n, obj: ind.obj, data, loc: format!("object {n}") });
                    by_off.insert(off, idx);
                }
                Entry::Compressed { .. } => {}
            }
        }
    }
    let mut latest: HashMap<u32, usize> = HashMap::new();
    for (n, e) in &merged {
        if let Entry::InUse { off, .. } = e { latest.insert(*n, by_off[off]); }
    }
    // Indirect /Length values.
    for (idx, s0, r, off) in pending_len {
        let len = latest.get(&r).and_then(|&i| objs[i].obj.int())
            .filter(|n| *n >= 0)
            .ok_or_else(|| Abort::Malformed(format!("stream {} has an unresolvable /Length {r} 0 R", objs[idx].num)))?;
        let (a, b, e) = syntax::finish_stream_end(d, s0, len as usize, objs[idx].num)?;
        objs[idx].data = Some((a, b));
        spans.push((off, e));
    }
    // Strict rule: every object in the file must be reachable through the xref chain. An
    // unreferenced object (e.g. a revision whose xref/trailer is damaged or missing) is something
    // a lenient, xref-reconstructing reader may still load, so parsers would disagree.
    spans.sort_unstable();
    for h in syntax::obj_headers(d) {
        ctx.tick()?;
        let i = spans.partition_point(|s| s.0 <= h);
        let covered = i > 0 && h < spans[i - 1].1;
        if !covered {
            return Err(Abort::Malformed(format!("object header at byte {h} is not referenced by any xref section")));
        }
    }
    // Compressed entries must point at an object stream.
    let mut latest_compressed = HashMap::new();
    for (n, e) in &merged {
        if let Entry::Compressed { stm, idx } = e {
            let ok = latest.get(stm).map(|&i| objs[i].data.is_some()
                && objs[i].obj.get(b"Type").and_then(Obj::name) == Some(b"ObjStm")).unwrap_or(false);
            if !ok { return Err(Abort::Malformed(format!("object {n} is in {stm}, which is not an object stream"))); }
            latest_compressed.insert(*n, (*stm, *idx));
        }
    }
    Ok(Doc { sections, objs, latest, compressed: latest_compressed, trailing, findings: Findings::default() })
}

fn xref_table(ctx: &mut Ctx, d: &[u8], at: usize, total: &mut u64, max: u64) -> Result<Section, Abort> {
    let mut lx = Lexer::new(d, at);
    lx.expect(b"xref")?;
    let mut entries = Vec::new();
    loop {
        ctx.tick()?;
        if lx.peek_word() == b"trailer" { lx.word(); break; }
        let first = lx.uint().ok_or_else(|| trunc_or_mal(&lx, "bad xref subsection header"))?;
        let count = lx.uint().ok_or_else(|| trunc_or_mal(&lx, "bad xref subsection count"))?;
        *total += count;
        if *total > max.saturating_mul(4).max(4096) {
            return Err(Abort::Objects(format!("xref lists {total}+ entries; maxPdfObjects={max}")));
        }
        for i in 0..count {
            ctx.tick()?;
            let off = lx.uint().ok_or_else(|| trunc_or_mal(&lx, "bad xref entry offset"))?;
            let gen = lx.uint().ok_or_else(|| trunc_or_mal(&lx, "bad xref entry generation"))?;
            let kind = lx.word();
            let num = first + i;
            // Spec 0.1.1 tolerance (Pillow): the free-list head, object 0, may carry generation 65536.
            let pillow_head = num == 0 && gen == 65536 && kind == b"f";
            if num > u32::MAX as u64 || (gen > 65535 && !pillow_head) {
                return Err(Abort::Malformed(format!("xref entry {num} has generation {gen} (max 65535)")));
            }
            match kind {
                b"n" if num != 0 => entries.push((num as u32, Entry::InUse { off: off as usize, gen: gen as u16 })),
                b"n" | b"f" => {}
                _ => return Err(trunc_or_mal(&lx, "xref entry type is not n/f")),
            }
        }
    }
    let trailer = lx.object(0)?;
    if trailer.dict().is_none() { return Err(Abort::Malformed("trailer is not a dictionary".into())); }
    Ok(Section { trailer, entries, end: lx.p })
}

fn trunc_or_mal(lx: &Lexer, m: &str) -> Abort {
    if lx.p >= lx.d.len() { Abort::Truncated(m.into()) } else { Abort::Malformed(format!("{m} at byte {}", lx.p)) }
}

fn xref_stream(ctx: &mut Ctx, d: &[u8], at: usize, budget: &mut Budget, total: &mut u64, max: u64) -> Result<Section, Abort> {
    let ind = syntax::indirect(d, at)?;
    if ind.obj.get(b"Type").and_then(Obj::name) != Some(b"XRef") {
        return Err(Abort::Malformed(format!("startxref/Prev offset {at} is neither 'xref' nor an XRef stream")));
    }
    let (s0, len) = match ind.stream {
        Some((s0, StreamLen::Direct(l))) => (s0, l),
        Some((_, StreamLen::Ref(_))) => return Err(Abort::Unsupported("XRef stream with indirect /Length".into())),
        None => return Err(Abort::Malformed("XRef object is not a stream".into())),
    };
    let (a, b, xend) = syntax::finish_stream_end(d, s0, len, ind.num)?;
    let raw = match filters::decode_stream(ctx, &ind.obj, &d[a..b], budget, Want::All)? {
        (Some(v), _) => v,
        (None, f) => return Err(Abort::Unsupported(format!("XRef stream filter {}", f.unwrap_or_default()))),
    };
    let w: Vec<usize> = match ind.obj.get(b"W") {
        Some(Obj::Array(a)) if a.len() == 3 => a.iter().map(|o| o.int().filter(|v| (0..=8).contains(v)).map(|v| v as usize))
            .collect::<Option<_>>().ok_or_else(|| Abort::Malformed("bad /W".into()))?,
        _ => return Err(Abort::Malformed("XRef stream without a valid /W".into())),
    };
    let size = ind.obj.get(b"Size").and_then(Obj::int).ok_or_else(|| Abort::Malformed("XRef stream without /Size".into()))?;
    let index: Vec<i64> = match ind.obj.get(b"Index") {
        Some(Obj::Array(a)) => a.iter().map(Obj::int).collect::<Option<_>>().ok_or_else(|| Abort::Malformed("bad /Index".into()))?,
        None => vec![0, size],
        _ => return Err(Abort::Malformed("bad /Index".into())),
    };
    if index.len() % 2 != 0 || index.iter().any(|v| *v < 0) { return Err(Abort::Malformed("bad /Index".into())); }
    let row = w[0] + w[1] + w[2];
    if row == 0 { return Err(Abort::Malformed("XRef /W sums to zero".into())); }
    let field = |r: &[u8], o: usize, n: usize| r[o..o + n].iter().fold(0u64, |acc, b| acc << 8 | *b as u64);
    let mut entries = Vec::new();
    let mut p = 0usize;
    for pair in index.chunks(2) {
        let (first, count) = (pair[0] as u64, pair[1] as u64);
        *total += count;
        if *total > max.saturating_mul(4).max(4096) {
            return Err(Abort::Objects(format!("xref lists {total}+ entries; maxPdfObjects={max}")));
        }
        for i in 0..count {
            ctx.tick()?;
            let r = raw.get(p..p + row).ok_or_else(|| Abort::Malformed("XRef stream shorter than /Index declares".into()))?;
            p += row;
            let ty = if w[0] == 0 { 1 } else { field(r, 0, w[0]) };
            let f2 = field(r, w[0], w[1]);
            let f3 = field(r, w[0] + w[1], w[2]);
            let num = first + i;
            if num == 0 || num > u32::MAX as u64 { continue; }
            match ty {
                0 => {}
                1 => entries.push((num as u32, Entry::InUse { off: f2 as usize, gen: f3.min(65535) as u16 })),
                2 => {
                    if f2 > u32::MAX as u64 || f3 > u32::MAX as u64 { return Err(Abort::Malformed("bad compressed xref entry".into())); }
                    entries.push((num as u32, Entry::Compressed { stm: f2 as u32, idx: f3 as u32 }))
                }
                _ => {} // reserved types are treated as null references (§7.5.8.3)
            }
        }
    }
    Ok(Section { trailer: ind.obj, entries, end: xend })
}

/// Decode object streams, walk every object of every revision, decode all other streams.
fn scan(ctx: &mut Ctx, doc: &mut Doc, d: &[u8], budget: &mut Budget) -> Result<(), Abort> {
    // 1. Object streams (every one present in any revision).
    let stm_idx: Vec<usize> = (0..doc.objs.len())
        .filter(|&i| doc.objs[i].data.is_some() && doc.objs[i].obj.get(b"Type").and_then(Obj::name) == Some(b"ObjStm"))
        .collect();
    let mut in_stm: HashMap<(u32, u32), usize> = HashMap::new();
    for i in stm_idx {
        let (a, b) = doc.objs[i].data.unwrap();
        let stm_num = doc.objs[i].num;
        let raw = match filters::decode_stream(ctx, &doc.objs[i].obj, &d[a..b], budget, Want::All)? {
            (Some(v), _) => v,
            (None, f) => return Err(Abort::Unsupported(format!("ObjStm {stm_num} filter {}", f.unwrap_or_default()))),
        };
        let n = doc.objs[i].obj.get(b"N").and_then(Obj::int).filter(|v| *v >= 0)
            .ok_or_else(|| Abort::Malformed(format!("ObjStm {stm_num} without /N")))? as usize;
        let first = doc.objs[i].obj.get(b"First").and_then(Obj::int).filter(|v| *v >= 0)
            .ok_or_else(|| Abort::Malformed(format!("ObjStm {stm_num} without /First")))? as usize;
        if first > raw.len() || n > raw.len() / 2 + 1 { return Err(Abort::Malformed(format!("ObjStm {stm_num} header out of range"))); }
        let mut hl = Lexer::new(&raw[..first], 0);
        let mut heads = Vec::with_capacity(n);
        for _ in 0..n {
            let num = hl.uint().ok_or_else(|| Abort::Malformed(format!("ObjStm {stm_num} header truncated")))?;
            let off = hl.uint().ok_or_else(|| Abort::Malformed(format!("ObjStm {stm_num} header truncated")))?;
            heads.push((num, off as usize));
        }
        for (k, (num, off)) in heads.into_iter().enumerate() {
            ctx.tick()?;
            let mut lx = Lexer::new(&raw, first.checked_add(off).filter(|p| *p <= raw.len())
                .ok_or_else(|| Abort::Malformed(format!("ObjStm {stm_num} offset out of range")))?);
            let obj = lx.object(0)?;
            if num > u32::MAX as u64 { return Err(Abort::Malformed("ObjStm object number out of range".into())); }
            in_stm.insert((stm_num, k as u32), doc.objs.len());
            doc.objs.push(Parsed { num: num as u32, obj, data: None, loc: format!("object {num} (in ObjStm {stm_num})") });
        }
    }
    for (n, (stm, idx)) in doc.compressed.clone() {
        let &i = in_stm.get(&(stm, idx)).ok_or_else(|| Abort::Malformed(format!("object {n} missing from ObjStm {stm}")))?;
        if doc.objs[i].num != n { return Err(Abort::Malformed(format!("ObjStm {stm} index {idx} holds {} not {n}", doc.objs[i].num))); }
        doc.latest.insert(n, i);
    }

    // 2. Walk every object and trailer for security-relevant names; collect content streams.
    let mut content: HashSet<u32> = HashSet::new();
    let mut f = Findings::default();
    let objs = &doc.objs;
    let latest = &doc.latest;
    let get = move |n: u32| latest.get(&n).map(|&i| &objs[i].obj);
    // Objects referenced from any /Annots array are annotations, whether or not they say so.
    let mut annot_refs: HashSet<u32> = HashSet::new();
    for p in &doc.objs { collect_annot_refs(&p.obj, &mut annot_refs, 0); }
    for s in &doc.sections { walk(&s.trailer, "trailer", &mut f, 0, &get, false); }
    for p in &doc.objs {
        ctx.tick()?;
        walk(&p.obj, &p.loc, &mut f, 0, &get, annot_refs.contains(&p.num));
        if p.obj.get(b"Type").and_then(Obj::name) == Some(b"Page") {
            match p.obj.get(b"Contents") {
                Some(Obj::Ref(n, _)) => { content.insert(*n); }
                Some(Obj::Array(a)) => for o in a { if let Obj::Ref(n, _) = o { content.insert(*n); } },
                _ => {}
            }
        }
        if p.data.is_some() && p.obj.get(b"Subtype").and_then(Obj::name) == Some(b"Form") { content.insert(p.num); }
    }

    // 3. Decode every remaining stream: counts toward the budget; content streams are also scanned.
    for p in &doc.objs {
        let Some((a, b)) = p.data else { continue };
        let ty = p.obj.get(b"Type").and_then(Obj::name);
        if ty == Some(b"ObjStm") || ty == Some(b"XRef") { continue; }
        if content.contains(&p.num) {
            // Every decoded byte is scanned (streaming, constant memory): no size cap.
            let mut scan = content::HiddenScan::new();
            let (_, opaque) = filters::decode_stream(ctx, &p.obj, &d[a..b], budget,
                                                     Want::Feed(&mut |c| scan.feed(c)))?;
            // Spec 0.1.4: a content stream this engine can't decode can't be scanned -> fail closed.
            if let Some(fl) = opaque {
                return Err(Abort::Unsupported(format!("{} content stream uses filter /{fl}, which is not decoded", p.loc)));
            }
            for h in scan.finish() { f.hidden.push(format!("{} ({})", h, p.loc)); }
        } else {
            filters::decode_stream(ctx, &p.obj, &d[a..b], budget, Want::Count)?;
        }
    }
    doc.findings = f;
    Ok(())
}

type Get<'a> = dyn Fn(u32) -> Option<&'a Obj> + 'a;

fn deref<'a>(o: &'a Obj, get: &Get<'a>) -> Option<&'a Obj> {
    let mut cur = o;
    for _ in 0..8 {
        match cur { Obj::Ref(n, _) => cur = get(*n)?, _ => return Some(cur) }
    }
    None
}

fn nm(o: Option<&Obj>) -> String {
    o.and_then(Obj::name).map(|n| format!("/{}", String::from_utf8_lossy(n))).unwrap_or_else(|| "no /S".into())
}

/// Walk one object: action triggers, embedded files, obfuscated names, and defense-in-depth action types.
fn collect_annot_refs(o: &Obj, out: &mut HashSet<u32>, depth: usize) {
    if depth > syntax::MAX_DEPTH + 1 { return; }
    match o {
        Obj::Array(a) => for x in a { collect_annot_refs(x, out, depth + 1) },
        Obj::Dict(dd) => for (k, v) in dd {
            if k.val == b"Annots" {
                if let Obj::Array(a) = v { for x in a { if let Obj::Ref(n, _) = x { out.insert(*n); } } }
            }
            collect_annot_refs(v, out, depth + 1);
        },
        _ => {}
    }
}

/// An annotation: /Type /Annot, a /Subtype with a /Rect (annotation dictionaries), or listed in /Annots.
fn is_annotation(o: &Obj) -> bool {
    o.get(b"Type").and_then(Obj::name) == Some(b"Annot") || (o.get(b"Subtype").is_some() && o.get(b"Rect").is_some())
}

/// An outline item: has /Title and a link into the outline tree.
fn is_outline_item(o: &Obj) -> bool {
    o.get(b"Title").is_some() && [&b"Parent"[..], b"Prev", b"Next", b"First"].iter().any(|k| o.get(k).is_some())
}

/// `annot`: the caller knows this dict is an annotation (it is listed in an /Annots array).
fn walk<'a>(o: &'a Obj, loc: &str, f: &mut Findings, depth: usize, get: &Get<'a>, annot: bool) {
    if depth > syntax::MAX_DEPTH + 1 { return; }
    let name = |n: &syntax::Name, f: &mut Findings| {
        let v = n.val.as_slice();
        let s = String::from_utf8_lossy(v);
        if n.escaped && SENSITIVE.contains(&v) { push_once(&mut f.obfuscated, format!("hex-escaped /{s} in {loc}")); }
        if EMBEDDED.contains(&v) { push_once(&mut f.embedded, format!("/{s} in {loc}")); }
    };
    match o {
        Obj::Name(n) => name(n, f),
        Obj::Array(a) => for x in a { walk(x, loc, f, depth + 1, get, false) },
        Obj::Dict(dd) => {
            // /A is an action only on annotations and outline items (spec 0.1.1). Elsewhere, e.g. on
            // a tagged-PDF StructElem, /A holds attributes. Active /S types and /JS keys are still
            // flagged wherever they appear (below).
            let scoped = annot || is_annotation(o) || is_outline_item(o);
            for (k, v) in dd {
                name(k, f);
                if k.val == b"Annots" {
                    if let Obj::Array(a) = v {
                        for x in a { walk(x, loc, f, depth + 1, get, matches!(x, Obj::Dict(_))) }
                        continue;
                    }
                }
                match k.val.as_slice() {
                    b"OpenAction" => match deref(v, get) {
                        // A destination (explicit array, or a named destination) is not an action.
                        Some(Obj::Array(_)) | Some(Obj::Name(_)) | Some(Obj::Str(_)) | Some(Obj::Null) => {}
                        _ => action(v, &format!("/OpenAction in {loc}"), f, get),
                    },
                    b"AA" => match deref(v, get) {
                        Some(Obj::Dict(trig)) => for (t, a) in trig {
                            action(a, &format!("/AA /{} in {loc}", String::from_utf8_lossy(&t.val)), f, get)
                        },
                        _ => push_once(&mut f.active, format!("/AA in {loc} is not a dictionary")),
                    },
                    b"A" if scoped => if let Some(Obj::Dict(_)) = deref(v, get) { action(v, &format!("/A in {loc}"), f, get) },
                    b"JavaScript" => if !empty_tree(v, get) {
                        push_once(&mut f.active, format!("/JavaScript name tree in {loc}"))
                    },
                    b"XFA" => push_once(&mut f.active, format!("/XFA in {loc}")),
                    b"JS" => push_once(&mut f.active, format!("/JS key in {loc}")),
                    b"Subtype" if v.name() == Some(b"RichMedia") => push_once(&mut f.active, format!("/RichMedia annotation in {loc}")),
                    b"S" => if let Some(t) = v.name() {
                        if ACTIVE_TYPES.contains(&t) { push_once(&mut f.active, format!("action /S /{} in {loc}", String::from_utf8_lossy(t))); }
                        if EXTERNAL.contains(&t) { push_once(&mut f.external, format!("/S /{} in {loc}", String::from_utf8_lossy(t))); }
                    },
                    _ => {}
                }
                walk(v, loc, f, depth + 1, get, false);
            }
        }
        _ => {}
    }
}

/// Evaluate an action and its /Next chain (transitively, cycles detected) against the inert allowlist.
fn action<'a>(start: &'a Obj, via: &str, f: &mut Findings, get: &Get<'a>) {
    let mut seen: HashSet<u32> = HashSet::new();
    let mut work: Vec<&'a Obj> = vec![start];
    let mut steps = 0usize;
    while let Some(o) = work.pop() {
        steps += 1;
        if steps > MAX_ACTION_CHAIN {
            push_once(&mut f.active, format!("action chain longer than {MAX_ACTION_CHAIN} via {via}"));
            return;
        }
        let mut cur = o;
        let mut hops = 0;
        let mut cyc = false;
        while let Obj::Ref(n, _) = cur {
            if !seen.insert(*n) { cyc = true; break; }
            hops += 1;
            match get(*n) { Some(x) if hops < 8 => cur = x, _ => { cur = &Obj::Null; break; } }
        }
        if cyc { continue; } // already evaluated
        let Some(_) = cur.dict() else {
            push_once(&mut f.active, format!("action via {via} is not a dictionary"));
            continue;
        };
        let s = cur.get(b"S").and_then(Obj::name);
        let has_js = cur.get(b"JS").is_some();
        let inert = matches!(s, Some(t) if INERT.contains(&t) || EXTERNAL.contains(&t));
        if !inert || has_js {
            let why = if has_js { format!("{} with /JS", nm(cur.get(b"S"))) } else { nm(cur.get(b"S")) };
            push_once(&mut f.active, format!("action {why} via {via}"));
        }
        if let Some(t) = s { if EXTERNAL.contains(&t) { push_once(&mut f.external, format!("/S /{} via {via}", String::from_utf8_lossy(t))); } }
        match cur.get(b"Next") {
            Some(Obj::Array(a)) => work.extend(a.iter().rev()),
            Some(n) => work.push(n),
            None => {}
        }
    }
}

/// True if a name tree has no entries (no /Names pairs and no /Kids).
fn empty_tree<'a>(v: &'a Obj, get: &Get<'a>) -> bool {
    match deref(v, get) {
        Some(t @ Obj::Dict(_)) => {
            let nonempty = |k: &[u8]| matches!(t.get(k).and_then(|x| deref(x, get)), Some(Obj::Array(a)) if !a.is_empty());
            !nonempty(b"Names") && !nonempty(b"Kids")
        }
        Some(Obj::Null) => true,
        _ => false,
    }
}

fn push_once(v: &mut Vec<String>, s: String) {
    if v.len() < 20 && !v.contains(&s) { v.push(s); }
}

fn pages(ctx: &mut Ctx, doc: &Doc, max: u64) -> Result<u64, Abort> {
    let get = |n: u32| doc.latest.get(&n).map(|&i| &doc.objs[i].obj);
    let root_ref = doc.sections[0].trailer.get(b"Root");
    let Some(Obj::Ref(r, _)) = root_ref else { return Err(Abort::Malformed("trailer has no /Root reference".into())) };
    let cat = get(*r).ok_or_else(|| Abort::Malformed(format!("/Root {r} 0 R does not resolve")))?;
    let Some(Obj::Ref(p, _)) = cat.get(b"Pages") else { return Err(Abort::Malformed("catalog has no /Pages reference".into())) };
    let declared = get(*p).and_then(|o| o.get(b"Count")).and_then(Obj::int);
    let mut count = 0u64;
    let mut seen = HashSet::new();
    let mut stack = vec![(*p, 0usize)];
    while let Some((n, depth)) = stack.pop() {
        ctx.tick()?;
        if depth > 64 { return Err(Abort::Unsupported("page tree deeper than 64".into())); }
        if !seen.insert(n) { return Err(Abort::Malformed(format!("page tree loop at object {n}"))); }
        let node = get(n).ok_or_else(|| Abort::Malformed(format!("page tree node {n} does not resolve")))?;
        match node.get(b"Type").and_then(Obj::name) {
            Some(b"Pages") => match node.get(b"Kids") {
                Some(Obj::Array(k)) => for kid in k.iter().rev() {
                    let Obj::Ref(kn, _) = kid else { return Err(Abort::Malformed("non-reference in /Kids".into())) };
                    stack.push((*kn, depth + 1));
                },
                _ => return Err(Abort::Malformed(format!("/Pages node {n} has no /Kids array"))),
            },
            Some(b"Page") => {
                count += 1;
                if count > max { return Ok(count); }
            }
            _ => return Err(Abort::Malformed(format!("page tree node {n} has no valid /Type"))),
        }
    }
    if let Some(dc) = declared {
        if dc != count as i64 {
            if dc > max as i64 { return Ok(dc as u64); }
            return Err(Abort::Malformed(format!("/Count {dc} but the page tree has {count} pages")));
        }
    }
    Ok(count)
}
