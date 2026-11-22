//! Regression tests that need `make corpus` (corpus/build/). Corpus conformance itself is
//! measured by tools/benchmark/bakeoff.py against the human-owned manifest.

use intakeguard_core::{inspect_bytes, inspect_reader, Claimed, Policy};

fn strict() -> Policy {
    Policy::from_json(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../corpus/policies/strict.json")).unwrap()).unwrap()
}

fn fixture(id: &str, file: &str) -> Vec<u8> {
    let p = format!("{}/../corpus/build/{id}/{file}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|_| panic!("{p} missing: run `make corpus`"))
}

fn verdict(d: &[u8]) -> (String, Vec<String>) {
    let o = inspect_bytes(d, &strict(), &Claimed { filename: Some("document.pdf".into()), mime: None }, None);
    let codes = o.report["reasonCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    (o.report["verdict"].as_str().unwrap().to_string(), codes)
}

/// Found by the bake-off mutation run: if the appended revision's xref/trailer is damaged, the
/// last valid startxref is the clean first revision, but the active objects are still in the file.
#[test]
fn damaged_incremental_update_is_not_accepted() {
    let d = fixture("pdf-evasion-incremental-update", "document.pdf");
    let xref2 = d.windows(4).rposition(|w| w == b"xref").unwrap();
    for cut in [xref2, xref2 + 3, d.len() - 6] {
        let (v, codes) = verdict(&d[..cut]);
        assert_eq!(v, "rejected", "cut at {cut}: {codes:?}");
    }
}

#[test]
fn trailing_text_is_only_a_warning() {
    let (v, codes) = verdict(&fixture("pdf-trailing-data", "document.pdf"));
    assert_eq!(v, "accepted");
    assert_eq!(codes, vec!["PDF_TRAILING_DATA"]);
}

#[test]
fn stream_pulls_at_most_max_bytes_plus_one() {
    struct Zeros(u64);
    impl std::io::Read for Zeros {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { b.fill(0); self.0 += b.len() as u64; Ok(b.len()) }
    }
    let mut z = Zeros(0);
    let o = inspect_reader(&mut z, &strict(), &Claimed::default(), None);
    assert_eq!(o.report["verdict"], "rejected");
    assert_eq!(o.report["original"]["complete"], false);
    assert_eq!(z.0, 10_485_761);
}

#[test]
fn policy_rejects_unknown_fields_and_digest_is_stable() {
    assert!(Policy::from_json(r#"{"version":"0.1","allow":["image/png"],"limitz":{}}"#).is_err());
    let a = Policy::from_json(r#"{"version":"0.1","allow":["image/png"]}"#).unwrap();
    let b = Policy::from_json(r#"{"allow":["image/png"],"version":"0.1","typeMismatch":"reject"}"#).unwrap();
    assert_eq!(a.digest(), b.digest());
}

/// Found by the 0.1.1 mutation run: object headers mangled (`1 0 ob*`) so the appended revision is
/// unreferenced, but its `endobj` sections carrying JavaScript remain after the final %%EOF.
#[test]
fn object_sections_after_eof_are_malformed() {
    let d = fixture("pdf-evasion-damaged-last-xref", "document.pdf");
    let eof = d.windows(5).position(|w| w == b"%%EOF").unwrap() + 6;
    let mut m = d.clone();
    for (i, w) in d.windows(7).enumerate().skip(eof) {
        if w == b"1 0 obj" || w == b"6 0 obj" { m[i + 6] = b'*'; }
    }
    let (v, codes) = verdict(&m);
    assert_eq!(v, "rejected", "{codes:?}");
    assert!(codes.contains(&"STRUCTURE_MALFORMED".to_string()));
}

#[test]
fn spec_011_tolerances_are_narrow() {
    // Empty Flate content is fine; a non-empty truncated Flate stream is not.
    let d = fixture("benign-pdf-empty-flate-stream", "document.pdf");
    assert_eq!(verdict(&d).0, "accepted");
    // Generation 65536 is tolerated only on the object-0 free-list head.
    assert_eq!(verdict(&fixture("benign-pdf-xref-free-gen-65536", "document.pdf")).0, "accepted");
    assert_eq!(verdict(&fixture("pdf-xref-gen-out-of-range", "document.pdf")).1, vec!["STRUCTURE_MALFORMED"]);
}

#[test]
fn report_0_2_fields() {
    let o = inspect_bytes(&fixture("benign-png-8x8", "image.png"), &strict(),
                          &Claimed { filename: Some("image.png".into()), mime: None }, None);
    assert_eq!(o.report["reportVersion"], "0.2");
    assert_eq!(o.report["policyDecision"], "transform");
    assert_eq!(o.report["verdict"], "rejected");
    assert_eq!(o.report["original"]["complete"], true);
    // The streaming path checks the cancel flag before its first read, so this is deterministic.
    let cancel = std::sync::atomic::AtomicBool::new(true);
    let d = fixture("benign-pdf-1page", "report.pdf");
    let c = inspect_reader(&d[..], &strict(), &Claimed::default(), Some(&cancel));
    assert_eq!(c.report["verdict"], "error");
    assert_eq!(c.report["policyDecision"], "error");
    assert_eq!(c.report["reasonCodes"], serde_json::json!(["ENGINE_CANCELLED"]));
}

/// Found by the decode-reencode mutation run: an unknown filter name on a content stream left the
/// hidden-text check skipped while the file was accepted.
#[test]
fn unknown_stream_filter_is_unsupported() {
    let d = fixture("benign-pdf-empty-flate-stream", "document.pdf");
    let i = d.windows(11).position(|w| w == b"FlateDecode").unwrap();
    let mut m = d.clone();
    m[i + 4] = b'm'; // FlatmDecode
    let (v, codes) = verdict(&m);
    assert_eq!(v, "rejected");
    assert_eq!(codes, vec!["UNSUPPORTED_FEATURE"]);
}

fn sanitize(id: &str, file: &str) -> intakeguard_core::Outcome {
    intakeguard_core::sanitize_bytes(&fixture(id, file), &strict(), &Claimed { filename: Some(file.into()), mime: None }, None)
}

#[test]
fn sanitize_produces_new_metadata_free_bytes() {
    for (id, file, mime) in [("img-meta-jpeg-exif-gps", "photo.jpg", "image/jpeg"),
                             ("img-meta-png-text-exif", "image.png", "image/png"),
                             ("benign-webp-8x8", "image.webp", "image/webp")] {
        let o = sanitize(id, file);
        assert_eq!(o.report["verdict"], "transformed", "{id}: {}", o.report);
        let out = o.output.expect("output bytes");
        assert_eq!(o.report["output"]["mime"], mime);
        assert_ne!(o.report["output"]["sha256"], o.report["original"]["sha256"]);
        for needle in [&b"Exif\0\0"[..], b"tEXt", b"eXIf", b"http://ns.adobe.com/xap/1.0/", b"Jane Example"] {
            assert!(!out.windows(needle.len()).any(|w| w == needle), "{id}: output contains {needle:?}");
        }
    }
}

#[test]
fn inspect_never_returns_output() {
    let o = inspect_bytes(&fixture("benign-jpeg-8x8", "photo.jpg"), &strict(),
                          &Claimed { filename: Some("photo.jpg".into()), mime: None }, None);
    assert!(o.output.is_none());
    assert_eq!(o.report["verdict"], "rejected");
    assert_eq!(o.report["policyDecision"], "transform");
}

#[test]
fn sanitizing_a_lossless_output_again_is_a_fixpoint() {
    let first = sanitize("benign-png-8x8", "image.png").output.unwrap();
    let o = intakeguard_core::sanitize_bytes(&first, &strict(), &Claimed { filename: Some("image.png".into()), mime: None }, None);
    assert_eq!(o.report["verdict"], "accepted", "{}", o.report);
    assert!(o.output.is_none());
}

// ---- spec 0.1.2 / review of PR #2

#[test]
fn grayscale_jpeg_is_transformed() {
    let o = sanitize("benign-jpeg-grayscale-8x8", "scan.jpg");
    assert_eq!(o.report["verdict"], "transformed", "{}", o.report);
}

#[test]
fn exif_orientation_is_applied() {
    let o = sanitize("img-exif-orientation-6", "photo.jpg");
    assert_eq!(o.report["verdict"], "transformed", "{}", o.report);
    let out = o.output.unwrap();
    let sof = out.windows(2).position(|w| w == [0xFF, 0xC0]).unwrap();
    let (h, w) = (u16::from_be_bytes([out[sof + 5], out[sof + 6]]), u16::from_be_bytes([out[sof + 7], out[sof + 8]]));
    assert_eq!((w, h), (8, 16));
    // Disabled by policy: dimensions unchanged.
    let mut p: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../corpus/policies/strict.json")).unwrap()).unwrap();
    p["images"]["applyOrientation"] = false.into();
    let pol = Policy::from_json(&p.to_string()).unwrap();
    let o = intakeguard_core::sanitize_bytes(&fixture("img-exif-orientation-6", "photo.jpg"), &pol, &Claimed::default(), None);
    let out = o.output.unwrap();
    let sof = out.windows(2).position(|w| w == [0xFF, 0xC0]).unwrap();
    assert_eq!(u16::from_be_bytes([out[sof + 7], out[sof + 8]]), 16);
}

#[test]
fn lossy_webp_becomes_jpeg() {
    let o = sanitize("benign-webp-lossy-to-jpeg", "photo.webp");
    assert_eq!(o.report["output"]["mime"], "image/jpeg", "{}", o.report);
    assert!(o.report["transformations"].as_array().unwrap().iter().any(|t| t["id"] == "image.format-converted"));
}

#[test]
fn iccp_is_metadata_and_never_reaches_the_decoder() {
    let o = sanitize("img-bomb-png-iccp", "image.png");
    assert_eq!(o.report["verdict"], "transformed", "{}", o.report);
    assert!(o.report["reasonCodes"].as_array().unwrap().iter().any(|c| c == "IMAGE_METADATA_PRESENT"));
    assert!(!o.output.unwrap().windows(4).any(|w| w == b"iCCP"));
}

#[test]
fn structelem_attributes_are_not_actions_but_active_types_still_are() {
    let d = fixture("benign-pdf-tagged-structelem-attributes", "report.pdf");
    assert_eq!(verdict(&d).0, "accepted");
    // Same length, so the xref stays valid: a JavaScript action smuggled into StructElem /A.
    let from = b"/A << /O /Layout /Placement /Block >>";
    let to   = b"/A << /S /JavaScript /JS (x)       >>";
    assert_eq!(from.len(), to.len());
    let i = d.windows(from.len()).position(|w| w == from).unwrap();
    let mut m = d.clone();
    m[i..i + to.len()].copy_from_slice(to);
    let (v, codes) = verdict(&m);
    assert_eq!(v, "rejected");
    assert!(codes.contains(&"PDF_ACTIVE_CONTENT".to_string()), "{codes:?}");
}

#[test]
fn filter_abbreviations_are_nonstandard_on_streams() {
    let d = fixture("benign-pdf-empty-flate-stream", "document.pdf");
    let from = b"/Filter /FlateDecode";
    let to   = b"/Filter /Fl         ";
    let i = d.windows(from.len()).position(|w| w == from).unwrap();
    let mut m = d.clone();
    m[i..i + to.len()].copy_from_slice(to);
    assert_eq!(verdict(&m).1, vec!["UNSUPPORTED_FEATURE"]);
}

// ---- spec 0.1.3

#[test]
fn lossy_webp_with_alpha_becomes_png_with_alpha() {
    let o = sanitize("benign-webp-lossy-alpha-to-png", "logo.webp");
    assert_eq!(o.report["verdict"], "transformed", "{}", o.report);
    assert_eq!(o.report["output"]["mime"], "image/png");
    let out = o.output.unwrap();
    // IHDR colour type 6 = RGBA.
    assert_eq!(out[25], 6, "PNG colour type");
    // Lossy WebP without alpha still becomes JPEG.
    assert_eq!(sanitize("benign-webp-lossy-to-jpeg", "photo.webp").report["output"]["mime"], "image/jpeg");
}

// ---- found by cargo-fuzz (tools/fuzz), 2026-11-22

/// Classic-xref PDF from object bodies (1-based, consecutive), like corpus/generators/_lib.py.
fn build_pdf(objs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offs = vec![];
    for (i, o) in objs.iter().enumerate() {
        offs.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(o);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offs { out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes()); }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

fn flate_stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let z = miniz_oxide::deflate::compress_to_vec_zlib(data, 6);
    let mut v = format!("<< {dict} /Filter /FlateDecode /Length {} >>\nstream\n", z.len()).into_bytes();
    v.extend_from_slice(&z);
    v.extend_from_slice(b"\nendstream");
    v
}

fn one_page(content: Vec<u8>, extra: Vec<Vec<u8>>, resources: &str) -> Vec<u8> {
    let mut objs = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << {resources} >> >>").into_bytes(),
        content,
    ];
    objs.extend(extra);
    build_pdf(&objs)
}

/// pdf fuzz crash: a content stream decoding to >4 MiB left pdf.hidden-content `skipped` (the old
/// scan cap) while the file was `accepted`, contradicting "accepted = every applicable check passed".
/// The scan is now streaming: every byte is scanned, so hidden text at the very end is found.
#[test]
fn large_content_streams_are_scanned_to_the_end() {
    let mut text = b"BT /F1 12 Tf 72 720 Td (visible) Tj ET\n".to_vec();
    text.extend(std::iter::repeat(b' ').take(12 << 20));
    text.extend_from_slice(b"\nBT 3 Tr (invisible) Tj ET");
    let pdf = one_page(flate_stream("", &text), vec![], "");
    let (v, codes) = verdict(&pdf);
    assert_eq!(v, "accepted", "{codes:?}");
    assert_eq!(codes, vec!["PDF_HIDDEN_CONTENT_SUSPECTED"]);
    let o = inspect_bytes(&pdf, &strict(), &Claimed::default(), None);
    let hc = o.report["checks"].as_array().unwrap().iter().find(|c| c["id"] == "pdf.hidden-content").unwrap();
    assert_eq!(hc["status"], "passed", "{hc}");
}

/// Found while fixing the above: a Flate stream with a PNG predictor that is not a content stream
/// (e.g. an image XObject) was rejected as UNSUPPORTED_FEATURE, because it was decoded with a
/// zero-byte retention cap. Only content streams need their bytes; the rest are only counted.
#[test]
fn predicted_image_streams_are_not_rejected() {
    let (w, h) = (8usize, 4usize);
    let mut rows = vec![];
    for _ in 0..h { rows.push(2u8); rows.extend(std::iter::repeat(7u8).take(w * 3)); } // PNG "Up" filter rows
    let img = flate_stream(&format!("/Type /XObject /Subtype /Image /Width {w} /Height {h} /ColorSpace /DeviceRGB \
                                     /BitsPerComponent 8 /DecodeParms << /Predictor 15 /Colors 3 /Columns {w} >>"), &rows);
    let pdf = one_page(flate_stream("", b"q 8 0 0 4 72 700 cm /Im1 Do Q"), vec![img], "/XObject << /Im1 5 0 R >>");
    let (v, codes) = verdict(&pdf);
    assert_eq!(v, "accepted", "{codes:?}");
}

/// jpeg fuzz crash: zune-jpeg panicked (upsampler assertion) on a 4-component frame whose first
/// component was 1x1 and second 2x2. Exotic sampling layouts are now UNSUPPORTED_FEATURE before
/// any decoder runs.
#[test]
fn exotic_jpeg_sampling_is_unsupported_not_a_decoder_panic() {
    let mut d = fixture("benign-jpeg-8x8", "photo.jpg");
    let sof = d.windows(2).position(|w| w == [0xFF, 0xC0]).unwrap();
    // components start at sof+10: (id, sampling, qtable) x n
    d[sof + 11] = 0x11;
    d[sof + 14] = 0x22;
    let o = intakeguard_core::sanitize_bytes(&d, &strict(), &Claimed { filename: Some("photo.jpg".into()), mime: None }, None);
    assert_eq!(o.report["verdict"], "rejected", "{}", o.report);
    assert!(o.report["reasonCodes"].as_array().unwrap().iter().any(|c| c == "UNSUPPORTED_FEATURE"));
    // Standard layouts still decode: the untouched fixture (4:2:0) and a 4:4:4 variant.
    let mut d444 = fixture("benign-jpeg-8x8", "photo.jpg");
    assert_eq!(intakeguard_core::sanitize_bytes(&d444, &strict(), &Claimed::default(), None).report["verdict"], "transformed");
    d444[sof + 11] = 0x11;
    let v = intakeguard_core::sanitize_bytes(&d444, &strict(), &Claimed::default(), None).report["verdict"].clone();
    assert!(v == "transformed" || v == "rejected", "{v}"); // 4:4:4 header with 4:2:0 scan data may not decode
}
