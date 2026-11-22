//! Spec 0.1.4 (ADR 0007): ASCIIHex, ASCII85, RunLength and LZW decoding for content, object and xref
//! streams, chained in any order with Flate, every byte counted against maxDecompressedBytes; anything
//! still undecodable in a stream a check depends on is UNSUPPORTED_FEATURE. Inputs are built in code.

use intakeguard_core::{inspect_bytes, Claimed, Policy};

fn strict() -> Policy {
    Policy::from_json(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../corpus/policies/strict.json")).unwrap()).unwrap()
}

fn verdict(d: &[u8]) -> (String, Vec<String>) {
    let o = inspect_bytes(d, &strict(), &Claimed { filename: Some("document.pdf".into()), mime: None }, None);
    let codes = o.report["reasonCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    (o.report["verdict"].as_str().unwrap().to_string(), codes)
}

fn hex(d: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = d.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect();
    v.push(b'>');
    v
}

fn a85(d: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    for c in d.chunks(4) {
        let mut g = [0u8; 4];
        g[..c.len()].copy_from_slice(c);
        let mut v = u32::from_be_bytes(g) as u64;
        let mut digits = [0u8; 5];
        for i in (0..5).rev() { digits[i] = (v % 85) as u8 + b'!'; v /= 85; }
        out.extend_from_slice(&digits[..c.len() + 1]);
    }
    out.extend_from_slice(b"~>");
    out
}

fn flate(d: &[u8]) -> Vec<u8> { miniz_oxide::deflate::compress_to_vec_zlib(d, 6) }

/// Minimal LZW (no Clear before the table fills; inputs here are short): MSB-first, 9-12-bit,
/// widths following the decoder's table (one entry behind the encoder's).
fn lzw(d: &[u8], early: u32) -> Vec<u8> {
    let mut table: std::collections::HashMap<Vec<u8>, u32> = Default::default();
    struct Bits { acc: u64, n: u32 }
    let mut bits = Bits { acc: 0, n: 0 };
    let mut out = vec![];
    let mut put = |code: u32, w: u32, out: &mut Vec<u8>| {
        bits.acc = (bits.acc << w) | code as u64;
        bits.n += w;
        while bits.n >= 8 { out.push((bits.acc >> (bits.n - 8)) as u8); bits.n -= 8; }
        bits.n
    };
    let width = |dec: u32| { let mut w = 9; while w < 12 && dec + early >= 1 << w { w += 1; } w };
    let (mut next, mut dec, mut first) = (258u32, 258u32, true);
    put(256, 9, &mut out);
    let mut cur: Vec<u8> = vec![];
    for &b in d {
        let mut ext = cur.clone();
        ext.push(b);
        if ext.len() == 1 || table.contains_key(&ext) { cur = ext; continue; }
        let code = if cur.len() == 1 { cur[0] as u32 } else { table[&cur] };
        put(code, width(dec), &mut out);
        if first { first = false } else { dec += 1 }
        assert!(next < 4000, "test encoder has no Clear");
        table.insert(ext, next);
        next += 1;
        cur = vec![b];
    }
    if !cur.is_empty() {
        let code = if cur.len() == 1 { cur[0] as u32 } else { table[&cur] };
        put(code, width(dec), &mut out);
        if !first { dec += 1 }
    }
    let left = put(257, width(dec), &mut out);
    if left > 0 { put(0, 8 - left, &mut out); }
    out
}

fn stream(dict: &str, raw: &[u8]) -> Vec<u8> {
    let mut v = format!("<< {dict} /Length {} >>\nstream\n", raw.len()).into_bytes();
    v.extend_from_slice(raw);
    v.extend_from_slice(b"\nendstream");
    v
}

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

fn page_objs(content: Vec<u8>, resources: &str) -> Vec<Vec<u8>> {
    vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << {resources} >> >>").into_bytes(),
        content,
    ]
}

fn one_page(content: Vec<u8>, extra: Vec<Vec<u8>>, resources: &str) -> Vec<u8> {
    let mut objs = page_objs(content, resources);
    objs.extend(extra);
    build_pdf(&objs)
}

const HIDDEN: &[u8] = b"BT /F1 12 Tf 72 720 Td (visible text, visible text, visible text) Tj ET\nBT 3 Tr (hidden) Tj ET\n";
const PLAIN: &[u8] = b"BT /F1 12 Tf 72 720 Td (visible text, visible text, visible text) Tj ET\n";

#[test]
fn early_change_0_and_1_are_both_read_from_decode_parms() {
    let long: Vec<u8> = HIDDEN.iter().copied().cycle().take(6000).collect(); // crosses the 9->10->11-bit widths
    for (early, parms) in [(1, ""), (1, "/DecodeParms << /EarlyChange 1 >>"), (0, "/DecodeParms << /EarlyChange 0 >>")] {
        let pdf = one_page(stream(&format!("/Filter /LZWDecode {parms}"), &lzw(&long, early)), vec![], "");
        assert_eq!(verdict(&pdf), ("accepted".into(), vec!["PDF_HIDDEN_CONTENT_SUSPECTED".into()]), "early {early} {parms}");
    }
    // A stream encoded with EarlyChange 0 but declared as 1 doesn't silently pass as clean.
    let pdf = one_page(stream("/Filter /LZWDecode", &lzw(&long, 0)), vec![], "");
    assert_ne!(verdict(&pdf), ("accepted".into(), vec![]));
    let pdf = one_page(stream("/Filter /LZWDecode /DecodeParms << /EarlyChange 2 >>", &lzw(PLAIN, 1)), vec![], "");
    assert_eq!(verdict(&pdf), ("rejected".into(), vec!["STRUCTURE_MALFORMED".into()]));
}

#[test]
fn predictor_after_lzw_in_a_chain_on_a_content_stream() {
    // [/ASCIIHexDecode /LZWDecode] with a PNG Up predictor on the LZW stage (DecodeParms aligned).
    let cols = 10;
    let mut text = HIDDEN.to_vec();
    while text.len() % cols != 0 { text.push(b' '); }
    let mut pred = vec![];
    let mut prev = vec![0u8; cols];
    for row in text.chunks(cols) {
        pred.push(2);
        pred.extend(row.iter().zip(&prev).map(|(c, p)| c.wrapping_sub(*p)));
        prev = row.to_vec();
    }
    let dict = format!("/Filter [/ASCIIHexDecode /LZWDecode] /DecodeParms [null << /Predictor 12 /Columns {cols} >>]");
    let pdf = one_page(stream(&dict, &hex(&lzw(&pred, 1))), vec![], "");
    assert_eq!(verdict(&pdf), ("accepted".into(), vec!["PDF_HIDDEN_CONTENT_SUSPECTED".into()]));
}

#[test]
fn xref_stream_with_legacy_filters_and_a_predictor() {
    // Objects 1-4 as in page_objs, then an xref stream (obj 5): [/ASCIIHexDecode /FlateDecode], PNG Up.
    let objs = page_objs(stream("/Filter /ASCII85Decode", &a85(HIDDEN)), "");
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offs = vec![];
    for (i, o) in objs.iter().enumerate() {
        offs.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(o);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref_off = out.len();
    offs.push(xref_off);
    // W [1 4 1], rows for objects 0..=5, PNG Up predictor over 6-byte rows.
    let mut rows: Vec<[u8; 6]> = vec![[0, 0, 0, 0, 0, 255]];
    for o in &offs { let b = (*o as u32).to_be_bytes(); rows.push([1, b[0], b[1], b[2], b[3], 0]); }
    let mut pred = vec![];
    let mut prev = [0u8; 6];
    for r in &rows {
        pred.push(2);
        pred.extend(r.iter().zip(prev).map(|(c, p)| c.wrapping_sub(p)));
        prev = *r;
    }
    let body = stream("/Type /XRef /Size 6 /W [1 4 1] /Root 1 0 R /Filter [/ASCIIHexDecode /FlateDecode] \
                       /DecodeParms [null << /Predictor 12 /Columns 6 >>]", &hex(&flate(&pred)));
    out.extend_from_slice(b"5 0 obj\n");
    out.extend_from_slice(&body);
    out.extend_from_slice(format!("\nendobj\nstartxref\n{xref_off}\n%%EOF\n").as_bytes());
    let (v, codes) = verdict(&out);
    assert_eq!(v, "accepted", "{codes:?}");
    assert!(!codes.iter().any(|c| c == "UNSUPPORTED_FEATURE" || c == "STRUCTURE_MALFORMED"), "{codes:?}");
}

#[test]
fn undecodable_filters_on_content_streams_are_unsupported() {
    for dict in ["/Filter /DCTDecode", "/Filter [/ASCIIHexDecode /JBIG2Decode]",
                 "/Filter /Crypt /DecodeParms << /Name /StdCF >>",
                 "/Filter /LZWDecode /DecodeParms 9 0 R"] {
        let pdf = one_page(stream(dict, &hex(PLAIN)), vec![], "");
        assert_eq!(verdict(&pdf), ("rejected".into(), vec!["UNSUPPORTED_FEATURE".into()]), "{dict}");
    }
    // Crypt /Identity is a passthrough: the stream is still scanned.
    let pdf = one_page(stream("/Filter [/Crypt /ASCIIHexDecode] /DecodeParms [<< /Name /Identity >> null]", &hex(HIDDEN)),
                       vec![], "");
    assert_eq!(verdict(&pdf), ("accepted".into(), vec!["PDF_HIDDEN_CONTENT_SUSPECTED".into()]));
}

#[test]
fn image_only_codecs_on_image_xobjects_are_not_decoded() {
    let jpegish = b"\xff\xd8\xff\xe0 not really a jpeg \xff\xd9";
    let img = stream("/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 \
                      /Filter [/ASCII85Decode /DCTDecode]", &a85(jpegish));
    // An LZW image with predictor parameters the engine would never accept on a content stream: only counted.
    let img2 = stream("/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 \
                       /Filter /LZWDecode /DecodeParms << /Predictor 15 /Columns 99999999 >>", &lzw(&[7; 64], 1));
    let pdf = one_page(stream("/Filter /ASCIIHexDecode", &hex(b"q /Im1 Do Q q /Im2 Do Q")), vec![img, img2],
                       "/XObject << /Im1 5 0 R /Im2 6 0 R >>");
    assert_eq!(verdict(&pdf), ("accepted".into(), vec![]));
}

#[test]
fn chained_bombs_hit_the_decompression_limit() {
    // Flate(RunLength(1 GiB of zeros)): small on disk, each stage counted as it streams.
    let mut rl = Vec::with_capacity(16 << 20);
    for _ in 0..(8 << 20) { rl.extend_from_slice(&[0x81, 0x00]); }
    rl.push(0x80);
    let pdf = one_page(stream("/Filter [/FlateDecode /RunLengthDecode]", &flate(&rl)), vec![], "");
    assert_eq!(verdict(&pdf), ("rejected".into(), vec!["LIMIT_DECOMPRESSED_BYTES_EXCEEDED".into()]));
    // The same bomb on a non-content stream is counted too.
    let pdf = one_page(stream("", PLAIN), vec![stream("/Filter [/FlateDecode /RunLengthDecode]", &flate(&rl))], "");
    assert_eq!(verdict(&pdf), ("rejected".into(), vec!["LIMIT_DECOMPRESSED_BYTES_EXCEEDED".into()]));
}
