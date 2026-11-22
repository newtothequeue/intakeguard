#![no_main]
//! Stream decoders (spec 0.1.4): the fuzz input is the encoded data of one stream in a fixed, valid
//! one-page PDF, so every execution reaches the filter pipeline instead of the PDF parser's error paths.
//!
//! Input layout: byte 0 picks the stream's role (content stream: decoded and scanned; image XObject:
//! only counted against the budget). Bytes 1-3 pick a chain of up to three filters (see FILTERS; a
//! selector past the end stops the chain). The rest is the raw stream data, as written to the file.
use libfuzzer_sys::fuzz_target;
use intakeguard_core::Claimed;
use intakeguard_fuzz::run;

/// (/Filter name, /DecodeParms dict or "null").
const FILTERS: &[(&str, &str)] = &[
    ("/ASCIIHexDecode", "null"),
    ("/ASCII85Decode", "null"),
    ("/RunLengthDecode", "null"),
    ("/LZWDecode", "null"),
    ("/LZWDecode", "<< /EarlyChange 0 >>"),
    ("/FlateDecode", "null"),
    ("/FlateDecode", "<< /Predictor 12 /Columns 8 >>"),
    ("/LZWDecode", "<< /Predictor 2 /Columns 4 /Colors 1 /BitsPerComponent 8 >>"),
    ("/LZWDecode", "<< /Predictor 15 /Columns 3 /Colors 3 /BitsPerComponent 4 /EarlyChange 0 >>"),
    ("/Crypt", "<< /Name /Identity >>"),
    ("/DCTDecode", "null"),
];

fn pdf(objs: &[Vec<u8>]) -> Vec<u8> {
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

fn stream(dict: &str, raw: &[u8]) -> Vec<u8> {
    let mut v = format!("<< {dict} /Length {} >>\nstream\n", raw.len()).into_bytes();
    v.extend_from_slice(raw);
    v.extend_from_slice(b"\nendstream");
    v
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 { return; }
    let (head, raw) = data.split_at(4);
    let chain: Vec<&(&str, &str)> = head[1..].iter().map_while(|s| FILTERS.get(*s as usize)).collect();
    let names: Vec<&str> = chain.iter().map(|f| f.0).collect();
    let parms: Vec<&str> = chain.iter().map(|f| f.1).collect();
    let fdict = format!("/Filter [{}] /DecodeParms [{}]", names.join(" "), parms.join(" "));
    let image = head[0] & 1 == 1;
    let mut objs = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /XObject << /Im1 5 0 R >> >> >>".to_vec(),
    ];
    if image {
        objs.push(stream("", b"q 1 0 0 1 0 0 cm /Im1 Do Q"));
        objs.push(stream(&format!("/Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceGray \
                                   /BitsPerComponent 8 {fdict}"), raw));
    } else {
        objs.push(stream(&fdict, raw));
        objs.push(stream("/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8",
                         b"\x80"));
    }
    run(&pdf(&objs), &Claimed { filename: Some("f.pdf".into()), mime: Some("application/pdf".into()) });
});
