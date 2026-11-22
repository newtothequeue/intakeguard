//! Stream decoding with a running decompression budget shared by the whole file (spec 0.1.4).
//!
//! Every filter chain runs as a push-based pipeline: each stage is a small state machine that passes its
//! output, chunk by chunk, to the next stage, so memory stays constant however long the chain is or however
//! much a stage expands (a RunLength or LZW bomb never materializes). Each decoder stage counts its output
//! against `maxDecompressedBytes` before passing it on.
//!
//! Decoded in-house, with no new dependency: FlateDecode (miniz_oxide), ASCIIHexDecode, ASCII85Decode,
//! RunLengthDecode, LZWDecode (EarlyChange 0/1), PNG predictors 10-15 and TIFF predictor 2 (Flate/LZW),
//! and Crypt /Identity. A truncated or invalid encoding is STRUCTURE_MALFORMED.

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

use super::syntax::Obj;
use crate::report::{Abort, Ctx};

pub struct Budget {
    pub used: u64,
    pub max: u64,
}


/// Standard stream filter names (ISO 32000-1 Table 6; spec 0.1.2). The abbreviations (AHx, Fl, ...)
/// are valid in inline images only, which this engine never decodes, so on a stream they are
/// non-standard. Anything outside this set is unsupported (fail closed).
const STANDARD: &[&[u8]] = &[b"ASCIIHexDecode", b"ASCII85Decode", b"LZWDecode", b"FlateDecode",
                             b"RunLengthDecode", b"CCITTFaxDecode", b"JBIG2Decode", b"DCTDecode",
                             b"JPXDecode", b"Crypt"];

fn filters(dict: &Obj) -> Result<Vec<Vec<u8>>, Abort> {
    let fs = filters_raw(dict)?;
    if let Some(f) = fs.iter().find(|f| !STANDARD.contains(&f.as_slice())) {
        return Err(Abort::Unsupported(format!("unknown stream filter /{}", String::from_utf8_lossy(f))));
    }
    Ok(fs)
}

fn filters_raw(dict: &Obj) -> Result<Vec<Vec<u8>>, Abort> {
    match dict.get(b"Filter") {
        None | Some(Obj::Null) => Ok(vec![]),
        Some(Obj::Name(n)) => Ok(vec![n.val.clone()]),
        Some(Obj::Array(a)) => a.iter().map(|o| o.name().map(<[u8]>::to_vec)
            .ok_or_else(|| Abort::Malformed("non-name in /Filter array".into()))).collect(),
        Some(Obj::Ref(..)) => Err(Abort::Unsupported("indirect /Filter".into())),
        _ => Err(Abort::Malformed("invalid /Filter".into())),
    }
}

/// What the caller needs from a stream.
pub enum Want<'a> {
    /// Only count decoded bytes against the budget (images, fonts, other non-syntax streams). Image-only
    /// codecs at the end of the chain (DCT, JPX, JBIG2, CCITTFax) are not decoded: decoding stops there.
    Count,
    /// The whole decoded stream (xref and object streams).
    All,
    /// Decoded bytes, chunk by chunk, in order (content streams, for the hidden-text scan).
    Feed(&'a mut dyn FnMut(&[u8])),
}

/// Image codecs whose payload is pixel data, not PDF syntax.
fn is_opaque(f: &[u8]) -> bool {
    matches!(f, b"DCTDecode" | b"JPXDecode" | b"CCITTFaxDecode" | b"JBIG2Decode")
}

/// Decode `raw` according to the stream dict.
/// Returns (the whole output for `Want::All`, Some(filter) if the chain contains a filter this engine
/// doesn't decode). For `All` and `Feed`, a filter that can't be decoded means the caller's check can't
/// run: it must reject (UNSUPPORTED_FEATURE). For `Count`, decoding simply stops before it.
pub fn decode_stream(ctx: &mut Ctx, dict: &Obj, raw: &[u8], budget: &mut Budget, want: Want)
                     -> Result<(Option<Vec<u8>>, Option<String>), Abort> {
    let fs = filters(dict)?;
    let parms = decode_parms(dict, fs.len())?;
    let needs_bytes = !matches!(want, Want::Count);
    // Build the stages up to the first filter we don't decode.
    let mut stages: Vec<StageKind> = Vec::new();
    let mut undecodable: Option<String> = None;
    for (i, f) in fs.iter().enumerate() {
        let p = parms[i].as_ref();
        match stage_kind(f, p)? {
            Some(k) => stages.push(k),
            None => {
                undecodable = Some(String::from_utf8_lossy(f).into_owned());
                break;
            }
        }
        // Counting only needs each decoder's output, so a predictor with no decoder after it is not run
        // (an image's predictor rows are pixel data; their parameters are not validated here).
        let feeds_a_decoder = fs.get(i + 1).is_some_and(|n| !is_opaque(n));
        if needs_bytes || feeds_a_decoder {
            if let Some(pr) = predictor(f, p)? { stages.push(pr); }
        }
    }
    if needs_bytes {
        if let Some(f) = undecodable { return Ok((None, Some(f))); }
    } else {
        // A predictor stopped at an undecodable filter only feeds the discard sink.
        while matches!(stages.last(), Some(StageKind::Png { .. } | StageKind::Tiff { .. } | StageKind::Identity)) {
            stages.pop();
        }
    }
    let mut collected: Vec<u8> = Vec::new();
    {
        let mut env = Env { ctx, budget };
        let terminal: Box<dyn Stage + '_> = match want {
            Want::Count => Box::new(Discard),
            Want::All => Box::new(Collect(&mut collected)),
            Want::Feed(f) => Box::new(Forward(f)),
        };
        let mut pipe = build(stages, terminal);
        pipe.put(&mut env, raw)?;
        pipe.end(&mut env)?;
    }
    Ok((needs_bytes.then_some(collected), None))
}

/// /DecodeParms aligned with the filter list (a dict for a single filter, or an array with nulls).
fn decode_parms(dict: &Obj, n: usize) -> Result<Vec<Option<Obj>>, Abort> {
    let mut out = vec![None; n];
    match dict.get(b"DecodeParms") {
        None | Some(Obj::Null) => {}
        Some(d @ Obj::Dict(_)) => { if n > 0 { out[0] = Some(d.clone()); } }
        Some(Obj::Array(a)) => {
            for (i, o) in a.iter().enumerate().take(n) {
                match o {
                    Obj::Null => {}
                    Obj::Dict(_) => out[i] = Some(o.clone()),
                    Obj::Ref(..) => return Err(Abort::Unsupported("indirect /DecodeParms entry".into())),
                    _ => return Err(Abort::Malformed("invalid /DecodeParms entry".into())),
                }
            }
        }
        Some(Obj::Ref(..)) => return Err(Abort::Unsupported("indirect /DecodeParms".into())),
        _ => return Err(Abort::Malformed("invalid /DecodeParms".into())),
    }
    Ok(out)
}

fn int_parm(p: Option<&Obj>, key: &[u8], default: i64) -> Result<i64, Abort> {
    match p.and_then(|p| p.get(key)) {
        None => Ok(default),
        Some(Obj::Int(v)) => Ok(*v),
        Some(Obj::Ref(..)) => Err(Abort::Unsupported(format!("indirect /{} in /DecodeParms", String::from_utf8_lossy(key)))),
        Some(_) => Err(Abort::Malformed(format!("invalid /{} in /DecodeParms", String::from_utf8_lossy(key)))),
    }
}

enum StageKind { Flate, Hex, A85, RunLength, Lzw { early: bool }, Png { row: usize, bpp: usize }, Tiff { cols: usize, colors: usize, bpc: usize }, Identity }

/// The decoder for one filter, or None if this engine doesn't decode it.
fn stage_kind(f: &[u8], p: Option<&Obj>) -> Result<Option<StageKind>, Abort> {
    Ok(Some(match f {
        b"FlateDecode" => StageKind::Flate,
        b"ASCIIHexDecode" => StageKind::Hex,
        b"ASCII85Decode" => StageKind::A85,
        b"RunLengthDecode" => StageKind::RunLength,
        b"LZWDecode" => match int_parm(p, b"EarlyChange", 1)? {
            0 => StageKind::Lzw { early: false },
            1 => StageKind::Lzw { early: true },
            e => return Err(Abort::Malformed(format!("LZW /EarlyChange {e}"))),
        },
        b"Crypt" => match p.and_then(|p| p.get(b"Name")).and_then(Obj::name) {
            None | Some(b"Identity") => StageKind::Identity,
            Some(_) => return Ok(None),
        },
        f if is_opaque(f) => return Ok(None),
        _ => return Ok(None),
    }))
}

/// The predictor stage that follows a Flate or LZW stage, if its /DecodeParms ask for one.
fn predictor(f: &[u8], p: Option<&Obj>) -> Result<Option<StageKind>, Abort> {
    if !matches!(f, b"FlateDecode" | b"LZWDecode") { return Ok(None); }
    let pred = int_parm(p, b"Predictor", 1)?;
    if pred == 1 { return Ok(None); }
    let cols = int_parm(p, b"Columns", 1)?;
    let colors = int_parm(p, b"Colors", 1)?;
    let bpc = int_parm(p, b"BitsPerComponent", 8)?;
    if !(1..=1 << 20).contains(&cols) || !(1..=32).contains(&colors) || ![1, 2, 4, 8, 16].contains(&bpc) {
        return Err(Abort::Malformed("invalid predictor parameters".into()));
    }
    let (cols, colors, bpc) = (cols as usize, colors as usize, bpc as usize);
    if (cols * colors * bpc + 7) / 8 > MAX_PREDICTOR_ROW {
        return Err(Abort::Unsupported(format!("predictor row longer than {MAX_PREDICTOR_ROW} bytes")));
    }
    match pred {
        2 => Ok(Some(StageKind::Tiff { cols, colors, bpc })),
        10..=15 => Ok(Some(StageKind::Png { row: (cols * colors * bpc + 7) / 8, bpp: ((colors * bpc + 7) / 8).max(1) })),
        _ => Err(Abort::Malformed(format!("invalid /Predictor {pred}"))),
    }
}

/// Longest predictor row this engine buffers (xref and content rows are tiny in practice).
const MAX_PREDICTOR_ROW: usize = 1 << 20;

// ------------------------------------------------------------------------------------ pipeline

pub struct Env<'c, 'b, 'x> {
    ctx: &'c mut Ctx<'x>,
    budget: &'b mut Budget,
}

impl Env<'_, '_, '_> {
    fn count(&mut self, n: usize) -> Result<(), Abort> {
        self.ctx.tick()?;
        self.budget.used += n as u64;
        if self.budget.used > self.budget.max {
            return Err(Abort::Decompressed(format!(
                "decoded bytes exceeded maxDecompressedBytes={} (stopped at {})", self.budget.max, self.budget.used)));
        }
        Ok(())
    }
}

trait Stage {
    fn put(&mut self, env: &mut Env, data: &[u8]) -> Result<(), Abort>;
    fn end(&mut self, env: &mut Env) -> Result<(), Abort>;
}

struct Discard;
impl Stage for Discard {
    fn put(&mut self, _: &mut Env, _: &[u8]) -> Result<(), Abort> { Ok(()) }
    fn end(&mut self, _: &mut Env) -> Result<(), Abort> { Ok(()) }
}

struct Collect<'v>(&'v mut Vec<u8>);
impl Stage for Collect<'_> {
    fn put(&mut self, _: &mut Env, d: &[u8]) -> Result<(), Abort> { self.0.extend_from_slice(d); Ok(()) }
    fn end(&mut self, _: &mut Env) -> Result<(), Abort> { Ok(()) }
}

struct Forward<'f>(&'f mut dyn FnMut(&[u8]));
impl Stage for Forward<'_> {
    fn put(&mut self, _: &mut Env, d: &[u8]) -> Result<(), Abort> { (self.0)(d); Ok(()) }
    fn end(&mut self, _: &mut Env) -> Result<(), Abort> { Ok(()) }
}

const OUT_CHUNK: usize = 64 * 1024;

/// Output side of a decoder stage: buffers up to OUT_CHUNK, counts each flush against the budget,
/// then passes it to the next stage.
struct Out<'n> {
    buf: Vec<u8>,
    next: Box<dyn Stage + 'n>,
}

impl Out<'_> {
    fn new<'n>(next: Box<dyn Stage + 'n>) -> Out<'n> { Out { buf: Vec::with_capacity(OUT_CHUNK), next } }
    #[inline]
    fn byte(&mut self, env: &mut Env, b: u8) -> Result<(), Abort> {
        self.buf.push(b);
        if self.buf.len() >= OUT_CHUNK { self.flush(env)?; }
        Ok(())
    }
    fn bytes(&mut self, env: &mut Env, d: &[u8]) -> Result<(), Abort> {
        for c in d.chunks(OUT_CHUNK) {
            self.buf.extend_from_slice(c);
            if self.buf.len() >= OUT_CHUNK { self.flush(env)?; }
        }
        Ok(())
    }
    fn flush(&mut self, env: &mut Env) -> Result<(), Abort> {
        if self.buf.is_empty() { return Ok(()); }
        env.count(self.buf.len())?;
        let r = self.next.put(env, &self.buf);
        self.buf.clear();
        r
    }
    fn finish(&mut self, env: &mut Env) -> Result<(), Abort> {
        self.flush(env)?;
        self.next.end(env)
    }
}

fn build<'n>(stages: Vec<StageKind>, terminal: Box<dyn Stage + 'n>) -> Box<dyn Stage + 'n> {
    let mut next = terminal;
    for k in stages.into_iter().rev() {
        next = match k {
            StageKind::Flate => Box::new(Flate { st: InflateState::new_boxed(DataFormat::Zlib), out: Out::new(next),
                                                 done: false, seen: false, scratch: vec![0u8; OUT_CHUNK] }),
            StageKind::Hex => Box::new(Hex { hi: None, done: false, out: Out::new(next) }),
            StageKind::A85 => Box::new(A85 { group: [0; 5], n: 0, tilde: false, done: false, out: Out::new(next) }),
            StageKind::RunLength => Box::new(RunLength { st: RlState::Len, done: false, out: Out::new(next) }),
            StageKind::Lzw { early } => Box::new(Lzw::new(early, Out::new(next))),
            StageKind::Png { row, bpp } => Box::new(Png { row, bpp, cur: Vec::with_capacity(row + 1),
                                                          prev: Vec::new(), outrow: Vec::new(), next }),
            StageKind::Tiff { cols, colors, bpc } => Box::new(Tiff { row: (cols * colors * bpc + 7) / 8, colors, bpc,
                                                                    cur: Vec::new(), next }),
            StageKind::Identity => next,
        };
    }
    next
}

fn mal(m: impl Into<String>) -> Abort { Abort::Malformed(m.into()) }

/// Spec 0.1.5 (ADR 0008): only PDF whitespace may follow a stage's end-of-data marker. Readers disagree about
/// anything else (qpdf's RunLength decoder ignores an early EOD and keeps going), so it is malformed.
fn after_eod(filter: &str, rest: &[u8]) -> Result<(), Abort> {
    match rest.iter().position(|&b| !super::syntax::is_ws(b)) {
        None => Ok(()),
        Some(i) => Err(mal(format!("{filter} data continues after its end-of-data marker (byte 0x{:02x})", rest[i]))),
    }
}

// ------------------------------------------------------------------------------------ decoders

struct Flate<'n> { st: Box<InflateState>, out: Out<'n>, done: bool, seen: bool, scratch: Vec<u8> }

impl Stage for Flate<'_> {
    fn put(&mut self, env: &mut Env, data: &[u8]) -> Result<(), Abort> {
        if self.done { return after_eod("FlateDecode", data); }
        if !data.is_empty() { self.seen = true; }
        let mut input = data;
        while !self.done && !input.is_empty() {
            let r = inflate(&mut self.st, input, &mut self.scratch, MZFlush::None);
            input = &input[r.bytes_consumed..];
            let n = r.bytes_written;
            if n > 0 {
                let chunk = self.scratch[..n].to_vec();
                self.out.bytes(env, &chunk)?;
            }
            match r.status {
                Ok(MZStatus::StreamEnd) => {
                    self.done = true;
                    return after_eod("FlateDecode", input);
                }
                Ok(_) | Err(MZError::Buf) => {
                    if r.bytes_consumed == 0 && n == 0 { break; } // needs more input
                }
                Err(e) => return Err(mal(format!("Flate decode error: {e:?}"))),
            }
        }
        Ok(())
    }
    fn end(&mut self, env: &mut Env) -> Result<(), Abort> {
        // Drain any output still buffered inside the inflater.
        while !self.done && self.seen {
            let r = inflate(&mut self.st, &[], &mut self.scratch, MZFlush::Finish);
            let n = r.bytes_written;
            if n > 0 {
                let chunk = self.scratch[..n].to_vec();
                self.out.bytes(env, &chunk)?;
            }
            match r.status {
                Ok(MZStatus::StreamEnd) => self.done = true,
                _ if n == 0 => break,
                _ => {}
            }
        }
        // Spec 0.1.1 tolerance: an empty Flate stream (/Length 0) is empty content.
        if self.seen && !self.done {
            return Err(mal("Flate stream ends before its end-of-stream marker"));
        }
        self.out.finish(env)
    }
}

struct Hex<'n> { hi: Option<u8>, done: bool, out: Out<'n> }

impl Stage for Hex<'_> {
    fn put(&mut self, env: &mut Env, data: &[u8]) -> Result<(), Abort> {
        if self.done { return after_eod("ASCIIHexDecode", data); }
        for (i, &b) in data.iter().enumerate() {
            let v = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                b'>' => {
                    if let Some(h) = self.hi.take() { self.out.byte(env, h << 4)?; }
                    self.done = true;
                    return after_eod("ASCIIHexDecode", &data[i + 1..]);
                }
                c if super::syntax::is_ws(c) => continue,
                c => return Err(mal(format!("invalid byte 0x{c:02x} in ASCIIHexDecode data"))),
            };
            match self.hi.take() { Some(h) => self.out.byte(env, h << 4 | v)?, None => self.hi = Some(v) }
        }
        Ok(())
    }
    fn end(&mut self, env: &mut Env) -> Result<(), Abort> {
        if !self.done { return Err(mal("ASCIIHexDecode data ends without its '>' end-of-data marker")); }
        self.out.finish(env)
    }
}

struct A85<'n> { group: [u8; 5], n: usize, tilde: bool, done: bool, out: Out<'n> }

impl A85<'_> {
    fn emit_group(&mut self, env: &mut Env, n: usize) -> Result<(), Abort> {
        // n = number of significant characters (2..=5); pad the rest with 'u'.
        let mut v: u64 = 0;
        for i in 0..5 { v = v * 85 + (if i < n { self.group[i] } else { 84 }) as u64; }
        if v > u32::MAX as u64 { return Err(mal("ASCII85 group out of range")); }
        let b = (v as u32).to_be_bytes();
        self.out.bytes(env, &b[..n - 1])
    }
}

impl Stage for A85<'_> {
    fn put(&mut self, env: &mut Env, data: &[u8]) -> Result<(), Abort> {
        if self.done { return after_eod("ASCII85Decode", data); }
        for (i, &c) in data.iter().enumerate() {
            if self.tilde {
                if c != b'>' { return Err(mal("ASCII85 '~' not followed by '>'")); }
                match self.n {
                    0 => {}
                    1 => return Err(mal("ASCII85 final group has a single character")),
                    n => self.emit_group(env, n)?,
                }
                self.n = 0;
                self.done = true;
                return after_eod("ASCII85Decode", &data[i + 1..]);
            }
            match c {
                b'!'..=b'u' => {
                    self.group[self.n] = c - b'!';
                    self.n += 1;
                    if self.n == 5 { self.emit_group(env, 5)?; self.n = 0; }
                }
                b'z' if self.n == 0 => self.out.bytes(env, &[0, 0, 0, 0])?,
                b'z' => return Err(mal("ASCII85 'z' inside a group")),
                b'~' => self.tilde = true,
                c if super::syntax::is_ws(c) => {}
                c => return Err(mal(format!("invalid byte 0x{c:02x} in ASCII85Decode data"))),
            }
        }
        Ok(())
    }
    fn end(&mut self, env: &mut Env) -> Result<(), Abort> {
        if !self.done { return Err(mal("ASCII85Decode data ends without its '~>' end-of-data marker")); }
        self.out.finish(env)
    }
}

enum RlState { Len, Literal(usize), Repeat(usize) }

struct RunLength<'n> { st: RlState, done: bool, out: Out<'n> }

impl Stage for RunLength<'_> {
    fn put(&mut self, env: &mut Env, data: &[u8]) -> Result<(), Abort> {
        if self.done { return after_eod("RunLengthDecode", data); }
        let mut i = 0;
        while i < data.len() {
            match self.st {
                RlState::Len => {
                    let l = data[i];
                    i += 1;
                    self.st = match l {
                        128 => {
                            self.done = true;
                            return after_eod("RunLengthDecode", &data[i..]);
                        }
                        0..=127 => RlState::Literal(l as usize + 1),
                        _ => RlState::Repeat(257 - l as usize),
                    };
                }
                RlState::Literal(n) => {
                    let take = n.min(data.len() - i);
                    self.out.bytes(env, &data[i..i + take])?;
                    i += take;
                    self.st = if take == n { RlState::Len } else { RlState::Literal(n - take) };
                }
                RlState::Repeat(n) => {
                    let b = data[i];
                    i += 1;
                    self.out.bytes(env, &[b; 128][..n])?;
                    self.st = RlState::Len;
                }
            }
        }
        Ok(())
    }
    fn end(&mut self, env: &mut Env) -> Result<(), Abort> {
        if !self.done { return Err(mal("RunLengthDecode data ends without its end-of-data byte (128)")); }
        self.out.finish(env)
    }
}

const LZW_CLEAR: u16 = 256;
const LZW_EOD: u16 = 257;
const LZW_MAX: usize = 4096;

struct Lzw<'n> {
    early: bool,
    acc: u32,
    nbits: u32,
    width: u32,
    /// entry -> (prefix code, last byte, length); 0..=255 are the single bytes.
    prefix: Vec<u16>,
    last: Vec<u8>,
    len: Vec<u16>,
    prev: Option<u16>,
    done: bool,
    scratch: Vec<u8>,
    out: Out<'n>,
}

impl<'n> Lzw<'n> {
    fn new(early: bool, out: Out<'n>) -> Lzw<'n> {
        let mut z = Lzw { early, acc: 0, nbits: 0, width: 9, prefix: Vec::with_capacity(LZW_MAX),
                          last: Vec::with_capacity(LZW_MAX), len: Vec::with_capacity(LZW_MAX), prev: None,
                          done: false, scratch: Vec::with_capacity(LZW_MAX), out };
        z.reset();
        z
    }

    fn reset(&mut self) {
        self.prefix.clear();
        self.last.clear();
        self.len.clear();
        for b in 0..=255u16 { self.prefix.push(u16::MAX); self.last.push(b as u8); self.len.push(1); }
        // 256 (Clear) and 257 (EOD) are not strings.
        for _ in 0..2 { self.prefix.push(u16::MAX); self.last.push(0); self.len.push(0); }
        self.width = 9;
        self.prev = None;
    }

    /// The string for `code`, written into self.scratch.
    fn string(&mut self, code: u16) {
        let n = self.len[code as usize] as usize;
        self.scratch.clear();
        self.scratch.resize(n, 0);
        let mut c = code;
        for i in (0..n).rev() {
            self.scratch[i] = self.last[c as usize];
            c = self.prefix[c as usize];
        }
    }

    fn add(&mut self, prefix: u16, byte: u8) {
        if self.prefix.len() >= LZW_MAX { return; } // table full: keep decoding with what we have
        let l = self.len[prefix as usize] + 1;
        self.prefix.push(prefix);
        self.last.push(byte);
        self.len.push(l);
        let next = self.prefix.len() as u32 + self.early as u32;
        if next >= (1 << self.width) && self.width < 12 { self.width += 1; }
    }

    fn code(&mut self, env: &mut Env, code: u16) -> Result<(), Abort> {
        match code {
            LZW_CLEAR => { self.reset(); return Ok(()); }
            LZW_EOD => { self.done = true; return Ok(()); }
            _ => {}
        }
        let next = self.prefix.len() as u16;
        match self.prev {
            None => {
                if code >= 256 { return Err(mal("LZW first code after a reset is not a literal")); }
                self.out.byte(env, code as u8)?;
            }
            Some(p) => {
                if code < next {
                    self.string(code);
                    let first = self.scratch[0];
                    self.add(p, first);
                } else if code == next && (next as usize) < LZW_MAX {
                    self.string(p);
                    let first = self.scratch[0];
                    self.scratch.push(first);
                    self.add(p, first);
                } else {
                    return Err(mal(format!("LZW code {code} beyond the table ({next} entries)")));
                }
                let s = std::mem::take(&mut self.scratch);
                let r = self.out.bytes(env, &s);
                self.scratch = s;
                r?;
            }
        }
        self.prev = Some(code);
        Ok(())
    }
}

impl Stage for Lzw<'_> {
    fn put(&mut self, env: &mut Env, data: &[u8]) -> Result<(), Abort> {
        if self.done { return after_eod("LZWDecode", data); }
        for (i, &b) in data.iter().enumerate() {
            self.acc = (self.acc << 8) | b as u32;
            self.nbits += 8;
            while self.nbits >= self.width {
                let code = ((self.acc >> (self.nbits - self.width)) & ((1 << self.width) - 1)) as u16;
                self.nbits -= self.width;
                self.acc &= (1 << self.nbits) - 1;
                self.code(env, code)?;
                // The rest of the byte holding the EOD code is padding; the bytes after it must be whitespace.
                if self.done { return after_eod("LZWDecode", &data[i + 1..]); }
            }
        }
        Ok(())
    }
    fn end(&mut self, env: &mut Env) -> Result<(), Abort> {
        if !self.done { return Err(mal("LZWDecode data ends without its end-of-data code (257)")); }
        self.out.finish(env)
    }
}

/// PNG predictors (10-15): each row is a filter-type byte followed by `row` bytes.
struct Png<'n> { row: usize, bpp: usize, cur: Vec<u8>, prev: Vec<u8>, outrow: Vec<u8>, next: Box<dyn Stage + 'n> }

impl Stage for Png<'_> {
    fn put(&mut self, env: &mut Env, data: &[u8]) -> Result<(), Abort> {
        for &b in data {
            self.cur.push(b);
            if self.cur.len() == self.row + 1 {
                let ft = self.cur[0];
                let mut outrow = std::mem::take(&mut self.outrow);
                outrow.clear();
                outrow.resize(self.row, 0);
                for i in 0..self.row {
                    let a = if i >= self.bpp { outrow[i - self.bpp] } else { 0 };
                    // The row above the first row is all zeros.
                    let up = self.prev.get(i).copied().unwrap_or(0);
                    let c = if i >= self.bpp { self.prev.get(i - self.bpp).copied().unwrap_or(0) } else { 0 };
                    outrow[i] = self.cur[i + 1].wrapping_add(match ft {
                        0 => 0,
                        1 => a,
                        2 => up,
                        3 => ((a as u16 + up as u16) / 2) as u8,
                        4 => {
                            let p = a as i16 + up as i16 - c as i16;
                            let (pa, pb, pc) = ((p - a as i16).abs(), (p - up as i16).abs(), (p - c as i16).abs());
                            if pa <= pb && pa <= pc { a } else if pb <= pc { up } else { c }
                        }
                        _ => return Err(mal(format!("invalid PNG predictor filter type {ft}"))),
                    });
                }
                self.next.put(env, &outrow)?;
                // The decoded row becomes the row above; the old one is reused as the next output buffer.
                self.outrow = std::mem::replace(&mut self.prev, outrow);
                self.cur.clear();
            }
        }
        Ok(())
    }
    fn end(&mut self, env: &mut Env) -> Result<(), Abort> {
        if !self.cur.is_empty() { return Err(mal("predicted data is not a whole number of rows")); }
        self.next.end(env)
    }
}

/// TIFF predictor 2: each sample is stored as the difference from the same component of the previous pixel.
struct Tiff<'n> { row: usize, colors: usize, bpc: usize, cur: Vec<u8>, next: Box<dyn Stage + 'n> }

impl Tiff<'_> {
    fn undo(&self, row: &mut [u8]) {
        match self.bpc {
            8 => for i in self.colors..row.len() { row[i] = row[i].wrapping_add(row[i - self.colors]); },
            16 => {
                let n = row.len() / 2;
                for s in self.colors..n {
                    let a = u16::from_be_bytes([row[2 * (s - self.colors)], row[2 * (s - self.colors) + 1]]);
                    let b = u16::from_be_bytes([row[2 * s], row[2 * s + 1]]).wrapping_add(a);
                    row[2 * s..2 * s + 2].copy_from_slice(&b.to_be_bytes());
                }
            }
            bits => {
                // 1, 2 or 4 bits per sample, MSB first.
                let per = 8 / bits;
                let mask = (1u8 << bits) - 1;
                let get = |row: &[u8], s: usize| (row[s / per] >> (8 - bits * (s % per + 1))) & mask;
                let samples = row.len() * per;
                for s in self.colors..samples {
                    let v = get(row, s).wrapping_add(get(row, s - self.colors)) & mask;
                    let shift = 8 - bits * (s % per + 1);
                    row[s / per] = (row[s / per] & !(mask << shift)) | (v << shift);
                }
            }
        }
    }
}

impl Stage for Tiff<'_> {
    fn put(&mut self, env: &mut Env, data: &[u8]) -> Result<(), Abort> {
        for &b in data {
            self.cur.push(b);
            if self.cur.len() == self.row {
                let mut r = std::mem::take(&mut self.cur);
                self.undo(&mut r);
                self.next.put(env, &r)?;
                r.clear();
                self.cur = r;
            }
        }
        Ok(())
    }
    fn end(&mut self, env: &mut Env) -> Result<(), Abort> {
        if !self.cur.is_empty() { return Err(mal("TIFF-predicted data is not a whole number of rows")); }
        self.next.end(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- reference encoders (test-only)

    fn hex(d: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = d.iter().flat_map(|b| format!("{b:02X}").into_bytes()).collect();
        v.extend_from_slice(b"\n>");
        v
    }

    fn a85(d: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        for c in d.chunks(4) {
            let mut g = [0u8; 4];
            g[..c.len()].copy_from_slice(c);
            let mut v = u32::from_be_bytes(g) as u64;
            if c.len() == 4 && v == 0 { out.push(b'z'); continue; }
            let mut digits = [0u8; 5];
            for i in (0..5).rev() { digits[i] = (v % 85) as u8 + b'!'; v /= 85; }
            out.extend_from_slice(&digits[..c.len() + 1]);
        }
        out.extend_from_slice(b"~>");
        out
    }

    fn rle(d: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        let mut i = 0;
        while i < d.len() {
            let mut run = 1;
            while i + run < d.len() && d[i + run] == d[i] && run < 128 { run += 1; }
            if run >= 2 {
                out.push((257 - run) as u8);
                out.push(d[i]);
                i += run;
            } else {
                let n = (d.len() - i).min(128);
                out.push((n - 1) as u8);
                out.extend_from_slice(&d[i..i + n]);
                i += n;
            }
        }
        out.push(128);
        out
    }

    /// MSB-first LZW; widths follow the decoder's table, which lags the encoder's by one entry.
    fn lzw(d: &[u8], early: u32) -> Vec<u8> {
        use std::collections::HashMap;
        struct W { acc: u64, n: u32, out: Vec<u8> }
        impl W {
            fn put(&mut self, code: u32, width: u32) {
                self.acc = (self.acc << width) | code as u64;
                self.n += width;
                while self.n >= 8 { self.out.push((self.acc >> (self.n - 8)) as u8); self.n -= 8; }
            }
        }
        let width = |dec: u32| { let mut w = 9; while w < 12 && dec + early >= 1 << w { w += 1; } w };
        let mut w = W { acc: 0, n: 0, out: vec![] };
        let mut table: HashMap<Vec<u8>, u32> = HashMap::new();
        let mut next = 258u32;
        let mut dec = 258u32; // decoder table size when it reads the next code
        let mut first = true;
        w.put(256, 9);
        let mut cur: Vec<u8> = vec![];
        for &b in d {
            let mut ext = cur.clone();
            ext.push(b);
            if ext.len() == 1 || table.contains_key(&ext) {
                cur = ext;
                continue;
            }
            let code = if cur.len() == 1 { cur[0] as u32 } else { table[&cur] };
            w.put(code, width(dec));
            if first { first = false } else { dec += 1 }
            table.insert(ext, next);
            next += 1;
            if next >= 4094 {
                w.put(256, width(dec));
                table.clear();
                next = 258;
                dec = 258;
                first = true;
            }
            cur = vec![b];
        }
        if !cur.is_empty() {
            let code = if cur.len() == 1 { cur[0] as u32 } else { table[&cur] };
            w.put(code, width(dec));
            if !first { dec += 1 }
        }
        w.put(257, width(dec));
        if w.n > 0 { let pad = 8 - w.n; w.put(0, pad); }
        w.out
    }

    fn sample(n: usize) -> Vec<u8> {
        // Deterministic mix of runs, text and noise.
        let mut x: u32 = 12345;
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            match (x >> 16) % 4 {
                0 => v.extend(std::iter::repeat((x >> 8) as u8).take(((x >> 3) % 300) as usize)),
                1 => v.extend_from_slice(b"BT /F1 12 Tf 72 720 Td (hello world) Tj ET\n"),
                _ => v.push((x >> 24) as u8),
            }
        }
        v.truncate(n);
        v
    }

    // ---- harness

    fn run(stages: Vec<StageKind>, raw: &[u8], chunk: usize, max: u64) -> Result<Vec<u8>, Abort> {
        let mut ctx = Ctx::new(60_000, None);
        let mut budget = Budget { used: 0, max };
        let mut got = Vec::new();
        {
            let mut env = Env { ctx: &mut ctx, budget: &mut budget };
            let mut pipe = build(stages, Box::new(Collect(&mut got)));
            for c in raw.chunks(chunk.max(1)) { pipe.put(&mut env, c)?; }
            pipe.end(&mut env)?;
        }
        Ok(got)
    }

    fn roundtrip(name: &str, mk: impl Fn() -> Vec<StageKind>, raw: &[u8], want: &[u8]) {
        for chunk in [1, 2, 3, 7, 64, 4093, raw.len().max(1)] {
            let got = run(mk(), raw, chunk, u64::MAX).unwrap_or_else(|e| panic!("{name} chunk {chunk}: {e:?}"));
            assert!(got == want, "{name} chunk {chunk}: {} bytes vs {}", got.len(), want.len());
        }
    }

    fn malformed(stages: Vec<StageKind>, raw: &[u8]) -> bool {
        matches!(run(stages, raw, 5, u64::MAX), Err(Abort::Malformed(_)))
    }

    #[test]
    fn each_decoder_round_trips_at_any_chunking() {
        for n in [0usize, 1, 2, 3, 4, 5, 255, 1000, 20_000] {
            let d = sample(n);
            roundtrip("hex", || vec![StageKind::Hex], &hex(&d), &d);
            roundtrip("a85", || vec![StageKind::A85], &a85(&d), &d);
            roundtrip("rle", || vec![StageKind::RunLength], &rle(&d), &d);
            roundtrip("lzw1", || vec![StageKind::Lzw { early: true }], &lzw(&d, 1), &d);
            roundtrip("lzw0", || vec![StageKind::Lzw { early: false }], &lzw(&d, 0), &d);
        }
    }

    #[test]
    fn lzw_survives_width_changes_and_table_resets() {
        // Enough distinct strings to fill the table (Clear) several times.
        let mut d = vec![];
        let mut x: u32 = 7;
        for _ in 0..200_000 { x = x.wrapping_mul(1664525).wrapping_add(1013904223); d.push((x >> 24) as u8 & 0x3f); }
        for early in [0, 1] {
            let enc = lzw(&d, early);
            let got = run(vec![StageKind::Lzw { early: early == 1 }], &enc, 1000, u64::MAX).unwrap();
            assert!(got == d, "early {early}");
        }
        // The wrong EarlyChange misreads codes: never silently the same output.
        let wrong = run(vec![StageKind::Lzw { early: false }], &lzw(&d, 1), 1000, u64::MAX);
        assert!(wrong.map_or(true, |g| g != d));
    }

    #[test]
    fn lzw_kwkwk_and_literal_streams() {
        for d in [&b"aaaaaaaaaaaaaaaaaaaa"[..], b"abababababababab", b"a", b""] {
            roundtrip("lzw", || vec![StageKind::Lzw { early: true }], &lzw(d, 1), d);
        }
    }

    #[test]
    fn chains_decode_in_order() {
        let d = sample(5000);
        // Encoders apply in reverse: the first filter in /Filter decodes first.
        let raw = hex(&lzw(&rle(&a85(&d)), 1));
        roundtrip("hex>lzw>rle>a85", || vec![StageKind::Hex, StageKind::Lzw { early: true }, StageKind::RunLength, StageKind::A85],
                  &raw, &d);
        let z = miniz_oxide::deflate::compress_to_vec_zlib(&d, 6);
        roundtrip("a85>flate", || vec![StageKind::A85, StageKind::Flate], &a85(&z), &d);
        roundtrip("flate>a85", || vec![StageKind::Flate, StageKind::A85],
                  &miniz_oxide::deflate::compress_to_vec_zlib(&a85(&d), 6), &d);
        roundtrip("identity", || vec![StageKind::Identity, StageKind::Hex], &hex(&d), &d);
    }

    #[test]
    fn predictors_after_lzw() {
        let (cols, colors) = (5usize, 3usize);
        let row = cols * colors;
        let rows: Vec<Vec<u8>> = (0..9).map(|r| (0..row).map(|i| (r * 31 + i * 7) as u8).collect()).collect();
        let want: Vec<u8> = rows.concat();
        // PNG: Sub, Up, Average, Paeth, None, cycled per row.
        let mut png = vec![];
        let mut prev = vec![0u8; row];
        for (r, cur) in rows.iter().enumerate() {
            let ft = [1u8, 2, 3, 4, 0][r % 5];
            png.push(ft);
            for i in 0..row {
                let a = if i >= colors { cur[i - colors] } else { 0 };
                let b = prev[i];
                let c = if i >= colors { prev[i - colors] } else { 0 };
                let p = match ft {
                    0 => 0, 1 => a, 2 => b, 3 => ((a as u16 + b as u16) / 2) as u8,
                    _ => {
                        let p = a as i16 + b as i16 - c as i16;
                        let (pa, pb, pc) = ((p - a as i16).abs(), (p - b as i16).abs(), (p - c as i16).abs());
                        if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c }
                    }
                };
                png.push(cur[i].wrapping_sub(p));
            }
            prev = cur.clone();
        }
        roundtrip("lzw+png", || vec![StageKind::Lzw { early: true }, StageKind::Png { row, bpp: colors }], &lzw(&png, 1), &want);
        // TIFF 2, 8 bpc.
        let tiff: Vec<u8> = rows.iter().flat_map(|cur| (0..row).map(|i| if i >= colors { cur[i].wrapping_sub(cur[i - colors]) } else { cur[i] })
            .collect::<Vec<_>>()).collect();
        roundtrip("lzw+tiff8", || vec![StageKind::Lzw { early: false }, StageKind::Tiff { cols, colors, bpc: 8 }],
                  &lzw(&tiff, 0), &want);
        // TIFF 2, 4 bpc, 1 color: samples 0,1,2,...15 per row encode as 0,1,1,...1.
        let want4: Vec<u8> = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let enc4: Vec<u8> = vec![0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
        roundtrip("tiff4", || vec![StageKind::Tiff { cols: 16, colors: 1, bpc: 4 }], &enc4, &want4);
        // TIFF 2, 16 bpc.
        let enc16 = [0x01, 0x00, 0x00, 0x01, 0xff, 0xff];
        roundtrip("tiff16", || vec![StageKind::Tiff { cols: 3, colors: 1, bpc: 16 }], &enc16, &[0x01, 0x00, 0x01, 0x01, 0x01, 0x00]);
        // Partial rows and bad PNG filter types are malformed.
        assert!(malformed(vec![StageKind::Png { row: 3, bpp: 1 }], &[0, 1, 2]));
        assert!(malformed(vec![StageKind::Png { row: 3, bpp: 1 }], &[5, 1, 2, 3]));
    }

    #[test]
    fn truncated_or_invalid_encodings_are_malformed() {
        assert!(malformed(vec![StageKind::Hex], b"414243"));
        assert!(malformed(vec![StageKind::Hex], b"41 4G>"));
        assert!(malformed(vec![StageKind::A85], b"9jqo^"));
        assert!(malformed(vec![StageKind::A85], b"9jqo^BlbD-v~>")); // 1-char final group (corpus fixture)
        assert!(malformed(vec![StageKind::A85], b"9jz~>"));
        assert!(malformed(vec![StageKind::A85], b"uuuuu~>")); // > 2^32-1
        assert!(malformed(vec![StageKind::A85], b"9jqo~x"));
        assert!(malformed(vec![StageKind::A85], b"9jqo{~>"));
        assert!(malformed(vec![StageKind::RunLength], &[2, b'a', b'b', b'c']));
        assert!(malformed(vec![StageKind::RunLength], &[0x81]));
        let enc = lzw(b"hello hello hello", 1);
        assert!(malformed(vec![StageKind::Lzw { early: true }], &enc[..enc.len() - 2]));
        // 9-bit codes: Clear, then 300 (beyond the table) as the first code.
        let bad = [0x80, 0x4b, 0x00, 0x00];
        assert!(malformed(vec![StageKind::Lzw { early: true }], &bad));
        assert_eq!(run(vec![StageKind::Hex], b"414>", 1, u64::MAX).unwrap(), b"A@"); // odd final digit
    }

    /// Spec 0.1.5 (ADR 0008): only PDF whitespace may follow an end-of-data marker, at any chunking.
    #[test]
    fn only_whitespace_may_follow_end_of_data() {
        let d = b"BT /F1 12 Tf (visible) Tj ET\n".repeat(20);
        let cases: Vec<(&str, fn() -> Vec<StageKind>, Vec<u8>)> = vec![
            ("hex", || vec![StageKind::Hex], hex(&d)),
            ("a85", || vec![StageKind::A85], a85(&d)),
            ("rle", || vec![StageKind::RunLength], rle(&d)),
            ("lzw1", || vec![StageKind::Lzw { early: true }], lzw(&d, 1)),
            ("lzw0", || vec![StageKind::Lzw { early: false }], lzw(&d, 0)),
            ("flate", || vec![StageKind::Flate], miniz_oxide::deflate::compress_to_vec_zlib(&d, 6)),
        ];
        for (name, mk, enc) in cases {
            // Whitespace (all six PDF whitespace bytes) after EOD is allowed.
            let ws = [enc.clone(), b"\0\t\n\x0c\r ".to_vec()].concat();
            roundtrip(name, mk, &ws, &d);
            // Anything else after EOD is malformed, whether it arrives in the same chunk or a later one.
            for tail in [&b"x"[..], b"\n\n%", b"\x80", b" BT 3 Tr (hidden) Tj ET"] {
                let bad = [enc.clone(), tail.to_vec()].concat();
                for chunk in [1, 3, 64, bad.len()] {
                    assert!(matches!(run(mk(), &bad, chunk, u64::MAX), Err(Abort::Malformed(_))),
                            "{name} tail {tail:?} chunk {chunk}");
                }
            }
        }
        // An early RunLength EOD with content after it (the qpdf differential).
        let early = [vec![0x80], rle(&d)].concat();
        assert!(matches!(run(vec![StageKind::RunLength], &early, 7, u64::MAX), Err(Abort::Malformed(_))));
        // In a chain, the check applies to each stage's own input: hex's '>' is followed by junk here.
        let z = miniz_oxide::deflate::compress_to_vec_zlib(&d, 6);
        let chained = [hex(&z), b"junk".to_vec()].concat();
        assert!(matches!(run(vec![StageKind::Hex, StageKind::Flate], &chained, 5, u64::MAX), Err(Abort::Malformed(_))));
        let inner = hex(&[z.clone(), b"QQ".to_vec()].concat()); // Flate's input continues after the zlib end
        assert!(matches!(run(vec![StageKind::Hex, StageKind::Flate], &inner, 5, u64::MAX), Err(Abort::Malformed(_))));
    }

    #[test]
    fn every_decoded_byte_counts_against_the_budget() {
        let bomb: Vec<u8> = [&[0x81u8, 0x00][..]].iter().cycle().take(1 << 16).flat_map(|s| s.iter().copied())
            .chain([0x80]).collect(); // 8 MiB of zeros
        assert_eq!(run(vec![StageKind::RunLength], &bomb, 4096, 9 << 20).unwrap().len(), 8 << 20);
        assert!(matches!(run(vec![StageKind::RunLength], &bomb, 4096, 1 << 20), Err(Abort::Decompressed(_))));
        // Chains count every stage: the hex stage's output (128 KiB + 1) plus RunLength's (8 MiB).
        let chained = hex(&bomb);
        let total = (8u64 << 20) + bomb.len() as u64;
        assert!(matches!(run(vec![StageKind::Hex, StageKind::RunLength], &chained, 4096, total - 1), Err(Abort::Decompressed(_))));
        assert!(run(vec![StageKind::Hex, StageKind::RunLength], &chained, 4096, total).is_ok());
    }
}
