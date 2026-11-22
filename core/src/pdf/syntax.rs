//! PDF object syntax (ISO 32000-1 §7.2–7.3). Strict, bounded, no recursion beyond MAX_DEPTH.

use crate::report::Abort;

pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone)]
pub struct Name {
    pub val: Vec<u8>,
    /// The token contained `#xx` escapes.
    pub escaped: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Obj {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Str(Vec<u8>),
    Name(Name),
    Array(Vec<Obj>),
    Dict(Vec<(Name, Obj)>),
    Ref(u32, u16),
}

impl Obj {
    pub fn dict(&self) -> Option<&[(Name, Obj)]> {
        if let Obj::Dict(d) = self { Some(d) } else { None }
    }
    pub fn get(&self, k: &[u8]) -> Option<&Obj> {
        self.dict()?.iter().rev().find(|(n, _)| n.val == k).map(|(_, v)| v)
    }
    pub fn name(&self) -> Option<&[u8]> {
        if let Obj::Name(n) = self { Some(&n.val) } else { None }
    }
    pub fn int(&self) -> Option<i64> {
        if let Obj::Int(i) = self { Some(*i) } else { None }
    }
}

pub fn is_ws(b: u8) -> bool { matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\0') }
pub fn is_delim(b: u8) -> bool { matches!(b, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%') }
fn is_regular(b: u8) -> bool { !is_ws(b) && !is_delim(b) }

pub struct Lexer<'a> {
    pub d: &'a [u8],
    pub p: usize,
}

fn mal(s: impl Into<String>) -> Abort { Abort::Malformed(s.into()) }

impl<'a> Lexer<'a> {
    pub fn new(d: &'a [u8], p: usize) -> Self { Lexer { d, p } }

    pub fn skip_ws(&mut self) {
        while self.p < self.d.len() {
            let b = self.d[self.p];
            if is_ws(b) {
                self.p += 1;
            } else if b == b'%' {
                while self.p < self.d.len() && self.d[self.p] != b'\n' && self.d[self.p] != b'\r' { self.p += 1; }
            } else {
                break;
            }
        }
    }

    /// Next regular-character token (keyword or number), without consuming it.
    pub fn peek_word(&mut self) -> &'a [u8] {
        self.skip_ws();
        let s = self.p;
        let mut e = s;
        while e < self.d.len() && is_regular(self.d[e]) { e += 1; }
        &self.d[s..e]
    }

    pub fn word(&mut self) -> &'a [u8] {
        let w = self.peek_word();
        self.p += w.len();
        w
    }

    pub fn expect(&mut self, kw: &[u8]) -> Result<(), Abort> {
        let at = self.p;
        if self.word() == kw { Ok(()) } else { Err(mal(format!("expected '{}' at byte {at}", String::from_utf8_lossy(kw)))) }
    }

    pub fn uint(&mut self) -> Option<u64> {
        let save = self.p;
        let w = self.word();
        if !w.is_empty() && w.len() <= 19 && w.iter().all(u8::is_ascii_digit) {
            std::str::from_utf8(w).ok()?.parse().ok()
        } else {
            self.p = save;
            None
        }
    }

    pub fn object(&mut self, depth: usize) -> Result<Obj, Abort> {
        if depth > MAX_DEPTH { return Err(Abort::Unsupported(format!("PDF objects nested deeper than {MAX_DEPTH}"))); }
        self.skip_ws();
        let Some(&b) = self.d.get(self.p) else { return Err(Abort::Truncated("PDF ends inside an object".into())) };
        match b {
            b'/' => Ok(Obj::Name(self.name()?)),
            b'(' => Ok(Obj::Str(self.literal()?)),
            b'<' if self.d.get(self.p + 1) == Some(&b'<') => {
                self.p += 2;
                let mut v = Vec::new();
                loop {
                    self.skip_ws();
                    match self.d.get(self.p) {
                        None => return Err(Abort::Truncated("PDF ends inside a dictionary".into())),
                        Some(b'>') if self.d.get(self.p + 1) == Some(&b'>') => { self.p += 2; break; }
                        Some(b'/') => {
                            let k = self.name()?;
                            let val = self.object(depth + 1)?;
                            v.push((k, val));
                        }
                        Some(_) => return Err(mal(format!("dictionary key is not a name at byte {}", self.p))),
                    }
                }
                Ok(Obj::Dict(v))
            }
            b'<' => Ok(Obj::Str(self.hexstr()?)),
            b'[' => {
                self.p += 1;
                let mut v = Vec::new();
                loop {
                    self.skip_ws();
                    match self.d.get(self.p) {
                        None => return Err(Abort::Truncated("PDF ends inside an array".into())),
                        Some(b']') => { self.p += 1; break; }
                        Some(_) => v.push(self.object(depth + 1)?),
                    }
                }
                Ok(Obj::Array(v))
            }
            _ => {
                let at = self.p;
                let w = self.word();
                match w {
                    b"" => Err(mal(format!("unexpected byte 0x{b:02x} at {at}"))),
                    b"true" => Ok(Obj::Bool(true)),
                    b"false" => Ok(Obj::Bool(false)),
                    b"null" => Ok(Obj::Null),
                    _ if w.iter().all(u8::is_ascii_digit) && w.len() <= 10 => {
                        // Possibly "num gen R".
                        let save = self.p;
                        if let Some(g) = self.uint() {
                            if self.word() == b"R" && g <= 65535 {
                                let n: u64 = std::str::from_utf8(w).unwrap().parse().unwrap();
                                if n <= u32::MAX as u64 { return Ok(Obj::Ref(n as u32, g as u16)); }
                            }
                        }
                        self.p = save;
                        Ok(Obj::Int(std::str::from_utf8(w).unwrap().parse().unwrap()))
                    }
                    _ => number(w).ok_or_else(|| mal(format!("unexpected token '{}' at byte {at}",
                                                              String::from_utf8_lossy(&w[..w.len().min(32)])))),
                }
            }
        }
    }

    fn name(&mut self) -> Result<Name, Abort> {
        self.p += 1; // '/'
        let mut val = Vec::new();
        let mut escaped = false;
        while self.p < self.d.len() && is_regular(self.d[self.p]) {
            let b = self.d[self.p];
            if b == b'#' {
                let h = self.d.get(self.p + 1..self.p + 3).ok_or_else(|| mal("truncated #xx escape in name"))?;
                let v = std::str::from_utf8(h).ok().and_then(|s| u8::from_str_radix(s, 16).ok())
                    .ok_or_else(|| mal("invalid #xx escape in name"))?;
                val.push(v);
                escaped = true;
                self.p += 3;
            } else {
                val.push(b);
                self.p += 1;
            }
            if val.len() > 4096 { return Err(mal("name token longer than 4096 bytes")); }
        }
        Ok(Name { val, escaped })
    }

    fn literal(&mut self) -> Result<Vec<u8>, Abort> {
        self.p += 1;
        let mut depth = 1usize;
        let mut out = Vec::new();
        while self.p < self.d.len() {
            let b = self.d[self.p];
            self.p += 1;
            match b {
                b'\\' => {
                    let Some(&e) = self.d.get(self.p) else { break };
                    self.p += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'0'..=b'7' => {
                            let mut v = (e - b'0') as u32;
                            for _ in 0..2 {
                                match self.d.get(self.p) {
                                    Some(&c @ b'0'..=b'7') => { v = v * 8 + (c - b'0') as u32; self.p += 1; }
                                    _ => break,
                                }
                            }
                            out.push(v as u8);
                        }
                        b'\r' => { if self.d.get(self.p) == Some(&b'\n') { self.p += 1; } }
                        b'\n' => {}
                        _ => out.push(e),
                    }
                }
                b'(' => { depth += 1; out.push(b); }
                b')' => {
                    depth -= 1;
                    if depth == 0 { return Ok(out); }
                    out.push(b);
                }
                _ => out.push(b),
            }
        }
        Err(Abort::Truncated("PDF ends inside a literal string".into()))
    }

    fn hexstr(&mut self) -> Result<Vec<u8>, Abort> {
        self.p += 1;
        let mut out = Vec::new();
        let mut hi: Option<u8> = None;
        while self.p < self.d.len() {
            let b = self.d[self.p];
            self.p += 1;
            if b == b'>' {
                if let Some(h) = hi { out.push(h << 4); }
                return Ok(out);
            }
            if is_ws(b) { continue; }
            let v = (b as char).to_digit(16).ok_or_else(|| mal("invalid character in hex string"))? as u8;
            match hi.take() { Some(h) => out.push(h << 4 | v), None => hi = Some(v) }
        }
        Err(Abort::Truncated("PDF ends inside a hex string".into()))
    }
}

fn number(w: &[u8]) -> Option<Obj> {
    let s = std::str::from_utf8(w).ok()?;
    if !s.bytes().all(|c| c.is_ascii_digit() || matches!(c, b'+' | b'-' | b'.')) { return None; }
    if let Ok(i) = s.parse::<i64>() { return Some(Obj::Int(i)); }
    let f: f64 = s.parse().ok().or_else(|| if s.ends_with('.') { s[..s.len() - 1].parse().ok() } else { None })?;
    f.is_finite().then_some(Obj::Real(f))
}

/// Stream /Length, which may be an indirect reference that the caller resolves.
pub enum StreamLen { Direct(usize), Ref(u32) }

#[allow(dead_code)]
pub struct Indirect {
    pub num: u32,
    pub gen: u16,
    pub obj: Obj,
    /// (start of data, length source)
    pub stream: Option<(usize, StreamLen)>,
    /// Lexer position just after the object (or after the `stream` EOL for streams).
    pub end: usize,
}

/// Parse `num gen obj <object> [stream...]` at `at`. For streams, the caller must call
/// `finish_stream` once the length is known.
pub fn indirect(d: &[u8], at: usize) -> Result<Indirect, Abort> {
    let mut lx = Lexer::new(d, at);
    let num = lx.uint().ok_or_else(|| mal(format!("no object number at byte {at}")))?;
    let gen = lx.uint().ok_or_else(|| mal(format!("no generation number at byte {at}")))?;
    if num > u32::MAX as u64 || gen > 65535 { return Err(mal("object number out of range")); }
    lx.expect(b"obj")?;
    let obj = lx.object(0)?;
    let save = lx.p;
    if lx.peek_word() == b"stream" {
        lx.word();
        // EOL after `stream` is CRLF or LF (§7.3.8.1).
        match (d.get(lx.p), d.get(lx.p + 1)) {
            (Some(b'\r'), Some(b'\n')) => lx.p += 2,
            (Some(b'\n'), _) => lx.p += 1,
            (Some(b'\r'), _) => lx.p += 1, // tolerated by most readers; still bounded by /Length
            (None, _) => return Err(Abort::Truncated("PDF ends after 'stream'".into())),
            _ => return Err(mal("'stream' keyword not followed by EOL")),
        }
        let len = match obj.get(b"Length") {
            Some(Obj::Int(n)) if *n >= 0 => StreamLen::Direct(*n as usize),
            Some(Obj::Ref(n, _)) => StreamLen::Ref(*n),
            _ => return Err(mal(format!("stream object {num} has no valid /Length"))),
        };
        return Ok(Indirect { num: num as u32, gen: gen as u16, obj, stream: Some((lx.p, len)), end: lx.p });
    }
    lx.p = save;
    lx.expect(b"endobj").map_err(|_| {
        if lx.p >= d.len() { Abort::Truncated(format!("object {num} is unterminated")) }
        else { mal(format!("object {num} is not terminated by endobj")) }
    })?;
    Ok(Indirect { num: num as u32, gen: gen as u16, obj, stream: None, end: lx.p })
}

/// Validate `endstream endobj` after `len` bytes of stream data.
/// Returns (data start, data end, offset just past `endobj`).
pub fn finish_stream_end(d: &[u8], start: usize, len: usize, num: u32) -> Result<(usize, usize, usize), Abort> {
    let end = start.checked_add(len).ok_or_else(|| mal("stream length overflow"))?;
    if end > d.len() { return Err(Abort::Truncated(format!("stream {num} runs past end of file"))); }
    let mut lx = Lexer::new(d, end);
    lx.skip_ws();
    if lx.word() != b"endstream" {
        return Err(mal(format!("stream {num}: /Length does not end at 'endstream'")));
    }
    lx.expect(b"endobj").map_err(|_| mal(format!("stream object {num} not terminated by endobj")))?;
    Ok((start, end, lx.p))
}

/// Offsets of every `N G obj` header in `d` (a raw byte scan, independent of any xref).
pub fn obj_headers(d: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 <= d.len() {
        if &d[i..i + 3] == b"obj" && d.get(i + 3).map_or(true, |&c| is_ws(c) || is_delim(c)) {
            // walk back: ws, digits (gen), ws, digits (num), then ws/start
            let mut j = i;
            let back_ws = |j: &mut usize| { let s = *j; while *j > 0 && is_ws(d[*j - 1]) { *j -= 1; } s != *j };
            let back_dg = |j: &mut usize| { let s = *j; while *j > 0 && d[*j - 1].is_ascii_digit() { *j -= 1; } s != *j };
            if back_ws(&mut j) && back_dg(&mut j) && back_ws(&mut j) && back_dg(&mut j)
                && (j == 0 || is_ws(d[j - 1]) || is_delim(d[j - 1])) {
                out.push(j);
            }
        }
        i += 1;
    }
    out
}
