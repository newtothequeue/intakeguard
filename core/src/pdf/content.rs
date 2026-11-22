//! Hidden-text heuristic over a decoded content stream. Best effort only: it flags text render
//! modes that draw nothing (3 = invisible, 7 = clip only). Not a prompt-injection guarantee.
//!
//! Streaming: `HiddenScan::feed` takes decoded bytes chunk by chunk, with state carried across chunk
//! boundaries, so every byte of every content stream is scanned in constant memory (no size cap).

use super::syntax::{is_delim, is_ws};

const MAX_FINDINGS: usize = 5;
const MAX_TOKEN: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum St { Normal, Comment, Literal, LtSeen, Hex, Name, Token, InlineImage }

pub struct HiddenScan {
    st: St,
    pos: usize,
    depth: usize,
    esc: bool,
    tok: Vec<u8>,
    tok_start: usize,
    tok_long: bool,
    last_num: Option<f64>,
    /// Inline image data: 0 = in data, 1 = whitespace seen, 2 = whitespace + 'E' seen.
    ei: u8,
    out: Vec<String>,
}

impl Default for HiddenScan {
    fn default() -> Self { Self::new() }
}

impl HiddenScan {
    pub fn new() -> Self {
        HiddenScan { st: St::Normal, pos: 0, depth: 0, esc: false, tok: Vec::with_capacity(MAX_TOKEN),
                     tok_start: 0, tok_long: false, last_num: None, ei: 0, out: Vec::new() }
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            if self.out.len() >= MAX_FINDINGS { return; }
            self.byte(b);
            self.pos += 1;
        }
    }

    pub fn finish(mut self) -> Vec<String> {
        if self.st == St::Token { self.end_token(); }
        self.out
    }

    fn byte(&mut self, b: u8) {
        match self.st {
            St::Comment => { if b == b'\n' || b == b'\r' { self.st = St::Normal; } }
            St::Literal => {
                if self.esc { self.esc = false; }
                else if b == b'\\' { self.esc = true; }
                else if b == b'(' { self.depth += 1; }
                else if b == b')' { self.depth -= 1; if self.depth == 0 { self.st = St::Normal; } }
            }
            St::LtSeen => {
                if b == b'<' { self.st = St::Normal; } // dictionary start
                else { self.st = St::Hex; self.byte(b); }
            }
            St::Hex => { if b == b'>' { self.st = St::Normal; } }
            St::Name => {
                if is_ws(b) || is_delim(b) { self.st = St::Normal; self.byte(b); }
            }
            St::Token => {
                if is_ws(b) || is_delim(b) {
                    // end_token leaves Normal, or InlineImage after "ID"; either way this byte belongs
                    // to the new state (for InlineImage it may be the whitespace before "EI").
                    self.end_token();
                    self.byte(b);
                } else if self.tok.len() < MAX_TOKEN { self.tok.push(b); } else { self.tok_long = true; }
            }
            St::InlineImage => {
                self.ei = match (self.ei, b) {
                    (2, b'I') => { self.st = St::Normal; self.last_num = None; 0 }
                    (1, b'E') => 2,
                    (_, c) if is_ws(c) => 1,
                    _ => 0,
                };
            }
            St::Normal => {
                if is_ws(b) { return; }
                match b {
                    b'%' => self.st = St::Comment,
                    b'(' => { self.st = St::Literal; self.depth = 1; self.esc = false; self.last_num = None; }
                    b'<' => { self.st = St::LtSeen; self.last_num = None; }
                    b'>' | b'[' | b']' | b'{' | b'}' | b')' => self.last_num = None,
                    b'/' => { self.st = St::Name; self.last_num = None; }
                    _ => {
                        self.st = St::Token;
                        self.tok.clear();
                        self.tok.push(b);
                        self.tok_long = false;
                        self.tok_start = self.pos;
                    }
                }
            }
        }
    }

    fn end_token(&mut self) {
        self.st = St::Normal;
        if self.tok_long { self.last_num = None; return; }
        if let Some(n) = std::str::from_utf8(&self.tok).ok().and_then(|t| t.parse::<f64>().ok()) {
            self.last_num = Some(n);
            return;
        }
        match self.tok.as_slice() {
            b"Tr" => {
                if let Some(m) = self.last_num {
                    if m == 3.0 || m == 7.0 {
                        self.out.push(format!("text render mode {m} (draws no visible glyphs) at content byte {}", self.tok_start));
                    }
                }
            }
            // Inline image data: skip to whitespace + "EI".
            b"ID" => { self.st = St::InlineImage; self.ei = 0; }
            _ => {}
        }
        self.last_num = None;
    }
}

/// Whole-buffer convenience wrapper (tests).
#[cfg(test)]
fn hidden_text(c: &[u8]) -> Vec<String> {
    let mut s = HiddenScan::new();
    s.feed(c);
    s.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_render_mode_3_and_7() {
        assert_eq!(hidden_text(b"BT 3 Tr (x) Tj ET").len(), 1);
        assert_eq!(hidden_text(b"BT 7 Tr (x) Tj ET").len(), 1);
        assert!(hidden_text(b"BT 0 Tr (3 Tr) Tj ET").is_empty());
        assert!(hidden_text(b"BT /F1 3 Tf 1 Tr ET").is_empty());
        assert!(hidden_text(b"BI /W 1 ID \x033 Tr EI 0 Tr").is_empty());
        assert!(hidden_text(b"<< /x 3 >> Tr").is_empty());
        assert_eq!(hidden_text(b"BI /W 0 ID EI 3 Tr").len(), 1); // empty inline image data
    }

    #[test]
    fn chunking_never_changes_the_result() {
        let c = b"q BT /F1 9 Tf (a\\) (b) 3 Tr) Tj ET % 3 Tr\n BI /W 2 ID \x00\x01 EI BT 3 Tr ET <4142> 7 Tr";
        let whole = hidden_text(c);
        assert_eq!(whole.len(), 2);
        for size in 1..c.len() {
            let mut s = HiddenScan::new();
            for part in c.chunks(size) { s.feed(part); }
            assert_eq!(s.finish(), whole, "chunk size {size}");
        }
    }
}
