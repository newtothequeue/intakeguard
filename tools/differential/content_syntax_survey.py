#!/usr/bin/env python3
"""Content-stream string-syntax survey (ADR 0009 false-positive measurement; verification role).

Scans every page (and form XObject) content stream of the PDFs under the given paths with an independent strict
lexer, and reports how many files contain each error spec 0.1.6 rejects:
  R1 non-hex byte in a hex string   R2 unclosed hex string   R3 unclosed literal string
Inline image data (ID..EI) is skipped. Local only; nothing leaves the machine.

    python tools/differential/content_syntax_survey.py ~/Downloads ~/Documents
"""
from __future__ import annotations
import argparse, collections, os, sys
from pathlib import Path
import pikepdf
SPEC = pikepdf.StreamDecodeLevel.specialized
SPEC=pikepdf.StreamDecodeLevel.specialized
WS=b" \t\r\n\x0c\x00"; HEX=set(b"0123456789abcdefABCDEF")|set(WS)
def lex_issues(c):
    """Strict lexical scan of one page's concatenated content. Returns set of issue kinds."""
    issues=set(); i=0; n=len(c)
    while i<n:
        b=c[i]
        if b==0x25:                                  # comment
            while i<n and c[i] not in (10,13): i+=1
            continue
        if b==0x28:                                  # literal string, nested, escapes
            depth=1; i+=1
            while i<n and depth:
                if c[i]==0x5c: i+=2; continue
                depth+= c[i]==0x28; depth-= c[i]==0x29; i+=1
            if depth: issues.add("R3 unterminated literal string")
            continue
        if b==0x3c:
            if i+1<n and c[i+1]==0x3c: i+=2; continue  # dict open
            j=c.find(b">",i+1)
            body=c[i+1: j if j!=-1 else n]
            if j==-1: issues.add("R2 unterminated hex string")
            if any(x not in HEX for x in body): issues.add("R1 non-hex char in hex string")
            i= (j+1) if j!=-1 else n; continue
        # inline image: BI ... ID <data> EI
        if c[i:i+2]==b"ID" and (i==0 or c[i-1] in WS) and i+2<n and c[i+2] in WS:
            k=i+3
            while True:
                e=c.find(b"EI",k)
                if e==-1: i=n; break
                if c[e-1] in WS and (e+2==n or c[e+2] in WS): i=e+2; break
                k=e+2
            continue
        i+=1
    return issues


def streams(pdf):
    for pg in pdf.pages:
        cs = pg.obj.get("/Contents")
        if cs is not None:
            parts = [cs] if isinstance(cs, pikepdf.Stream) else list(cs)
            yield "page", b"\n".join(x.read_bytes(decode_level=SPEC) for x in parts)
    for obj in pdf.objects:
        if isinstance(obj, pikepdf.Stream) and obj.get("/Subtype") == "/Form":
            yield "form", obj.read_bytes(decode_level=SPEC)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    files = []
    for p in args.paths:
        p = Path(p).expanduser()
        files += [p] if p.is_file() else [q for q in p.rglob("*") if q.suffix.lower() == ".pdf" and q.is_file()]
    counts, hits, opened = collections.Counter(), collections.defaultdict(list), 0
    for f in files:
        try:
            with pikepdf.open(f) as pdf:
                opened += 1
                found = set()
                for _, data in streams(pdf):
                    found |= lex_issues(data)
        except Exception:  # noqa: BLE001 - unreadable/encrypted: out of scope for this survey
            continue
        for k in found:
            counts[k] += 1
            hits[k].append(str(f))
    print(f"{opened} PDFs scanned")
    for k in sorted(counts):
        print(f"  {k}: {counts[k]} files")
        for h in hits[k][:10]:
            print(f"     {h}")
    if not counts:
        print("  none: spec 0.1.6 would reject none of these files for string syntax")
    return 0


if __name__ == "__main__":
    sys.exit(main())
