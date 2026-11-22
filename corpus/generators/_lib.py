"""Deterministic, stdlib-only builders for corpus fixtures.

Rules: no timestamps, no unseeded randomness, no network, no real malware.
Every generator module exposes `generate() -> dict[str, bytes]` mapping fixture id -> bytes.
"""

from __future__ import annotations

import random
import re
import struct
import zlib

# ---------------------------------------------------------------- PNG

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def png_chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)


def png_rgb(width: int, height: int, pixel=(200, 60, 60), *, seed: int | None = None,
            extra_chunks: list[tuple[bytes, bytes]] | None = None) -> bytes:
    """Valid 8-bit RGB PNG. With seed, pixels are pseudo-random (incompressible)."""
    rng = random.Random(seed) if seed is not None else None
    raw = bytearray()
    for _ in range(height):
        raw.append(0)  # filter type none
        if rng:
            raw += rng.randbytes(width * 3)
        else:
            raw += bytes(pixel) * width
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    out = PNG_SIG + png_chunk(b"IHDR", ihdr)
    for ctype, data in extra_chunks or []:
        out += png_chunk(ctype, data)
    out += png_chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + png_chunk(b"IEND", b"")
    return out


def png_declared_dims(width: int, height: int) -> bytes:
    """PNG whose IHDR declares huge dimensions but carries a tiny IDAT (image bomb probe)."""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    tiny = zlib.compress(b"\x00" * 64, 9)
    return PNG_SIG + png_chunk(b"IHDR", ihdr) + png_chunk(b"IDAT", tiny) + png_chunk(b"IEND", b"")


def zlib_fixed_repeat_rows(row_prefix: bytes, pattern: bytes, pattern_len: int, rows: int) -> bytes:
    """zlib stream for `rows` repetitions of (row_prefix + pattern repeated to pattern_len bytes),
    encoded by hand with fixed-Huffman deflate (RFC 1951 3.2.6).

    Unlike zlib.compress, the output does not depend on the zlib build (zlib vs zlib-ng give
    different compressed bytes for the same input), so fixture hashes are stable across machines.
    """
    acc = 0
    nbits = 0
    out = bytearray()

    def put(value: int, n: int) -> None:  # LSB-first bit packing
        nonlocal acc, nbits
        acc |= value << nbits
        nbits += n
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8

    def rev(code: int, n: int) -> int:  # Huffman codes are sent MSB-first
        r = 0
        for _ in range(n):
            r = (r << 1) | (code & 1)
            code >>= 1
        return r

    def lit(b: int) -> list[tuple[int, int]]:
        return [(rev(0x30 + b, 8), 8)] if b < 144 else [(rev(0x190 + b - 144, 9), 9)]

    # Length symbols used: 258 -> 285 (8-bit code 0xC5, no extra); 3..257 via the RFC table.
    LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
                131, 163, 195, 227, 258]
    LEN_EXTRA = [0] * 8 + [1] * 4 + [2] * 4 + [3] * 4 + [4] * 4 + [5] * 4 + [0]

    def length_tokens(length: int) -> list[tuple[int, int]]:
        i = max(j for j, b in enumerate(LEN_BASE) if b <= length)
        sym = 257 + i
        code = [(rev(sym - 256, 7), 7)] if sym <= 279 else [(rev(0xC0 + sym - 280, 8), 8)]
        if LEN_EXTRA[i]:
            code.append((length - LEN_BASE[i], LEN_EXTRA[i]))
        return code

    period = len(pattern)
    assert period in (1, 2, 3, 4), "distance code below assumes a short period"
    dist = [(rev(period - 1, 5), 5)]  # distances 1-4 are codes 0-3, no extra bits

    row_tokens: list[tuple[int, int]] = []
    for b in row_prefix + pattern:
        row_tokens += lit(b)
    remaining = pattern_len - period
    while remaining >= 3:
        n = min(258, remaining if remaining - 258 >= 3 or remaining <= 258 else remaining - 3)
        row_tokens += length_tokens(n) + dist
        remaining -= n
    for k in range(remaining):
        row_tokens += lit(pattern[(pattern_len - remaining + k) % period])

    put(1, 1)  # BFINAL
    put(1, 2)  # BTYPE = 01 (fixed Huffman)
    for _ in range(rows):
        for v, n in row_tokens:
            put(v, n)
    put(0, 7)  # end-of-block (256)
    if nbits:
        out.append(acc & 0xFF)

    raw_row = row_prefix + (pattern * (pattern_len // period + 1))[:pattern_len]
    adler = 1
    for _ in range(rows):
        adler = zlib.adler32(raw_row, adler)
    return b"\x78\x01" + bytes(out) + struct.pack(">I", adler)


# ---------------------------------------------------------------- legacy PDF filter encoders (spec 0.1.4)

def enc_ascii_hex(data: bytes) -> bytes:
    """ASCIIHexDecode encoding, with '>' as end-of-data."""
    return data.hex().encode() + b">"


def enc_ascii85(data: bytes) -> bytes:
    """ASCII85Decode encoding (Adobe alphabet, 'z' for zero groups), with '~>' as end-of-data."""
    import base64
    return base64.a85encode(data, foldspaces=False, adobe=False) + b"~>"


def enc_run_length(data: bytes) -> bytes:
    """RunLengthDecode encoding: repeat runs (>= 3) as 257-n, literal runs otherwise, then EOD 128."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        j = i
        while j < n and j - i < 128 and data[j] == data[i]:
            j += 1
        if j - i >= 3:
            out += bytes([257 - (j - i), data[i]])
            i = j
            continue
        k = i
        while k < n and k - i < 128:
            if k + 2 < n and data[k] == data[k + 1] == data[k + 2]:
                break
            k += 1
        out.append(k - i - 1)
        out += data[i:k]
        i = k
    return bytes(out) + b"\x80"


def enc_lzw(data: bytes, early_change: int = 1) -> bytes:
    """LZWDecode encoding as PDF defines it: MSB-first variable-width codes (9-12 bits), Clear = 256,
    EOD = 257. With early_change=1 (the PDF default) the code width grows one code early."""
    CLEAR, EOD = 256, 257
    acc = 0
    nbits = 0
    out = bytearray()

    def emit(code: int, width: int) -> None:
        nonlocal acc, nbits
        acc = (acc << width) | code
        nbits += width
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
        acc &= (1 << nbits) - 1

    # The decoder adds a table entry for every code it reads *except the first after a Clear*, so its table
    # runs one entry behind the encoder's. The width of each code must follow the decoder's table size.
    def width_for(codes_since_clear: int) -> int:
        dec_next = 258 + max(0, codes_since_clear - 1)
        w = 9
        while w < 12 and dec_next + early_change >= (1 << w):
            w += 1
        return w

    def reset():
        return {bytes([i]): i for i in range(256)}, 258, 0

    table, next_code, n = reset()
    emit(CLEAR, 9)
    w = b""
    for byte in data:
        c = bytes([byte])
        wc = w + c
        if wc in table:
            w = wc
            continue
        emit(table[w], width_for(n))
        n += 1
        table[wc] = next_code
        next_code += 1
        if next_code >= 4094:  # table nearly full: Clear (at the current width) and restart
            emit(CLEAR, width_for(n))
            table, next_code, n = reset()
        w = c
    if w:
        emit(table[w], width_for(n))
        n += 1
    emit(EOD, width_for(n))
    if nbits:
        out.append((acc << (8 - nbits)) & 0xFF)
    return bytes(out)


def pdf_raw_stream(dict_entries: bytes, encoded: bytes) -> bytes:
    """A stream object whose data is already encoded (the /Filter goes in dict_entries)."""
    return b"<< " + dict_entries + b"/Length " + str(len(encoded)).encode() + b" >>\nstream\n" + encoded + b"\nendstream"


# ---------------------------------------------------------------- JPEG / WebP / GIF bases

# 8x8 baseline JPEG (JFIF, no EXIF), generated once by a standard encoder and frozen here.
JPEG_8X8 = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb00430006040506050406060506070706080a100a0a09090a140e0f0c1017141818171416161a1d251f1a1b231c1616202c20232627292a29191f2d302d283025282928ffdb0043010707070a080a130a0a13281a161a2828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828ffc00011080008000803012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00e728a28af10fd40fffd9"
)

# 8x8 lossless WebP (VP8L), frozen.
WEBP_8X8 = bytes.fromhex("524946461e000000574542505650384c110000002f07c0010007509e2297a7ff8188e87f0000")

# 1x1 GIF89a.
GIF_1X1 = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")

JFIF_END = 2 + 2 + 16  # SOI + APP0 marker + APP0 payload (length 16 incl. length bytes)


def jpeg_insert_segment(jpeg: bytes, marker: int, payload: bytes, *, after_app0: bool = True) -> bytes:
    if len(payload) + 2 > 0xFFFF:
        raise ValueError("segment too large")
    seg = bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload
    pos = JFIF_END if after_app0 else 2
    return jpeg[:pos] + seg + jpeg[pos:]


def jpeg_set_sof_dims(jpeg: bytes, width: int, height: int) -> bytes:
    i = jpeg.index(b"\xff\xc0")
    # FFC0 | len(2) | precision(1) | height(2) | width(2)
    return jpeg[: i + 5] + struct.pack(">HH", height, width) + jpeg[i + 9:]


def exif_with_gps(make: str = "SafeFileTestCam", lat=(37, 46, 30), lon=(122, 25, 10)) -> bytes:
    """APP1 payload: 'Exif\\0\\0' + little-endian TIFF with IFD0 (Make, GPSInfo) and a GPS IFD."""
    def rational3(dms):
        return b"".join(struct.pack("<II", v, 1) for v in dms)

    make_b = make.encode() + b"\x00"
    # Layout (offsets relative to TIFF header start):
    # 0: header(8) | 8: IFD0 (2 + 2*12 + 4 = 30) | 38: make string | gps IFD | gps data
    ifd0_off = 8
    ifd0_size = 2 + 2 * 12 + 4
    make_off = ifd0_off + ifd0_size
    gps_ifd_off = make_off + len(make_b)
    gps_entries = 4
    gps_ifd_size = 2 + gps_entries * 12 + 4
    lat_off = gps_ifd_off + gps_ifd_size
    lon_off = lat_off + 24

    tiff = b"II*\x00" + struct.pack("<I", ifd0_off)
    ifd0 = struct.pack("<H", 2)
    ifd0 += struct.pack("<HHII", 0x010F, 2, len(make_b), make_off)      # Make (ASCII)
    ifd0 += struct.pack("<HHII", 0x8825, 4, 1, gps_ifd_off)             # GPSInfo IFD pointer
    ifd0 += struct.pack("<I", 0)
    gps = struct.pack("<H", gps_entries)
    gps += struct.pack("<HHI", 0x0001, 2, 2) + b"N\x00\x00\x00"          # GPSLatitudeRef
    gps += struct.pack("<HHII", 0x0002, 5, 3, lat_off)                  # GPSLatitude
    gps += struct.pack("<HHI", 0x0003, 2, 2) + b"W\x00\x00\x00"          # GPSLongitudeRef
    gps += struct.pack("<HHII", 0x0004, 5, 3, lon_off)                  # GPSLongitude
    gps += struct.pack("<I", 0)
    body = tiff + ifd0 + make_b + gps + rational3(lat) + rational3(lon)
    assert len(tiff + ifd0) == make_off and lat_off == len(tiff + ifd0 + make_b + gps)
    return b"Exif\x00\x00" + body


def pe_stub() -> bytes:
    """Inert MZ/PE header bytes (not runnable): an 'executable disguised as an image' probe."""
    dos = bytearray(128)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x80)
    msg = b"This program cannot be run in DOS mode.\r\r\n$"
    dos[0x4E:0x4E + len(msg)] = msg
    pe = b"PE\x00\x00" + struct.pack("<HH", 0x14C, 0) + b"\x00" * 16
    return bytes(dos) + pe


# ---------------------------------------------------------------- PDF

def pdf_stream(dict_entries: bytes, data: bytes, *, compress: bool = False) -> bytes:
    if compress:
        data = zlib.compress(data, 9)
        dict_entries = b"/Filter /FlateDecode " + dict_entries
    return b"<< " + dict_entries + b"/Length " + str(len(data)).encode() + b" >>\nstream\n" + data + b"\nendstream"


def pdf_build(objects: dict[int, bytes], *, root: int = 1, trailer_extra: bytes = b"",
              version: bytes = b"1.7", free_gen: int = 65535,
              entry_gens: dict[int, int] | None = None) -> bytes:
    """Classic xref-table PDF. Object numbers must be 1..n consecutive.

    free_gen: generation written for the object-0 free-list head (Pillow writes 65536).
    entry_gens: override the generation written in the xref for specific in-use objects.
    """
    n = max(objects)
    assert sorted(objects) == list(range(1, n + 1)), "objects must be numbered 1..n"
    entry_gens = entry_gens or {}
    out = bytearray(b"%PDF-" + version + b"\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in range(1, n + 1):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode() + objects[num] + b"\nendobj\n"
    xref_off = len(out)
    out += f"xref\n0 {n + 1}\n0000000000 {free_gen:05d} f \n".encode()
    for num in range(1, n + 1):
        out += f"{offsets[num]:010d} {entry_gens.get(num, 0):05d} n \n".encode()
    out += (b"trailer\n<< /Size " + str(n + 1).encode() + b" /Root " + str(root).encode()
            + b" 0 R " + trailer_extra + b">>\nstartxref\n" + str(xref_off).encode() + b"\n%%EOF\n")
    return bytes(out)


def pdf_last_startxref(pdf: bytes) -> int:
    return int(re.findall(rb"startxref\s+(\d+)", pdf)[-1])


def pdf_incremental_update(base: bytes, new_objects: dict[int, bytes], *, size: int, root: int = 1) -> bytes:
    """Append an incremental update section (new revision) to an existing classic-xref PDF."""
    prev = pdf_last_startxref(base)
    out = bytearray(base)
    offsets = {}
    for num in sorted(new_objects):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode() + new_objects[num] + b"\nendobj\n"
    xref_off = len(out)
    out += b"xref\n"
    for num in sorted(new_objects):
        out += f"{num} 1\n{offsets[num]:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {size} /Root {root} 0 R /Prev {prev} >>\nstartxref\n{xref_off}\n%%EOF\n").encode()
    return bytes(out)


def pdf_build_objstm(plain: dict[int, bytes], compressed: dict[int, bytes], *, root: int) -> bytes:
    """PDF 1.5+ with an object stream (compressed objects) and a cross-reference stream.

    `plain` and `compressed` object numbers together must be 1..k; the ObjStm gets k+1 and the
    XRef stream k+2. Compressed objects must not be streams (PDF rule).
    """
    k = max(list(plain) + list(compressed))
    assert sorted(list(plain) + list(compressed)) == list(range(1, k + 1))
    objstm_num, xref_num = k + 1, k + 2

    header, body = [], bytearray()
    index = {}
    for i, num in enumerate(sorted(compressed)):
        index[num] = i
        header.append(f"{num} {len(body)}")
        body += compressed[num] + b"\n"
    header_b = (" ".join(header) + "\n").encode()
    objstm_data = header_b + bytes(body)
    objstm = pdf_stream(b"/Type /ObjStm /N " + str(len(compressed)).encode()
                        + b" /First " + str(len(header_b)).encode() + b" ", objstm_data, compress=True)

    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(plain):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode() + plain[num] + b"\nendobj\n"
    offsets[objstm_num] = len(out)
    out += f"{objstm_num} 0 obj\n".encode() + objstm + b"\nendobj\n"
    offsets[xref_num] = len(out)

    rows = bytearray(struct.pack(">BIH", 0, 0, 0xFFFF))
    for num in range(1, xref_num + 1):
        if num in compressed:
            rows += struct.pack(">BIH", 2, objstm_num, index[num])
        else:
            rows += struct.pack(">BIH", 1, offsets[num], 0)
    xref_stream = pdf_stream(b"/Type /XRef /Size " + str(xref_num + 1).encode()
                             + b" /W [1 4 2] /Root " + str(root).encode() + b" 0 R ", bytes(rows), compress=True)
    out += f"{xref_num} 0 obj\n".encode() + xref_stream + b"\nendobj\n"
    out += f"startxref\n{offsets[xref_num]}\n%%EOF\n".encode()
    return bytes(out)


HELLO_CONTENT = b"BT /F1 24 Tf 72 720 Td (Hello from the SafeFile corpus) Tj ET"
FONT = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"


def pdf_simple_objects(*, catalog_extra: bytes = b"", page_extra: bytes = b"",
                       content: bytes = HELLO_CONTENT) -> dict[int, bytes]:
    """1 Catalog, 2 Pages, 3 Page, 4 content stream, 5 font."""
    return {
        1: b"<< /Type /Catalog /Pages 2 0 R " + catalog_extra + b">>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> " + page_extra + b">>"),
        4: pdf_stream(b"", content),
        5: FONT,
    }
