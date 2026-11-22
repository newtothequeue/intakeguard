"""Benign fixtures that pin the spec 0.1.2 image decisions (ADR 0004)."""

import struct


from _lib import PNG_SIG, jpeg_insert_segment, png_chunk, zlib_fixed_repeat_rows

# 16x8 lossy WebP (VP8), frozen from a standard encoder.
WEBP_LOSSY_16X8 = bytes.fromhex(
    "524946462e0000005745425056503820220000009001009d012a1000080002003425a40002e69a1f8000fef79f7c8c177cf7c07d4000"
)

# 16x8 baseline JPEG, no EXIF, frozen from a standard encoder.
JPEG_16X8 = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb0043000503040404030504040405050506070c08070707070f0b0b090c110f1212110f111113161c1713141a1511111821181a1d1d1f1f1f13172224221e241c1e1f1effdb0043010505050706070e08080e1e1411141e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1effc00011080008001003012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f003fe19b7fe9c3ff001da3fe19b7fe9c3ff1da28a00fffd9"
)


def exif_orientation(value: int) -> bytes:
    """APP1 payload: 'Exif\\0\\0' + little-endian TIFF with one IFD0 entry, Orientation (0x0112, SHORT)."""
    tiff = b"II*\x00" + struct.pack("<I", 8)
    ifd = struct.pack("<H", 1) + struct.pack("<HHIHH", 0x0112, 3, 1, value, 0) + struct.pack("<I", 0)
    return b"Exif\x00\x00" + tiff + ifd


def png_solid_large(width: int, height: int) -> bytes:
    """Large solid-colour RGB PNG. The IDAT is hand-encoded fixed-Huffman deflate (not zlib.compress), so
    the bytes and hash are identical on every machine. zlib and zlib-ng compress differently."""
    idat = zlib_fixed_repeat_rows(b"\x00", bytes((40, 90, 160)), width * 3, height)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return PNG_SIG + png_chunk(b"IHDR", ihdr) + png_chunk(b"IDAT", idat) + png_chunk(b"IEND", b"")


def generate() -> dict[str, bytes]:
    return {
        "benign-webp-lossy-to-jpeg": WEBP_LOSSY_16X8,
        "img-exif-orientation-6": jpeg_insert_segment(JPEG_16X8, 0xE1, exif_orientation(6)),
        "benign-png-36mp": png_solid_large(6000, 6000),  # 36,000,000 px < 40,000,000 maxImagePixels
    }
