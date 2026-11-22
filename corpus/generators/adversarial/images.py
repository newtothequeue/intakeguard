"""T4/T6/T11/T12: image metadata, dimension bombs, truncation, byte limits."""

import struct

from _lib import (JPEG_8X8, exif_with_gps, jpeg_insert_segment, jpeg_set_sof_dims,
                  png_declared_dims, png_rgb)


def generate() -> dict[str, bytes]:
    png_meta = png_rgb(8, 8, extra_chunks=[
        (b"tEXt", b"Author\x00Jane Example"),
        (b"tEXt", b"Comment\x00internal-ticket-4821"),
        (b"eXIf", exif_with_gps()[6:]),  # PNG eXIf carries a bare TIFF stream, no 'Exif\0\0' prefix
    ])
    full = png_rgb(8, 8)
    # Cut inside the IDAT chunk: IEND is missing and the IDAT CRC can't be checked.
    idat = full.index(b"IDAT")
    idat_len = struct.unpack(">I", full[idat - 4: idat])[0]
    truncated = full[: idat + 4 + idat_len // 2]

    return {
        "img-meta-jpeg-exif-gps": jpeg_insert_segment(JPEG_8X8, 0xE1, exif_with_gps()),
        "img-meta-png-text-exif": png_meta,
        "img-bomb-png-dimensions": png_declared_dims(100_000, 100_000),
        "img-bomb-jpeg-dimensions": jpeg_set_sof_dims(JPEG_8X8, 65_000, 65_000),
        "img-truncated-png": truncated,
        "limit-bytes-over-png": png_rgb(64, 64, seed=1),  # ~12 KB, incompressible
    }
