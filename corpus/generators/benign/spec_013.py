"""Benign fixture pinning spec 0.1.3 (ADR 0005): lossy WebP with alpha must become PNG, keeping transparency."""

# 16x8 lossy WebP: VP8X container + ALPH (alpha) + VP8 (lossy), frozen from a standard encoder.
# Corner pixels are fully transparent; the centre block is opaque green.
WEBP_LOSSY_ALPHA_16X8 = bytes.fromhex(
    "524946468c00000057454250565038580a000000100000000f0000070000414c504816000000010f30ff11118220dba606f3b73cc42122fa1fb01e0056503820500000005002009d012a1000080002003425b00274ba00ed00dcffbb60094000fecbb7ffc3475654dd01cced41a2e437adae5fff1dbff84afadd9d603a74c41bfcd5ff209f5bb3a40742f8937ffda59fe2a00000"
)


def generate() -> dict[str, bytes]:
    assert b"ALPH" in WEBP_LOSSY_ALPHA_16X8 and b"VP8 " in WEBP_LOSSY_ALPHA_16X8
    return {"benign-webp-lossy-alpha-to-png": WEBP_LOSSY_ALPHA_16X8}
