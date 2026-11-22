//! PNG / JPEG / WebP header walks. No pixel data is decoded: dimensions come from IHDR, SOFn and
//! VP8/VP8L/VP8X headers, so a dimension bomb is rejected before any pixel allocation.

use crate::exif;
use crate::policy::Policy;
use crate::report::{Abort, Ctx};

#[derive(Default)]
struct Info {
    dims: Option<(u64, u64)>,
    metadata: Vec<String>,
    gps: bool,
}

/// Returns true when the structure was fully validated.
pub fn inspect(ctx: &mut Ctx, policy: &Policy, mime: &str, d: &[u8]) -> bool {
    let mut info = Info::default();
    let res = match mime {
        "image/png" => png(ctx, d, &mut info),
        "image/jpeg" => jpeg(ctx, d, &mut info),
        "image/webp" => webp(ctx, d, &mut info),
        _ => Err(Abort::Unsupported(format!("{mime} not supported"))),
    };
    let ok = res.is_ok();
    match res {
        Ok(()) => ctx.pass("image.structure"),
        Err(a) => crate::apply_abort(ctx, "image.structure", a),
    }

    match info.dims {
        Some((w, h)) => {
            let l = &policy.limits;
            let mut bad = false;
            if w > l.max_image_dimension || h > l.max_image_dimension {
                bad = true;
                ctx.fail("image.dimensions", "LIMIT_IMAGE_DIMENSION_EXCEEDED",
                         format!("{w}x{h}; maxImageDimension={}", l.max_image_dimension));
            }
            if w.saturating_mul(h) > l.max_image_pixels {
                bad = true;
                ctx.fail("image.dimensions", "LIMIT_IMAGE_PIXELS_EXCEEDED",
                         format!("{} px; maxImagePixels={}", w.saturating_mul(h), l.max_image_pixels));
            }
            if !bad { ctx.pass_detail("image.dimensions", format!("{w}x{h} (declared)")); }
        }
        None => ctx.skip("image.dimensions", "no dimensions could be read"),
    }

    if !ok && info.metadata.is_empty() {
        ctx.skip("image.metadata", "structure invalid; metadata scan incomplete");
    } else if info.metadata.is_empty() {
        ctx.pass("image.metadata");
    } else {
        let what = info.metadata.join(", ");
        match policy.images.metadata.as_str() {
            "reject" => ctx.fail("image.metadata", "IMAGE_METADATA_PRESENT", what),
            "keep" => ctx.warn("image.metadata", "IMAGE_METADATA_PRESENT", format!("{what}; kept by policy")),
            _ => ctx.fail_downgraded("image.metadata", "IMAGE_METADATA_PRESENT", format!("{what}; removed by policy")),
        }
        if info.gps {
            ctx.warn("image.gps", "IMAGE_GPS_PRESENT", "EXIF GPSInfo IFD present");
        }
    }
    ok
}

fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (n, e) in t.iter_mut().enumerate() {
            let mut c = n as u32;
            for _ in 0..8 { c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 }; }
            *e = c;
        }
        t
    });
    let mut c = 0xFFFF_FFFFu32;
    for &b in data { c = t[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8); }
    c ^ 0xFFFF_FFFF
}

fn be32(d: &[u8], o: usize) -> u32 { u32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]) }

fn png(ctx: &mut Ctx, d: &[u8], info: &mut Info) -> Result<(), Abort> {
    let mut p = 8usize;
    let mut first = true;
    let mut saw_idat = false;
    loop {
        ctx.tick()?;
        if d.len() < p + 8 { return Err(Abort::Truncated(format!("PNG ends at byte {} without IEND", d.len()))); }
        let len = be32(d, p) as usize;
        if len > 0x7FFF_FFFF { return Err(Abort::Malformed("PNG chunk length over 2^31-1".into())); }
        let ty = &d[p + 4..p + 8];
        let tys = String::from_utf8_lossy(ty).to_string();
        let end = p + 8 + len + 4;
        if d.len() < end {
            return Err(Abort::Truncated(format!("PNG chunk {tys} at {p} needs {} bytes, file has {}", end, d.len())));
        }
        let body = &d[p + 8..p + 8 + len];
        if crc32(&d[p + 4..p + 8 + len]) != be32(d, p + 8 + len) {
            return Err(Abort::Malformed(format!("PNG chunk {tys} CRC mismatch")));
        }
        if first {
            if ty != b"IHDR" || len != 13 { return Err(Abort::Malformed("PNG first chunk is not a 13-byte IHDR".into())); }
            let (w, h) = (be32(body, 0) as u64, be32(body, 4) as u64);
            info.dims = Some((w, h));
            if w == 0 || h == 0 || w > 0x7FFF_FFFF || h > 0x7FFF_FFFF {
                return Err(Abort::Malformed(format!("PNG IHDR dimensions {w}x{h} invalid")));
            }
            let (depth, color) = (body[8], body[9]);
            let ok = match color {
                0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
                3 => matches!(depth, 1 | 2 | 4 | 8),
                2 | 4 | 6 => matches!(depth, 8 | 16),
                _ => false,
            };
            if !ok || body[10] != 0 || body[11] != 0 || body[12] > 1 {
                return Err(Abort::Malformed("PNG IHDR has an invalid depth/color/method combination".into()));
            }
            first = false;
        } else {
            match ty {
                b"IHDR" => return Err(Abort::Malformed("duplicate IHDR".into())),
                b"IDAT" => saw_idat = true,
                b"IEND" => {
                    if !saw_idat { return Err(Abort::Malformed("PNG has no IDAT".into())); }
                    if end != d.len() {
                        return Err(Abort::Malformed(format!("{} bytes after IEND", d.len() - end)));
                    }
                    return Ok(());
                }
                b"acTL" | b"fcTL" | b"fdAT" => return Err(Abort::Unsupported("animated PNG (APNG)".into())),
                // iCCP counts as metadata (spec 0.1.2: ICC profiles are removed). Its compressed
                // profile is never inflated: the transform hands the decoder a stream without it.
                b"tEXt" | b"zTXt" | b"iTXt" | b"tIME" | b"iCCP" => info.metadata.push(format!("PNG {tys}")),
                b"eXIf" => {
                    info.metadata.push("PNG eXIf".into());
                    if exif::has_gps(body).unwrap_or(false) { info.gps = true; }
                }
                b"PLTE" => {}
                _ if ty[0].is_ascii_uppercase() => {
                    return Err(Abort::Unsupported(format!("unknown critical PNG chunk {tys}")));
                }
                _ => {}
            }
        }
        p = end;
    }
}

fn jpeg(ctx: &mut Ctx, d: &[u8], info: &mut Info) -> Result<(), Abort> {
    let mut p = 2usize;
    let mut saw_sof = false;
    loop {
        ctx.tick()?;
        if p >= d.len() { return Err(Abort::Truncated("JPEG ends before EOI".into())); }
        if d[p] != 0xFF { return Err(Abort::Malformed(format!("expected a JPEG marker at byte {p}"))); }
        while p < d.len() && d[p] == 0xFF { p += 1; }
        if p >= d.len() { return Err(Abort::Truncated("JPEG ends inside a marker".into())); }
        let m = d[p];
        p += 1;
        match m {
            0xD8 => return Err(Abort::Malformed("second SOI".into())),
            0xD9 => {
                if !saw_sof { return Err(Abort::Malformed("JPEG EOI before any frame".into())); }
                if p != d.len() { return Err(Abort::Malformed(format!("{} bytes after EOI", d.len() - p))); }
                return Ok(());
            }
            0x01 | 0xD0..=0xD7 => continue,
            _ => {}
        }
        if d.len() < p + 2 { return Err(Abort::Truncated("JPEG segment length cut off".into())); }
        let len = u16::from_be_bytes([d[p], d[p + 1]]) as usize;
        if len < 2 { return Err(Abort::Malformed("JPEG segment length < 2".into())); }
        if d.len() < p + len { return Err(Abort::Truncated(format!("JPEG segment FF{m:02X} runs past end of file"))); }
        let seg = &d[p + 2..p + len];
        match m {
            0xC0..=0xCF if m != 0xC4 && m != 0xC8 && m != 0xCC => {
                if saw_sof { return Err(Abort::Unsupported("multiple JPEG frames".into())); }
                if seg.len() < 6 { return Err(Abort::Malformed("short SOF segment".into())); }
                let h = u16::from_be_bytes([seg[1], seg[2]]) as u64;
                let w = u16::from_be_bytes([seg[3], seg[4]]) as u64;
                info.dims = Some((w, h));
                if h == 0 || w == 0 { return Err(Abort::Unsupported("JPEG height defined by DNL / zero dimension".into())); }
                jpeg_components(seg)?;
                saw_sof = true;
            }
            0xE0 => {
                if !(seg.starts_with(b"JFIF\0") || seg.starts_with(b"JFXX\0")) { info.metadata.push("JPEG APP0 (non-JFIF)".into()); }
            }
            0xE1 => {
                if let Some(t) = seg.strip_prefix(b"Exif\0\0") {
                    info.metadata.push("JPEG APP1/EXIF".into());
                    if exif::has_gps(t).unwrap_or(false) { info.gps = true; }
                } else if seg.starts_with(b"http://ns.adobe.com/xap/1.0/") {
                    info.metadata.push("JPEG APP1/XMP".into());
                } else {
                    info.metadata.push("JPEG APP1".into());
                }
            }
            0xE2..=0xEF => info.metadata.push(format!("JPEG APP{}", m - 0xE0)),
            0xFE => info.metadata.push("JPEG COM".into()),
            0xDA => {
                if !saw_sof { return Err(Abort::Malformed("SOS before SOF".into())); }
                // Entropy-coded data: skip to the next marker that isn't stuffing or a restart.
                let mut q = p + len;
                loop {
                    if q + 1 >= d.len() { return Err(Abort::Truncated("JPEG scan data ends before EOI".into())); }
                    if d[q] == 0xFF && d[q + 1] != 0x00 && !(0xD0..=0xD7).contains(&d[q + 1]) && d[q + 1] != 0xFF {
                        break;
                    }
                    q += 1;
                    if q & 0xFFFF == 0 { ctx.tick()?; }
                }
                p = q;
                continue;
            }
            _ => {}
        }
        p += len;
    }
}

/// Frame components: 1 (gray), 3 (YCbCr) or 4 (CMYK/YCCK). The first component carries the largest
/// sampling factors (each 1 or 2); every other component matches them or is 1x1. That covers
/// 4:4:4, 4:2:2, 4:2:0, 4:4:0, grayscale, CMYK and Adobe YCCK, which is what real encoders write.
/// Anything else is UNSUPPORTED_FEATURE: exotic layouts are where decoders misbehave (a fuzzed
/// 4-component frame with the first component 1x1 and the second 2x2 made zune-jpeg panic).
fn jpeg_components(seg: &[u8]) -> Result<(), Abort> {
    let n = seg[5] as usize;
    if !matches!(n, 1 | 3 | 4) {
        return Err(Abort::Unsupported(format!("JPEG with {n} components")));
    }
    let comps = seg.get(6..6 + 3 * n).ok_or_else(|| Abort::Malformed("SOF component list cut short".into()))?;
    let (h0, v0) = (comps[1] >> 4, comps[1] & 15);
    if !(1..=2).contains(&h0) || !(1..=2).contains(&v0) {
        return Err(Abort::Unsupported(format!("JPEG sampling factors {h0}x{v0} on the first component")));
    }
    let mut ids = Vec::with_capacity(n);
    for c in comps.chunks_exact(3) {
        let (h, v) = (c[1] >> 4, c[1] & 15);
        if !((h, v) == (h0, v0) || (h, v) == (1, 1)) {
            return Err(Abort::Unsupported(format!(
                "JPEG sampling factors {h}x{v} with the first component at {h0}x{v0}")));
        }
        if c[2] > 3 { return Err(Abort::Malformed("JPEG quantization table id > 3".into())); }
        if ids.contains(&c[0]) { return Err(Abort::Malformed("duplicate JPEG component id".into())); }
        ids.push(c[0]);
    }
    Ok(())
}

fn le32(d: &[u8], o: usize) -> u32 { u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]) }
fn le24(d: &[u8], o: usize) -> u32 { d[o] as u32 | (d[o + 1] as u32) << 8 | (d[o + 2] as u32) << 16 }

fn webp(ctx: &mut Ctx, d: &[u8], info: &mut Info) -> Result<(), Abort> {
    let riff = le32(d, 4) as usize;
    let total = riff.checked_add(8).ok_or_else(|| Abort::Malformed("RIFF size overflow".into()))?;
    if d.len() < total { return Err(Abort::Truncated(format!("RIFF declares {total} bytes, file has {}", d.len()))); }
    if d.len() > total { return Err(Abort::Malformed(format!("{} bytes after the RIFF container", d.len() - total))); }
    let mut p = 12usize;
    let mut first = true;
    let mut extended = false;
    let mut saw_image = false;
    while p < total {
        ctx.tick()?;
        if total < p + 8 { return Err(Abort::Truncated("WebP chunk header cut off".into())); }
        let ty = &d[p..p + 4];
        let len = le32(d, p + 4) as usize;
        let end = p + 8 + len + (len & 1);
        if total < p + 8 + len { return Err(Abort::Truncated(format!("WebP chunk {} runs past end", String::from_utf8_lossy(ty)))); }
        let body = &d[p + 8..p + 8 + len];
        match ty {
            b"VP8X" if first => {
                if len < 10 { return Err(Abort::Malformed("short VP8X".into())); }
                if body[0] & 0x02 != 0 { return Err(Abort::Unsupported("animated WebP".into())); }
                info.dims = Some((1 + le24(body, 4) as u64, 1 + le24(body, 7) as u64));
                extended = true;
            }
            b"VP8 " => {
                if len < 10 || body[3..6] != [0x9D, 0x01, 0x2A] { return Err(Abort::Malformed("bad VP8 frame header".into())); }
                let w = (u16::from_le_bytes([body[6], body[7]]) & 0x3FFF) as u64;
                let h = (u16::from_le_bytes([body[8], body[9]]) & 0x3FFF) as u64;
                if !extended { info.dims = Some((w, h)); }
                saw_image = true;
            }
            b"VP8L" => {
                if len < 5 || body[0] != 0x2F { return Err(Abort::Malformed("bad VP8L signature".into())); }
                let b = le32(body, 1);
                if !extended { info.dims = Some(((b & 0x3FFF) as u64 + 1, ((b >> 14) & 0x3FFF) as u64 + 1)); }
                saw_image = true;
            }
            b"ANIM" | b"ANMF" => return Err(Abort::Unsupported("animated WebP".into())),
            b"EXIF" => {
                info.metadata.push("WebP EXIF".into());
                let t = body.strip_prefix(b"Exif\0\0").unwrap_or(body);
                if exif::has_gps(t).unwrap_or(false) { info.gps = true; }
            }
            b"XMP " => info.metadata.push("WebP XMP".into()),
            b"ICCP" => info.metadata.push("WebP ICCP".into()),
            _ if first => return Err(Abort::Malformed("WebP first chunk is not VP8/VP8L/VP8X".into())),
            _ => {}
        }
        first = false;
        p = end;
    }
    if !saw_image { return Err(Abort::Malformed("WebP has no image bitstream chunk".into())); }
    Ok(())
}

/// EXIF orientation of an already-validated image (first EXIF block wins), or None.
pub fn orientation(mime: &str, d: &[u8]) -> Option<u16> {
    match mime {
        "image/jpeg" => {
            let mut p = 2usize;
            while p + 4 <= d.len() && d[p] == 0xFF {
                let m = d[p + 1];
                if m == 0xDA || m == 0xD9 { return None; }
                if m == 0x01 || (0xD0..=0xD7).contains(&m) { p += 2; continue; }
                let len = u16::from_be_bytes([d[p + 2], d[p + 3]]) as usize;
                let seg = d.get(p + 4..p + 2 + len)?;
                if m == 0xE1 {
                    if let Some(t) = seg.strip_prefix(b"Exif\0\0") { return exif::orientation(t); }
                }
                p += 2 + len;
            }
            None
        }
        "image/png" => {
            let mut p = 8usize;
            while p + 12 <= d.len() {
                let len = be32(d, p) as usize;
                let body = d.get(p + 8..p + 8 + len)?;
                match &d[p + 4..p + 8] {
                    b"eXIf" => return exif::orientation(body),
                    b"IEND" => return None,
                    _ => {}
                }
                p += 12 + len;
            }
            None
        }
        "image/webp" => {
            let mut p = 12usize;
            while p + 8 <= d.len() {
                let len = le32(d, p + 4) as usize;
                let body = d.get(p + 8..p + 8 + len)?;
                if &d[p..p + 4] == b"EXIF" {
                    return exif::orientation(body.strip_prefix(b"Exif\0\0").unwrap_or(body));
                }
                p += 8 + len + (len & 1);
            }
            None
        }
        _ => None,
    }
}

/// A copy of a validated PNG with only the chunks the pixel decoder needs (IHDR, PLTE, tRNS, IDAT,
/// IEND). Ancillary chunks we discard, notably zlib-compressed iCCP/zTXt/iTXt, never reach the
/// decoder, so they are never inflated.
pub fn png_pixel_chunks(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(d.len());
    out.extend_from_slice(&d[..8]);
    let mut p = 8usize;
    while p + 12 <= d.len() {
        let len = be32(d, p) as usize;
        let end = p + 12 + len;
        if end > d.len() { break; }
        let ty = &d[p + 4..p + 8];
        if matches!(ty, b"IHDR" | b"PLTE" | b"tRNS" | b"IDAT" | b"IEND") { out.extend_from_slice(&d[p..end]); }
        if ty == b"IEND" { break; }
        p = end;
    }
    out
}
