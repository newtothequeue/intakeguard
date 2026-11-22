//! decode-reencode for JPEG / PNG / WebP (format-guarantees.md, "JPEG / PNG / WebP").
//!
//! Runs only after every inspection check passed, so the header-declared dimensions are already
//! within policy. The decoded pixel buffer is sized from the header and counted against
//! maxDecompressedBytes **before** it is allocated. Encoders are given pixels only, so no EXIF,
//! XMP, ICC, text chunks, comments or APPn segments (other than the encoder's own APP0/JFIF) can
//! reach the output.

use std::io::Cursor;

use crate::policy::Policy;
use crate::report::{Abort, Ctx};

/// JPEG quality used whenever the output is JPEG (spec 0.1.2). Not bit-identical.
pub const JPEG_QUALITY: u8 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout { L8, La8, Rgb8, Rgba8, L16, La16, Rgb16, Rgba16 }

impl Layout {
    fn channels(self) -> usize {
        match self { Layout::L8 | Layout::L16 => 1, Layout::La8 | Layout::La16 => 2,
                     Layout::Rgb8 | Layout::Rgb16 => 3, Layout::Rgba8 | Layout::Rgba16 => 4 }
    }
    fn wide(self) -> bool { matches!(self, Layout::L16 | Layout::La16 | Layout::Rgb16 | Layout::Rgba16) }
    fn to8(self) -> Layout {
        match self { Layout::L16 => Layout::L8, Layout::La16 => Layout::La8,
                     Layout::Rgb16 => Layout::Rgb8, Layout::Rgba16 => Layout::Rgba8, l => l }
    }
}

pub struct Pixels {
    pub w: u32,
    pub h: u32,
    pub layout: Layout,
    /// Row-major samples; 16-bit samples are big-endian (as PNG stores them).
    pub data: Vec<u8>,
}

pub struct Artifact {
    pub bytes: Vec<u8>,
    pub mime: &'static str,
    pub w: u32,
    pub h: u32,
    /// Human-readable notes for the transformations list (e.g. "16-bit samples reduced to 8-bit").
    pub notes: Vec<String>,
}

pub enum Failure {
    /// A limit or cancellation stopped the transform (mapped to its usual reason code).
    Abort(Abort),
    /// Decoding or encoding failed: TRANSFORM_FAILED, no output.
    Failed(String),
}

impl From<Abort> for Failure { fn from(a: Abort) -> Self { Failure::Abort(a) } }

fn fail<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> Failure + '_ {
    move |e| Failure::Failed(format!("{what}: {e}"))
}

/// Pixel buffers are governed by maxImagePixels / maxImageDimension (spec 0.1.2), not by
/// maxDecompressedBytes. The header walk already enforced them on the declared size; this re-checks
/// what the decoder itself reports before anything is allocated.
fn pixel_budget(policy: &Policy, w: usize, h: usize, bytes_per_px: usize, what: &str) -> Result<usize, Failure> {
    let l = &policy.limits;
    if w == 0 || h == 0 || w as u64 > l.max_image_dimension || h as u64 > l.max_image_dimension {
        return Err(Failure::Abort(Abort::Malformed(format!("{what} decoder reports {w}x{h}, outside policy dimensions"))));
    }
    if (w as u64) * (h as u64) > l.max_image_pixels {
        return Err(Failure::Abort(Abort::Malformed(format!("{what} decoder reports {} px > maxImagePixels", w * h))));
    }
    w.checked_mul(h).and_then(|n| n.checked_mul(bytes_per_px))
        .ok_or_else(|| Failure::Failed(format!("{what}: decoded size overflows")))
}

pub struct Decoded {
    pub px: Pixels,
    /// The source was lossy (JPEG, or WebP with a VP8 bitstream).
    pub lossy: bool,
}

pub fn decode(ctx: &mut Ctx, policy: &Policy, mime: &str, d: &[u8]) -> Result<Decoded, Failure> {
    ctx.check_now()?;
    let max_dim = policy.limits.max_image_dimension as usize;
    let (px, lossy) = match mime {
        "image/png" => {
            // Only IHDR/PLTE/tRNS/IDAT/IEND reach the decoder: iCCP and text chunks are never inflated.
            let clean = crate::images::png_pixel_chunks(d);
            let ihdr = clean.get(16..24).ok_or_else(|| Failure::Failed("PNG: no IHDR".into()))?;
            let (w, h) = (u32::from_be_bytes(ihdr[0..4].try_into().unwrap()) as usize,
                          u32::from_be_bytes(ihdr[4..8].try_into().unwrap()) as usize);
            // Worst case 8 bytes per pixel (RGBA16) plus decoder working space.
            let cap = pixel_budget(policy, w, h, 8, "PNG")?.saturating_add(8 << 20);
            let mut dec = png::Decoder::new_with_limits(Cursor::new(clean), png::Limits { bytes: cap });
            // EXPAND: palette -> RGB(A), low-bit gray -> 8-bit, tRNS -> alpha. 16-bit stays 16-bit.
            dec.set_transformations(png::Transformations::EXPAND);
            let mut r = dec.read_info().map_err(fail("PNG decode"))?;
            if r.info().animation_control.is_some() {
                return Err(Failure::Abort(Abort::Unsupported("animated PNG (APNG)".into())));
            }
            let n = r.output_buffer_size();
            if n > cap { return Err(Failure::Failed("PNG decode: output buffer larger than the pixel budget".into())); }
            let mut buf = vec![0u8; n];
            let fi = r.next_frame(&mut buf).map_err(fail("PNG decode"))?;
            buf.truncate(fi.buffer_size());
            let wide = fi.bit_depth == png::BitDepth::Sixteen;
            let layout = match (fi.color_type, wide) {
                (png::ColorType::Grayscale, false) => Layout::L8,
                (png::ColorType::GrayscaleAlpha, false) => Layout::La8,
                (png::ColorType::Rgb, false) => Layout::Rgb8,
                (png::ColorType::Rgba, false) => Layout::Rgba8,
                (png::ColorType::Grayscale, true) => Layout::L16,
                (png::ColorType::GrayscaleAlpha, true) => Layout::La16,
                (png::ColorType::Rgb, true) => Layout::Rgb16,
                (png::ColorType::Rgba, true) => Layout::Rgba16,
                (c, _) => return Err(Failure::Failed(format!("PNG decode: unexpected output color type {c:?}"))),
            };
            (Pixels { w: fi.width, h: fi.height, layout, data: buf }, false)
        }
        "image/jpeg" => {
            use zune_jpeg::zune_core::colorspace::ColorSpace;
            use zune_jpeg::zune_core::options::DecoderOptions;
            let opts = DecoderOptions::default()
                .set_max_width(max_dim)
                .set_max_height(max_dim)
                .jpeg_set_out_colorspace(ColorSpace::RGB);
            let mut dec = zune_jpeg::JpegDecoder::new_with_options(d, opts);
            dec.decode_headers().map_err(fail("JPEG decode"))?;
            let info = dec.info().ok_or_else(|| Failure::Failed("JPEG decode: no frame info".into()))?;
            // Single-component (grayscale) JPEGs decode to one channel even when RGB is requested.
            let (layout, ch) = match dec.get_output_colorspace() {
                Some(ColorSpace::Luma) => (Layout::L8, 1),
                Some(ColorSpace::RGB) => (Layout::Rgb8, 3),
                other => return Err(Failure::Failed(format!("JPEG decode: unsupported output colour space {other:?}"))),
            };
            let n = pixel_budget(policy, info.width as usize, info.height as usize, ch, "JPEG")?;
            if dec.output_buffer_size() != Some(n) {
                return Err(Failure::Failed(format!("JPEG decode: buffer size {:?} != {n}", dec.output_buffer_size())));
            }
            let mut buf = vec![0u8; n];
            dec.decode_into(&mut buf).map_err(fail("JPEG decode"))?;
            (Pixels { w: info.width as u32, h: info.height as u32, layout, data: buf }, true)
        }
        "image/webp" => {
            let mut dec = image_webp::WebPDecoder::new(Cursor::new(d)).map_err(fail("WebP decode"))?;
            if dec.is_animated() {
                return Err(Failure::Abort(Abort::Unsupported("animated WebP".into())));
            }
            let (w, h) = dec.dimensions();
            let alpha = dec.has_alpha();
            let n = pixel_budget(policy, w as usize, h as usize, if alpha { 4 } else { 3 }, "WebP")?;
            if dec.output_buffer_size() != Some(n) {
                return Err(Failure::Failed(format!("WebP decode: buffer size {:?} != {n}", dec.output_buffer_size())));
            }
            dec.set_memory_limit(n.saturating_add(8 << 20));
            let lossy = dec.is_lossy();
            let layout = if alpha { Layout::Rgba8 } else { Layout::Rgb8 };
            let mut buf = vec![0u8; n];
            dec.read_image(&mut buf).map_err(fail("WebP decode"))?;
            (Pixels { w, h, layout, data: buf }, lossy)
        }
        other => return Err(Failure::Failed(format!("no decoder for {other}"))),
    };
    ctx.check_now()?;
    let need = px.w as usize * px.h as usize * px.layout.channels() * if px.layout.wide() { 2 } else { 1 };
    if px.data.len() != need {
        return Err(Failure::Failed(format!("decoder returned {} bytes, expected {need}", px.data.len())));
    }
    Ok(Decoded { px, lossy })
}

/// Apply an EXIF orientation (2..=8) to the pixels. 5..=8 swap width and height.
pub fn orient(px: Pixels, o: u16) -> Pixels {
    if !(2..=8).contains(&o) { return px; }
    let (w, h) = (px.w as usize, px.h as usize);
    let bpp = px.layout.channels() * if px.layout.wide() { 2 } else { 1 };
    let (nw, nh) = if o >= 5 { (h, w) } else { (w, h) };
    let mut out = vec![0u8; px.data.len()];
    for y2 in 0..nh {
        for x2 in 0..nw {
            let (x, y) = match o {
                2 => (w - 1 - x2, y2),
                3 => (w - 1 - x2, h - 1 - y2),
                4 => (x2, h - 1 - y2),
                5 => (y2, x2),
                6 => (y2, h - 1 - x2),
                7 => (w - 1 - y2, h - 1 - x2),
                _ => (w - 1 - y2, x2), // 8
            };
            let s = (y * w + x) * bpp;
            let t = (y2 * nw + x2) * bpp;
            out[t..t + bpp].copy_from_slice(&px.data[s..s + bpp]);
        }
    }
    Pixels { w: nw as u32, h: nh as u32, layout: px.layout, data: out }
}

/// 16-bit -> 8-bit by taking the high byte (exact for values that came from 8-bit data).
fn narrow(px: &Pixels) -> (Layout, std::borrow::Cow<'_, [u8]>) {
    if !px.layout.wide() { return (px.layout, std::borrow::Cow::Borrowed(&px.data)); }
    (px.layout.to8(), std::borrow::Cow::Owned(px.data.chunks_exact(2).map(|s| s[0]).collect()))
}

/// `same`: JPEG -> JPEG, PNG -> PNG, lossless WebP -> lossless WebP, lossy WebP -> JPEG (spec 0.1.2),
/// except lossy WebP with alpha -> lossless PNG, so transparency is never flattened (spec 0.1.3).
pub fn output_mime(policy: &Policy, input: &'static str, lossy: bool, alpha: bool) -> &'static str {
    match policy.images.output_format.as_str() {
        "png" => "image/png",
        "webp" => "image/webp",
        "jpeg" => "image/jpeg",
        _ if input == "image/webp" && lossy && alpha => "image/png",
        _ if input == "image/webp" && lossy => "image/jpeg",
        _ => input,
    }
}

/// Composite an alpha channel over white (JPEG has no alpha).
fn flatten(data: &[u8], channels: usize) -> Vec<u8> {
    let c = channels - 1;
    let mut out = Vec::with_capacity(data.len() / channels * c);
    for p in data.chunks_exact(channels) {
        let a = p[c] as u32;
        for &v in &p[..c] { out.push(((v as u32 * a + 255 * (255 - a) + 127) / 255) as u8); }
    }
    out
}

pub fn encode(px: &Pixels, mime: &'static str) -> Result<Artifact, Failure> {
    let mut notes = Vec::new();
    let mut out = Vec::new();
    match mime {
        "image/png" => {
            let (ct, depth) = match px.layout {
                Layout::L8 => (png::ColorType::Grayscale, png::BitDepth::Eight),
                Layout::La8 => (png::ColorType::GrayscaleAlpha, png::BitDepth::Eight),
                Layout::Rgb8 => (png::ColorType::Rgb, png::BitDepth::Eight),
                Layout::Rgba8 => (png::ColorType::Rgba, png::BitDepth::Eight),
                Layout::L16 => (png::ColorType::Grayscale, png::BitDepth::Sixteen),
                Layout::La16 => (png::ColorType::GrayscaleAlpha, png::BitDepth::Sixteen),
                Layout::Rgb16 => (png::ColorType::Rgb, png::BitDepth::Sixteen),
                Layout::Rgba16 => (png::ColorType::Rgba, png::BitDepth::Sixteen),
            };
            let mut e = png::Encoder::new(&mut out, px.w, px.h);
            e.set_color(ct);
            e.set_depth(depth);
            e.set_compression(png::Compression::Default);
            let mut w = e.write_header().map_err(fail("PNG encode"))?;
            w.write_image_data(&px.data).map_err(fail("PNG encode"))?;
            w.finish().map_err(fail("PNG encode"))?;
        }
        "image/jpeg" => {
            let (layout, data) = narrow(px);
            if px.layout.wide() { notes.push("16-bit samples reduced to 8-bit".into()); }
            let (ct, buf): (jpeg_encoder::ColorType, std::borrow::Cow<[u8]>) = match layout {
                Layout::L8 => (jpeg_encoder::ColorType::Luma, data),
                Layout::Rgb8 => (jpeg_encoder::ColorType::Rgb, data),
                Layout::La8 => {
                    notes.push("alpha composited over white (JPEG has no alpha)".into());
                    (jpeg_encoder::ColorType::Luma, flatten(&data, 2).into())
                }
                Layout::Rgba8 => {
                    notes.push("alpha composited over white (JPEG has no alpha)".into());
                    (jpeg_encoder::ColorType::Rgb, flatten(&data, 4).into())
                }
                _ => unreachable!("narrowed"),
            };
            let (w, h) = (u16::try_from(px.w), u16::try_from(px.h));
            let (Ok(w), Ok(h)) = (w, h) else { return Err(Failure::Failed("JPEG output larger than 65535".into())) };
            jpeg_encoder::Encoder::new(&mut out, JPEG_QUALITY).encode(&buf, w, h, ct).map_err(fail("JPEG encode"))?;
            notes.push(format!("encoded as baseline JPEG, quality {JPEG_QUALITY}; pixels are not bit-identical"));
        }
        "image/webp" => {
            let (layout, data) = narrow(px);
            if px.layout.wide() { notes.push("16-bit samples reduced to 8-bit".into()); }
            let ct = match layout {
                Layout::L8 => image_webp::ColorType::L8,
                Layout::La8 => image_webp::ColorType::La8,
                Layout::Rgb8 => image_webp::ColorType::Rgb8,
                Layout::Rgba8 => image_webp::ColorType::Rgba8,
                _ => unreachable!("narrowed"),
            };
            image_webp::WebPEncoder::new(&mut out).encode(&data, px.w, px.h, ct).map_err(fail("WebP encode"))?;
            notes.push("encoded as lossless WebP (VP8L)".into());
        }
        other => return Err(Failure::Failed(format!("no encoder for {other}"))),
    }
    Ok(Artifact { bytes: out, mime, w: px.w, h: px.h, notes })
}

/// Full transform: decode, encode to the policy's output format.
pub fn run(ctx: &mut Ctx, policy: &Policy, mime: &'static str, d: &[u8]) -> Result<Artifact, Failure> {
    // A decoder error means the file violates its format beyond what the header walk checks
    // (e.g. corrupt entropy-coded data): that is a structural rejection, not an engine failure.
    let px = decode(ctx, policy, mime, d).map_err(|e| match e {
        Failure::Failed(why) => Failure::Abort(Abort::Malformed(why)),
        other => other,
    })?;
    let Decoded { px, lossy } = px;
    let o = if policy.images.apply_orientation { crate::images::orientation(mime, d).unwrap_or(1) } else { 1 };
    let px = orient(px, o);
    ctx.check_now()?;
    let alpha = matches!(px.layout, Layout::La8 | Layout::Rgba8 | Layout::La16 | Layout::Rgba16);
    let target = output_mime(policy, mime, lossy, alpha);
    let mut a = encode(&px, target)?;
    if o != 1 { a.notes.insert(0, format!("EXIF orientation {o} applied to the pixels")); }
    if mime == "image/webp" && lossy && policy.images.output_format == "same" {
        a.notes.insert(0, if target == "image/png" {
            "lossy WebP with alpha re-encoded as lossless PNG, transparency kept (spec 0.1.3)".into()
        } else {
            "lossy WebP source re-encoded as JPEG (spec 0.1.2)".into()
        });
    }
    ctx.check_now()?;
    Ok(a)
}
