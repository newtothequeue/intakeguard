//! Minimal, bounds-checked TIFF/EXIF reader: only answers "does IFD0 point at a GPS IFD with entries?".

fn rd16(d: &[u8], o: usize, le: bool) -> Option<u16> {
    let b = d.get(o..o.checked_add(2)?)?;
    Some(if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
}

fn rd32(d: &[u8], o: usize, le: bool) -> Option<u32> {
    let b = d.get(o..o.checked_add(4)?)?;
    let a = [b[0], b[1], b[2], b[3]];
    Some(if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
}

/// IFD0 Orientation (0x0112) if present and valid (1..=8).
pub fn orientation(tiff: &[u8]) -> Option<u16> {
    let le = match tiff.get(0..4)? {
        b"II*\0" => true,
        b"MM\0*" => false,
        _ => return None,
    };
    let ifd0 = rd32(tiff, 4, le)? as usize;
    let n = rd16(tiff, ifd0, le)? as usize;
    if n > 1024 { return None; }
    for i in 0..n {
        let e = ifd0 + 2 + i * 12;
        if rd16(tiff, e, le)? == 0x0112 {
            // SHORT, count 1: the value sits in the first two bytes of the value field.
            if rd16(tiff, e + 2, le)? != 3 { return None; }
            let v = rd16(tiff, e + 8, le)?;
            return (1..=8).contains(&v).then_some(v);
        }
    }
    None
}

/// `tiff` starts at the TIFF header ("II*\0" or "MM\0*").
/// Returns Some(true) if a GPSInfo pointer to a non-empty IFD is present, Some(false) if not,
/// None if the structure can't be read (callers treat unreadable EXIF as metadata present).
pub fn has_gps(tiff: &[u8]) -> Option<bool> {
    let le = match tiff.get(0..4)? {
        b"II*\0" => true,
        b"MM\0*" => false,
        _ => return None,
    };
    let ifd0 = rd32(tiff, 4, le)? as usize;
    let n = rd16(tiff, ifd0, le)? as usize;
    if n > 1024 { return None; }
    for i in 0..n {
        let e = ifd0 + 2 + i * 12;
        if rd16(tiff, e, le)? == 0x8825 {
            let gps = rd32(tiff, e + 8, le)? as usize;
            return Some(rd16(tiff, gps, le).map(|c| c > 0).unwrap_or(true));
        }
    }
    Some(false)
}
