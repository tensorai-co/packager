//! Apple icon files (`.icns`): the same entries, in the same order, as `iconutil` writes —
//! PNG for most sizes, RLE-compressed ARGB for 16 and 32 px.

use crate::image::Image;
use crate::{Error, Result};

/// (type, pixel size, ARGB instead of PNG), in `iconutil`'s order.
const ENTRIES: [(&[u8; 4], u32, bool); 10] = [
    (b"ic12", 64, false),   // 32@2x
    (b"ic07", 128, false),  // 128
    (b"ic13", 256, false),  // 128@2x
    (b"ic08", 256, false),  // 256
    (b"ic04", 16, true),    // 16
    (b"ic14", 512, false),  // 256@2x
    (b"ic09", 512, false),  // 512
    (b"ic05", 32, true),    // 32
    (b"ic10", 1024, false), // 512@2x
    (b"ic11", 32, false),   // 16@2x
];

/// Builds an `.icns` from one image, resizing to each size (upscaling if the source is small).
pub fn from_image(src: &Image) -> Vec<u8> {
    let mut cache: Vec<(u32, Image)> = Vec::new();
    let mut body = Vec::new();
    for (ty, size, argb) in ENTRIES {
        let img = match cache.iter().find(|(s, _)| *s == size) {
            Some((_, i)) => i.clone(),
            None => {
                let i = src.resize(size, size);
                cache.push((size, i.clone()));
                i
            }
        };
        let data = if argb { encode_argb(&img) } else { img.to_png() };
        body.extend_from_slice(ty);
        body.extend_from_slice(&(data.len() as u32 + 8).to_be_bytes());
        body.extend_from_slice(&data);
    }
    let mut out = b"icns".to_vec();
    out.extend_from_slice(&(body.len() as u32 + 8).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn encode_argb(img: &Image) -> Vec<u8> {
    let mut out = b"ARGB".to_vec();
    for ch in [3usize, 0, 1, 2] {
        let plane: Vec<u8> = img.rgba.chunks(4).map(|p| p[ch]).collect();
        packbits(&plane, &mut out);
    }
    out
}

/// The icns flavor of PackBits: `0..=127` copies n+1 literal bytes, `128..=255` repeats the next
/// byte n-125 times (3 to 130).
fn packbits(data: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < data.len() {
        let mut run = 1;
        while i + run < data.len() && data[i + run] == data[i] && run < 130 {
            run += 1;
        }
        if run >= 3 {
            out.push((run + 125) as u8);
            out.push(data[i]);
            i += run;
            continue;
        }
        let start = i;
        while i < data.len() && i - start < 128 {
            if i + 2 < data.len() && data[i] == data[i + 1] && data[i] == data[i + 2] {
                break;
            }
            i += 1;
        }
        out.push((i - start - 1) as u8);
        out.extend_from_slice(&data[start..i]);
    }
}

fn unpackbits(data: &[u8], n: usize, p: &mut usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let c = *data.get(*p).ok_or_else(|| Error::malformed("icns", "truncated ARGB data"))? as usize;
        *p += 1;
        if c < 128 {
            let s = data.get(*p..*p + c + 1).ok_or_else(|| Error::malformed("icns", "truncated ARGB data"))?;
            out.extend_from_slice(s);
            *p += c + 1;
        } else {
            let b = *data.get(*p).ok_or_else(|| Error::malformed("icns", "truncated ARGB data"))?;
            *p += 1;
            out.extend(std::iter::repeat_n(b, c - 125));
        }
    }
    out.truncate(n);
    Ok(out)
}

/// One decoded entry of an `.icns`.
#[derive(Debug, Clone)]
pub struct IconEntry {
    /// The four-character type (`ic10`…).
    pub kind: [u8; 4],
    /// The image, if the entry is PNG or ARGB.
    pub image: Option<Image>,
    /// The raw entry data.
    pub data: Vec<u8>,
}

/// Reads the entries of an `.icns`.
pub fn read(data: &[u8]) -> Result<Vec<IconEntry>> {
    if data.len() < 8 || &data[..4] != b"icns" {
        return Err(Error::malformed("icns", "missing `icns` header"));
    }
    let total = (u32::from_be_bytes(data[4..8].try_into().unwrap_or_default()) as usize).min(data.len());
    let mut p = 8;
    let mut out = Vec::new();
    while p + 8 <= total {
        let kind: [u8; 4] = data[p..p + 4].try_into().unwrap_or_default();
        let len = u32::from_be_bytes(data[p + 4..p + 8].try_into().unwrap_or_default()) as usize;
        if len < 8 || p + len > total {
            return Err(Error::malformed("icns", "entry out of range"));
        }
        let body = data[p + 8..p + len].to_vec();
        let image = if body.starts_with(b"\x89PNG") {
            Some(crate::format::png::decode(&body)?)
        } else if body.starts_with(b"ARGB") {
            let size = ENTRIES.iter().find(|e| *e.0 == kind).map(|e| e.1).unwrap_or(0);
            let n = (size * size) as usize;
            let mut q = 4;
            let planes = [unpackbits(&body, n, &mut q)?, unpackbits(&body, n, &mut q)?, unpackbits(&body, n, &mut q)?, unpackbits(&body, n, &mut q)?];
            let mut img = Image::new(size, size);
            for (i, px) in img.rgba.chunks_mut(4).enumerate().take(n) {
                px.copy_from_slice(&[planes[1][i], planes[2][i], planes[3][i], planes[0][i]]);
            }
            Some(img)
        } else {
            None
        };
        out.push(IconEntry { kind, image, data: body });
        p += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut src = Image::new(64, 64);
        for (i, p) in src.rgba.chunks_mut(4).enumerate() {
            p.copy_from_slice(&[(i % 64 * 4) as u8, (i / 64 * 4) as u8, 128, if i % 7 == 0 { 0 } else { 255 }]);
        }
        let icns = from_image(&src);
        let entries = read(&icns).unwrap();
        assert_eq!(entries.len(), 10);
        let small = entries.iter().find(|e| &e.kind == b"ic04").unwrap().image.as_ref().unwrap();
        assert_eq!(small, &src.resize(16, 16));
    }
}
