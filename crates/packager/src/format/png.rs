//! PNG decode (every bit depth, color type and Adam7 interlacing, to RGBA8) and encode (RGBA8).

use crate::compress::{Level, unzlib, zlib};
use crate::crypto::crc::Crc32;
use crate::image::Image;
use crate::{Error, Result};

const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

fn bad(m: impl Into<String>) -> Error {
    Error::malformed("png", m)
}

/// Decodes a PNG into 8-bit RGBA (straight alpha).
pub fn decode(data: &[u8]) -> Result<Image> {
    if !data.starts_with(SIGNATURE) {
        return Err(bad("missing PNG signature"));
    }
    let mut p = 8;
    let mut ihdr = None;
    let mut palette: Vec<[u8; 4]> = Vec::new();
    let mut trns: Option<Vec<u8>> = None;
    let mut idat = Vec::new();
    while p + 8 <= data.len() {
        let len = u32::from_be_bytes(data[p..p + 4].try_into().unwrap_or_default()) as usize;
        let ty = &data[p + 4..p + 8];
        let body = data.get(p + 8..p + 8 + len).ok_or_else(|| bad("truncated chunk"))?;
        p += 12 + len;
        match ty {
            b"IHDR" => {
                if body.len() != 13 {
                    return Err(bad("bad IHDR"));
                }
                ihdr = Some((u32::from_be_bytes(body[0..4].try_into().unwrap_or_default()), u32::from_be_bytes(body[4..8].try_into().unwrap_or_default()), body[8], body[9], body[12]));
            }
            b"PLTE" => palette = body.chunks(3).filter(|c| c.len() == 3).map(|c| [c[0], c[1], c[2], 255]).collect(),
            b"tRNS" => trns = Some(body.to_vec()),
            b"IDAT" => idat.extend_from_slice(body),
            b"IEND" => break,
            _ => {}
        }
    }
    let (w, h, depth, color, interlace) = ihdr.ok_or_else(|| bad("missing IHDR"))?;
    if w == 0 || h == 0 || w > 1 << 16 || h > 1 << 16 {
        return Err(bad(format!("unsupported size {w}x{h}")));
    }
    let channels = match color {
        0 => 1,
        2 => 3,
        3 => 1,
        4 => 2,
        6 => 4,
        _ => return Err(bad(format!("bad color type {color}"))),
    };
    let valid = match color {
        0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
        3 => matches!(depth, 1 | 2 | 4 | 8),
        _ => matches!(depth, 8 | 16),
    };
    if !valid {
        return Err(bad(format!("bad bit depth {depth} for color type {color}")));
    }
    if let Some(t) = &trns
        && color == 3
    {
        for (i, a) in t.iter().enumerate() {
            if let Some(e) = palette.get_mut(i) {
                e[3] = *a;
            }
        }
    }
    let raw = unzlib(&idat)?;
    let bpp_bits = channels * depth as usize;
    let mut out = vec![0u8; w as usize * h as usize * 4];
    let passes: &[(usize, usize, usize, usize)] = if interlace == 1 { &[(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)] } else { &[(0, 0, 1, 1)] };
    let mut off = 0;
    for &(x0, y0, dx, dy) in passes {
        let pw = (w as usize).saturating_sub(x0).div_ceil(dx);
        let ph = (h as usize).saturating_sub(y0).div_ceil(dy);
        if pw == 0 || ph == 0 {
            continue;
        }
        let stride = (pw * bpp_bits).div_ceil(8);
        let bpp = bpp_bits.div_ceil(8).max(1);
        let mut prev = vec![0u8; stride];
        for py in 0..ph {
            let filter = *raw.get(off).ok_or_else(|| bad("image data too short"))?;
            let line = raw.get(off + 1..off + 1 + stride).ok_or_else(|| bad("image data too short"))?;
            off += 1 + stride;
            let mut cur = line.to_vec();
            unfilter(filter, &mut cur, &prev, bpp)?;
            for px in 0..pw {
                let rgba = sample(&cur, px, depth, color, &palette, trns.as_deref());
                let (x, y) = (x0 + px * dx, y0 + py * dy);
                let o = (y * w as usize + x) * 4;
                out[o..o + 4].copy_from_slice(&rgba);
            }
            prev = cur;
        }
    }
    Ok(Image { width: w, height: h, rgba: out })
}

fn unfilter(filter: u8, cur: &mut [u8], prev: &[u8], bpp: usize) -> Result<()> {
    match filter {
        0 => {}
        1 => {
            for i in bpp..cur.len() {
                cur[i] = cur[i].wrapping_add(cur[i - bpp]);
            }
        }
        2 => {
            for i in 0..cur.len() {
                cur[i] = cur[i].wrapping_add(prev[i]);
            }
        }
        3 => {
            for i in 0..cur.len() {
                let a = if i >= bpp { cur[i - bpp] as u16 } else { 0 };
                cur[i] = cur[i].wrapping_add(((a + prev[i] as u16) / 2) as u8);
            }
        }
        4 => {
            for i in 0..cur.len() {
                let a = if i >= bpp { cur[i - bpp] } else { 0 };
                let c = if i >= bpp { prev[i - bpp] } else { 0 };
                cur[i] = cur[i].wrapping_add(paeth(a, prev[i], c));
            }
        }
        f => return Err(bad(format!("bad filter type {f}"))),
    }
    Ok(())
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i16 + b as i16 - c as i16;
    let (pa, pb, pc) = ((p - a as i16).abs(), (p - b as i16).abs(), (p - c as i16).abs());
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

fn sample(line: &[u8], x: usize, depth: u8, color: u8, palette: &[[u8; 4]], trns: Option<&[u8]>) -> [u8; 4] {
    let get = |i: usize| -> u16 {
        match depth {
            8 => line[i] as u16,
            16 => u16::from_be_bytes([line[i * 2], line[i * 2 + 1]]),
            d => {
                let bit = i * d as usize;
                let v = line[bit / 8] >> (8 - d as usize - bit % 8);
                (v & ((1 << d) - 1)) as u16
            }
        }
    };
    let to8 = |v: u16| -> u8 {
        match depth {
            16 => (v >> 8) as u8,
            8 => v as u8,
            d => (v as u32 * 255 / ((1u32 << d) - 1)) as u8,
        }
    };
    let trns16 = |i: usize| trns.and_then(|t| t.get(i * 2..i * 2 + 2)).map(|s| u16::from_be_bytes([s[0], s[1]]));
    match color {
        0 => {
            let v = get(x);
            let a = if trns16(0) == Some(v) { 0 } else { 255 };
            let g = to8(v);
            [g, g, g, a]
        }
        2 => {
            let (r, g, b) = (get(x * 3), get(x * 3 + 1), get(x * 3 + 2));
            let a = if trns16(0) == Some(r) && trns16(1) == Some(g) && trns16(2) == Some(b) { 0 } else { 255 };
            [to8(r), to8(g), to8(b), a]
        }
        3 => palette.get(get(x) as usize).copied().unwrap_or([0, 0, 0, 255]),
        4 => {
            let g = to8(get(x * 2));
            [g, g, g, to8(get(x * 2 + 1))]
        }
        _ => [to8(get(x * 4)), to8(get(x * 4 + 1)), to8(get(x * 4 + 2)), to8(get(x * 4 + 3))],
    }
}

/// The pixel density from the `pHYs` chunk, in dots per inch, when it's given in meters.
pub fn dpi(data: &[u8]) -> Option<f64> {
    if !data.starts_with(SIGNATURE) {
        return None;
    }
    let mut p = 8;
    while p + 8 <= data.len() {
        let len = u32::from_be_bytes(data[p..p + 4].try_into().ok()?) as usize;
        let ty = &data[p + 4..p + 8];
        if ty == b"pHYs" && len == 9 {
            let b = data.get(p + 8..p + 17)?;
            let x = u32::from_be_bytes(b[0..4].try_into().ok()?);
            return (b[8] == 1 && x > 0).then_some(x as f64 * 0.0254);
        }
        if ty == b"IDAT" || ty == b"IEND" {
            return None;
        }
        p += 12 + len;
    }
    None
}

/// How many pixels make one point when macOS draws this image: 2 for a 144-DPI (Retina) image,
/// 1 for 72 DPI or no density given.
pub fn backing_scale(data: &[u8]) -> u32 {
    dpi(data).map(|d| (d / 72.0).round().max(1.0) as u32).unwrap_or(1)
}

/// The same PNG with its density set to `dpi` (a `pHYs` chunk replaced or inserted after
/// `IHDR`); the image data is untouched.
pub fn with_dpi(data: &[u8], dpi: f64) -> Result<Vec<u8>> {
    if !data.starts_with(SIGNATURE) {
        return Err(bad("missing PNG signature"));
    }
    let ppm = (dpi / 0.0254).round() as u32;
    let mut phys = Vec::with_capacity(9);
    phys.extend_from_slice(&ppm.to_be_bytes());
    phys.extend_from_slice(&ppm.to_be_bytes());
    phys.push(1);
    let mut out = SIGNATURE.to_vec();
    let mut p = 8;
    while p + 12 <= data.len() {
        let len = u32::from_be_bytes(data[p..p + 4].try_into().unwrap_or_default()) as usize;
        let end = p + 12 + len;
        let ty: [u8; 4] = data[p + 4..p + 8].try_into().unwrap_or_default();
        let chunk_bytes = data.get(p..end).ok_or_else(|| bad("truncated chunk"))?;
        if &ty != b"pHYs" {
            out.extend_from_slice(chunk_bytes);
        }
        if &ty == b"IHDR" {
            chunk(&mut out, b"pHYs", &phys);
        }
        p = end;
    }
    Ok(out)
}

/// Encodes 8-bit RGBA as a PNG, choosing a filter per row (minimum sum of absolute differences).
pub fn encode(img: &Image) -> Vec<u8> {
    let w = img.width as usize;
    let stride = w * 4;
    let mut raw = Vec::with_capacity((stride + 1) * img.height as usize);
    let zero = vec![0u8; stride];
    let mut candidates = vec![vec![0u8; stride]; 5];
    for y in 0..img.height as usize {
        let cur = &img.rgba[y * stride..(y + 1) * stride];
        let prev = if y == 0 { &zero[..] } else { &img.rgba[(y - 1) * stride..y * stride] };
        for (f, out) in candidates.iter_mut().enumerate() {
            for i in 0..stride {
                let a = if i >= 4 { cur[i - 4] } else { 0 };
                let c = if i >= 4 { prev[i - 4] } else { 0 };
                let pred = match f {
                    0 => 0,
                    1 => a,
                    2 => prev[i],
                    3 => ((a as u16 + prev[i] as u16) / 2) as u8,
                    _ => paeth(a, prev[i], c),
                };
                out[i] = cur[i].wrapping_sub(pred);
            }
        }
        let best = (0..5).min_by_key(|&f| candidates[f].iter().map(|&b| (b as i8).unsigned_abs() as u64).sum::<u64>()).unwrap_or(0);
        raw.push(best as u8);
        raw.extend_from_slice(&candidates[best]);
    }
    let mut out = SIGNATURE.to_vec();
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&img.width.to_be_bytes());
    ihdr.extend_from_slice(&img.height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &zlib(&raw, Level::BEST));
    chunk(&mut out, b"IEND", &[]);
    out
}

fn chunk(out: &mut Vec<u8>, ty: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(ty);
    out.extend_from_slice(body);
    let mut c = Crc32::new();
    c.update(ty);
    c.update(body);
    out.extend_from_slice(&c.value().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut img = Image::new(37, 20);
        for (i, px) in img.rgba.chunks_mut(4).enumerate() {
            px.copy_from_slice(&[(i * 7) as u8, (i * 13) as u8, (i / 3) as u8, (255 - i % 256) as u8]);
        }
        let back = decode(&encode(&img)).unwrap();
        assert_eq!(back, img);
    }

    #[test]
    fn density() {
        let png = encode(&Image::new(4, 4));
        assert_eq!(backing_scale(&png), 1);
        let retina = with_dpi(&png, 144.0).unwrap();
        assert_eq!(backing_scale(&retina), 2);
        assert!((dpi(&retina).unwrap() - 144.0).abs() < 0.1);
        assert_eq!(decode(&retina).unwrap(), Image::new(4, 4));
        // Replacing keeps a single pHYs chunk.
        let again = with_dpi(&retina, 72.0).unwrap();
        assert_eq!(again.windows(4).filter(|w| w == b"pHYs").count(), 1);
        assert_eq!(backing_scale(&again), 1);
    }
}
