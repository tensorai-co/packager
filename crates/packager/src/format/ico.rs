//! Windows icons (`.ico`): what the `.exe`, MSI shortcuts and Add/Remove Programs show. The
//! 256 px image is stored as PNG (Vista and later); smaller sizes as 32-bit BMPs with an AND
//! mask, which every consumer (including old shell code paths) reads.

use crate::image::Image;
use crate::{Error, Result};

/// The sizes written by [`from_image`], as Windows' shell and installers request them.
pub const SIZES: [u32; 6] = [16, 24, 32, 48, 64, 256];

/// One image in an icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconImage {
    /// Width in pixels (1–256).
    pub width: u32,
    /// Height in pixels (1–256).
    pub height: u32,
    /// Bits per pixel.
    pub bit_count: u16,
    /// The image data: a PNG file, or a BMP `BITMAPINFOHEADER` + pixels + AND mask.
    pub data: Vec<u8>,
}

/// A 32-bit DIB (bottom-up BGRA, then a 1-bit AND mask) as icons store it.
fn dib(img: &Image) -> Vec<u8> {
    let (w, h) = (img.width as usize, img.height as usize);
    let mask_stride = w.div_ceil(32) * 4;
    let mut out = Vec::with_capacity(40 + w * h * 4 + mask_stride * h);
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(w as i32).to_le_bytes());
    out.extend_from_slice(&((h * 2) as i32).to_le_bytes()); // XOR image + AND mask
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    out.extend_from_slice(&((w * h * 4 + mask_stride * h) as u32).to_le_bytes());
    out.extend_from_slice(&[0; 16]); // resolution, palette
    for y in (0..h).rev() {
        for x in 0..w {
            let p = &img.rgba[(y * w + x) * 4..(y * w + x) * 4 + 4];
            out.extend_from_slice(&[p[2], p[1], p[0], p[3]]);
        }
    }
    for y in (0..h).rev() {
        let mut row = vec![0u8; mask_stride];
        for x in 0..w {
            if img.rgba[(y * w + x) * 4 + 3] == 0 {
                row[x / 8] |= 0x80 >> (x % 8);
            }
        }
        out.extend_from_slice(&row);
    }
    out
}

/// The images of an icon for `img` at each of `sizes`.
pub fn images(img: &Image, sizes: &[u32]) -> Vec<IconImage> {
    sizes
        .iter()
        .map(|&s| {
            let r = img.resize(s, s);
            let data = if s >= 256 { r.to_png() } else { dib(&r) };
            IconImage { width: s, height: s, bit_count: 32, data }
        })
        .collect()
}

/// An `.ico` file for `img` at the standard [`SIZES`].
pub fn from_image(img: &Image) -> Vec<u8> {
    write(&images(img, &SIZES))
}

fn dim(v: u32) -> u8 {
    if v >= 256 { 0 } else { v as u8 }
}

/// Writes an `.ico` file.
pub fn write(images: &[IconImage]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len();
    for i in images {
        out.extend_from_slice(&[dim(i.width), dim(i.height), 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&i.bit_count.to_le_bytes());
        out.extend_from_slice(&(i.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += i.data.len();
    }
    for i in images {
        out.extend_from_slice(&i.data);
    }
    out
}

/// The `GRPICONDIR` of an icon group resource (`RT_GROUP_ICON`) whose images are the
/// `RT_ICON` resources `first_id`, `first_id + 1`…
pub fn group_directory(images: &[IconImage], first_id: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    for (k, i) in images.iter().enumerate() {
        out.extend_from_slice(&[dim(i.width), dim(i.height), 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&i.bit_count.to_le_bytes());
        out.extend_from_slice(&(i.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(first_id + k as u16).to_le_bytes());
    }
    out
}

/// Reads an `.ico` file.
pub fn read(data: &[u8]) -> Result<Vec<IconImage>> {
    let bad = |m: &str| Error::malformed("ico", m);
    if data.len() < 6 || data[..4] != [0, 0, 1, 0] {
        return Err(bad("not an icon file"));
    }
    let n = u16::from_le_bytes([data[4], data[5]]) as usize;
    let mut out = Vec::with_capacity(n);
    for k in 0..n {
        let e = data.get(6 + 16 * k..22 + 16 * k).ok_or_else(|| bad("truncated directory"))?;
        let size = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as usize;
        let off = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as usize;
        let img = data.get(off..off + size).ok_or_else(|| bad("image out of range"))?;
        let d = |b: u8| if b == 0 { 256 } else { u32::from(b) };
        out.push(IconImage { width: d(e[0]), height: d(e[1]), bit_count: u16::from_le_bytes([e[6], e[7]]), data: img.to_vec() });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut img = Image::new(64, 64);
        for (i, p) in img.rgba.chunks_mut(4).enumerate() {
            p.copy_from_slice(&[i as u8, 0, 200, if i % 7 == 0 { 0 } else { 255 }]);
        }
        let ico = from_image(&img);
        let back = read(&ico).unwrap();
        assert_eq!(back.iter().map(|i| i.width).collect::<Vec<_>>(), SIZES.to_vec());
        assert!(back[5].data.starts_with(b"\x89PNG"));
        assert_eq!(u32::from_le_bytes(back[0].data[..4].try_into().unwrap()), 40);
        // 16x16: header, 16*16*4 pixels, 16 rows of a 4-byte mask.
        assert_eq!(back[0].data.len(), 40 + 1024 + 64);
        let g = group_directory(&back, 1);
        assert_eq!(g.len(), 6 + 14 * 6);
    }
}
