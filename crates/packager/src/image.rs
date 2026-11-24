//! RGBA images and high-quality resizing (replaces `sips`), plus icon generation from one source PNG.

use std::path::Path;

use crate::Result;
use crate::error::IoContext;
use crate::format::{icns, ico, png};

/// An 8-bit RGBA image with straight (non-premultiplied) alpha, rows top to bottom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// `width * height * 4` bytes.
    pub rgba: Vec<u8>,
}

impl Image {
    /// A transparent image.
    pub fn new(width: u32, height: u32) -> Self {
        Image { width, height, rgba: vec![0; width as usize * height as usize * 4] }
    }

    /// Reads a PNG file.
    pub fn open_png(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        png::decode(&std::fs::read(path).at(path)?)
    }

    /// Encodes as PNG.
    pub fn to_png(&self) -> Vec<u8> {
        png::encode(self)
    }

    /// Resizes with a separable Lanczos-3 filter in premultiplied linear-ish space
    /// (premultiplied so transparent edges don't bleed dark fringes).
    pub fn resize(&self, width: u32, height: u32) -> Image {
        if width == self.width && height == self.height {
            return self.clone();
        }
        // Premultiply into f32.
        let src: Vec<[f32; 4]> = self
            .rgba
            .chunks(4)
            .map(|p| {
                let a = p[3] as f32 / 255.0;
                [p[0] as f32 * a, p[1] as f32 * a, p[2] as f32 * a, p[3] as f32]
            })
            .collect();
        let tmp = resample_axis(&src, self.width as usize, self.height as usize, width as usize, true);
        let dst = resample_axis(&tmp, width as usize, self.height as usize, height as usize, false);
        let mut out = Image::new(width, height);
        for (o, p) in out.rgba.chunks_mut(4).zip(dst) {
            let a = p[3].clamp(0.0, 255.0);
            if a < 0.5 {
                o.copy_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            let inv = 255.0 / a;
            o[0] = (p[0] * inv).round().clamp(0.0, 255.0) as u8;
            o[1] = (p[1] * inv).round().clamp(0.0, 255.0) as u8;
            o[2] = (p[2] * inv).round().clamp(0.0, 255.0) as u8;
            o[3] = a.round() as u8;
        }
        out
    }
}

fn lanczos3(x: f32) -> f32 {
    let x = x.abs();
    if x < 1e-6 {
        return 1.0;
    }
    if x >= 3.0 {
        return 0.0;
    }
    let px = std::f32::consts::PI * x;
    3.0 * px.sin() * (px / 3.0).sin() / (px * px)
}

/// Resamples along x (`horizontal`) or y. `w`/`h` are the source size; `n` the new length.
fn resample_axis(src: &[[f32; 4]], w: usize, h: usize, n: usize, horizontal: bool) -> Vec<[f32; 4]> {
    let old = if horizontal { w } else { h };
    let scale = old as f32 / n as f32;
    let support = 3.0 * scale.max(1.0);
    let filter_scale = scale.max(1.0);
    // Precompute weights per output position.
    let weights: Vec<(usize, Vec<f32>)> = (0..n)
        .map(|i| {
            let center = (i as f32 + 0.5) * scale;
            let lo = (center - support).floor().max(0.0) as usize;
            let hi = ((center + support).ceil() as usize).min(old);
            let mut ws: Vec<f32> = (lo..hi).map(|j| lanczos3((j as f32 + 0.5 - center) / filter_scale)).collect();
            let sum: f32 = ws.iter().sum();
            if sum.abs() > 1e-6 {
                ws.iter_mut().for_each(|x| *x /= sum);
            }
            (lo, ws)
        })
        .collect();
    let (ow, oh) = if horizontal { (n, h) } else { (w, n) };
    let mut out = vec![[0f32; 4]; ow * oh];
    for y in 0..oh {
        for x in 0..ow {
            let (lo, ws) = &weights[if horizontal { x } else { y }];
            let mut acc = [0f32; 4];
            for (k, wt) in ws.iter().enumerate() {
                let s = if horizontal { src[y * w + lo + k] } else { src[(lo + k) * w + x] };
                for c in 0..4 {
                    acc[c] += s[c] * wt;
                }
            }
            out[y * ow + x] = acc;
        }
    }
    out
}

/// An `.icns` with every size macOS uses, generated from one (ideally 1024×1024) PNG.
pub fn icns_from_png(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    Ok(icns::from_image(&Image::open_png(path)?))
}

/// An `.ico` with the sizes Windows uses, generated from one PNG.
pub fn ico_from_png(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    Ok(ico::from_image(&Image::open_png(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resize_keeps_solid_color() {
        let mut img = Image::new(64, 64);
        for p in img.rgba.chunks_mut(4) {
            p.copy_from_slice(&[200, 100, 50, 255]);
        }
        for (w, h) in [(16, 16), (128, 128), (10, 30)] {
            let r = img.resize(w, h);
            assert!(r.rgba.chunks(4).all(|p| p == [200, 100, 50, 255]), "{w}x{h}");
        }
    }
}
