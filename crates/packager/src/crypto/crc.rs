//! Checksums: CRC-32 (zlib/gzip/PNG/UDIF), Adler-32 (zlib), and the POSIX `cksum` CRC (`Bom`).

const fn make_table(poly: u32, reflected: bool) -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = if reflected { i as u32 } else { (i as u32) << 24 };
        let mut k = 0;
        while k < 8 {
            c = if reflected {
                if c & 1 != 0 { poly ^ (c >> 1) } else { c >> 1 }
            } else if c & 0x8000_0000 != 0 {
                (c << 1) ^ poly
            } else {
                c << 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC32_TABLE: [u32; 256] = make_table(0xEDB8_8320, true);
static CKSUM_TABLE: [u32; 256] = make_table(0x04C1_1DB7, false);

/// Streaming CRC-32 (IEEE 802.3, reflected), as used by zlib, gzip, PNG and UDIF.
#[derive(Clone, Copy, Default)]
pub struct Crc32(u32);

impl Crc32 {
    /// A fresh CRC.
    pub fn new() -> Self {
        Crc32(0)
    }
    /// Feeds `data`.
    pub fn update(&mut self, data: &[u8]) {
        let mut c = !self.0;
        for &b in data {
            c = CRC32_TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
        }
        self.0 = !c;
    }
    /// The checksum so far.
    pub fn value(&self) -> u32 {
        self.0
    }
}

/// CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.value()
}

/// Adler-32 of `data`, continuing from `adler` (start with 1).
pub fn adler32(adler: u32, data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (adler & 0xffff, adler >> 16);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// The POSIX `cksum` checksum of `data` (CRC-32/CKSUM with the length appended).
pub fn posix_cksum(data: &[u8]) -> u32 {
    let mut c = 0u32;
    let step = |c: u32, b: u8| (c << 8) ^ CKSUM_TABLE[(((c >> 24) as u8) ^ b) as usize];
    for &b in data {
        c = step(c, b);
    }
    let mut len = data.len() as u64;
    while len != 0 {
        c = step(c, len as u8);
        len >>= 8;
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(adler32(1, b"Wikipedia"), 0x11E6_0398);
        // `printf 123456789 | cksum` → 930766865
        assert_eq!(posix_cksum(b"123456789"), 930_766_865);
        // `printf '' | cksum` → 4294967295
        assert_eq!(posix_cksum(b""), 4_294_967_295);
    }
}
