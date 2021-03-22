// http://cr.yp.to/mac/poly1305-20050329.pdf

use std::convert::TryInto;

use byteorder::{ByteOrder, LittleEndian};

#[derive(Clone, Default)]
struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305 {
    pub fn new(r: &[u8; 16], s: &[u8; 16]) -> Self {
        let mut poly = Self::default();
        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        poly.r[0] = (u32::from_le_bytes(r[..4].try_into().unwrap())) & 0x3ff_ffff;
        poly.r[1] = (u32::from_le_bytes(r[3..7].try_into().unwrap()) >> 2) & 0x3ff_ff03;
        poly.r[2] = (u32::from_le_bytes(r[6..10].try_into().unwrap()) >> 4) & 0x3ff_c0ff;
        poly.r[3] = (u32::from_le_bytes(r[9..13].try_into().unwrap()) >> 6) & 0x3f0_3fff;
        poly.r[4] = (u32::from_le_bytes(r[12..16].try_into().unwrap()) >> 8) & 0x00f_ffff;

        LittleEndian::read_u32_into(s, &mut poly.pad);

        poly
    }
    pub fn compute_block(&mut self, block: &[u8; 16], partial: bool) {
        let hibit = if partial { 0 } else { 1 << 24 };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        // h += m
        h0 += (u32::from_le_bytes(block[0..4].try_into().unwrap())) & 0x3ff_ffff;
        h1 += (u32::from_le_bytes(block[3..7].try_into().unwrap()) >> 2) & 0x3ff_ffff;
        h2 += (u32::from_le_bytes(block[6..10].try_into().unwrap()) >> 4) & 0x3ff_ffff;
        h3 += (u32::from_le_bytes(block[9..13].try_into().unwrap()) >> 6) & 0x3ff_ffff;
        h4 += (u32::from_le_bytes(block[12..16].try_into().unwrap()) >> 8) | hibit;

        // h *= r
        let d0 = (u64::from(h0) * u64::from(r0))
            + (u64::from(h1) * u64::from(s4))
            + (u64::from(h2) * u64::from(s3))
            + (u64::from(h3) * u64::from(s2))
            + (u64::from(h4) * u64::from(s1));

        let mut d1 = (u64::from(h0) * u64::from(r1))
            + (u64::from(h1) * u64::from(r0))
            + (u64::from(h2) * u64::from(s4))
            + (u64::from(h3) * u64::from(s3))
            + (u64::from(h4) * u64::from(s2));

        let mut d2 = (u64::from(h0) * u64::from(r2))
            + (u64::from(h1) * u64::from(r1))
            + (u64::from(h2) * u64::from(r0))
            + (u64::from(h3) * u64::from(s4))
            + (u64::from(h4) * u64::from(s3));

        let mut d3 = (u64::from(h0) * u64::from(r3))
            + (u64::from(h1) * u64::from(r2))
            + (u64::from(h2) * u64::from(r1))
            + (u64::from(h3) * u64::from(r0))
            + (u64::from(h4) * u64::from(s4));

        let mut d4 = (u64::from(h0) * u64::from(r4))
            + (u64::from(h1) * u64::from(r3))
            + (u64::from(h2) * u64::from(r2))
            + (u64::from(h3) * u64::from(r1))
            + (u64::from(h4) * u64::from(r0));

        // (partial) h %= p
        let mut c: u32;
        c = (d0 >> 26) as u32;
        h0 = d0 as u32 & 0x3ff_ffff;
        d1 += u64::from(c);

        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & 0x3ff_ffff;
        d2 += u64::from(c);

        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & 0x3ff_ffff;
        d3 += u64::from(c);

        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & 0x3ff_ffff;
        d4 += u64::from(c);

        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & 0x3ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    /// Finalize output producing a [`Tag`]
    pub fn finalize(&mut self, ret: &mut [u8; 16]) {
        // fully carry h
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c: u32;
        c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += c;

        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += c;

        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += c;

        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ff_ffff;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ff_ffff;

        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ff_ffff;

        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ff_ffff;

        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % (2^128)
        h0 |= h1 << 26;
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);

        // h = mac = (h + pad) % (2^128)
        let mut f: u64;
        f = u64::from(h0) + u64::from(self.pad[0]);
        h0 = f as u32;

        f = u64::from(h1) + u64::from(self.pad[1]) + (f >> 32);
        h1 = f as u32;

        f = u64::from(h2) + u64::from(self.pad[2]) + (f >> 32);
        h2 = f as u32;

        f = u64::from(h3) + u64::from(self.pad[3]) + (f >> 32);
        h3 = f as u32;

        ret[0..4].copy_from_slice(&h0.to_le_bytes());
        ret[4..8].copy_from_slice(&h1.to_le_bytes());
        ret[8..12].copy_from_slice(&h2.to_le_bytes());
        ret[12..16].copy_from_slice(&h3.to_le_bytes());
    }
}

pub fn authenticate(msg: &[u8], r: &[u8; 16], s: &[u8; 16]) -> [u8; 16] {
    let mut ret = [0u8; 16];
    let mut p = Poly1305::new(r, s);
    for block in msg.chunks(16) {
        if block.len() == 16 {
            p.compute_block(block.try_into().unwrap(), false);
        } else {
            let mut filled_block = [0u8; 16];
            filled_block[..block.len()].copy_from_slice(block);
            filled_block[block.len()] = 1;
            p.compute_block(&filled_block, true);
        }
    }
    p.finalize(&mut ret);
    return ret;
}

#[cfg(test)]
mod test {
    #[test]
    fn test_poly1305_examples() {
        // from Appendix B of reference paper
        static VALUES: &'static [(&'static [u8], [u8; 16], [u8; 16], [u8; 16])] = &[
            // (msg, r, aes, result)
            (
                &[0xf3, 0xf6],
                [
                    0x85, 0x1f, 0xc4, 0x0c, 0x34, 0x67, 0xac, 0x0b, 0xe0, 0x5c, 0xc2, 0x04, 0x04,
                    0xf3, 0xf7, 0x00,
                ],
                [
                    0x58, 0x0b, 0x3b, 0x0f, 0x94, 0x47, 0xbb, 0x1e, 0x69, 0xd0, 0x95, 0xb5, 0x92,
                    0x8b, 0x6d, 0xbc,
                ],
                [
                    0xf4, 0xc6, 0x33, 0xc3, 0x04, 0x4f, 0xc1, 0x45, 0xf8, 0x4f, 0x33, 0x5c, 0xb8,
                    0x19, 0x53, 0xde,
                ],
            ),
            (
                &[],
                [
                    0xa0, 0xf3, 0x08, 0x00, 0x00, 0xf4, 0x64, 0x00, 0xd0, 0xc7, 0xe9, 0x07, 0x6c,
                    0x83, 0x44, 0x03,
                ],
                [
                    0xdd, 0x3f, 0xab, 0x22, 0x51, 0xf1, 0x1a, 0xc7, 0x59, 0xf0, 0x88, 0x71, 0x29,
                    0xcc, 0x2e, 0xe7,
                ],
                [
                    0xdd, 0x3f, 0xab, 0x22, 0x51, 0xf1, 0x1a, 0xc7, 0x59, 0xf0, 0x88, 0x71, 0x29,
                    0xcc, 0x2e, 0xe7,
                ],
            ),
            (
                &[
                    0x66, 0x3c, 0xea, 0x19, 0x0f, 0xfb, 0x83, 0xd8, 0x95, 0x93, 0xf3, 0xf4, 0x76,
                    0xb6, 0xbc, 0x24, 0xd7, 0xe6, 0x79, 0x10, 0x7e, 0xa2, 0x6a, 0xdb, 0x8c, 0xaf,
                    0x66, 0x52, 0xd0, 0x65, 0x61, 0x36,
                ],
                [
                    0x48, 0x44, 0x3d, 0x0b, 0xb0, 0xd2, 0x11, 0x09, 0xc8, 0x9a, 0x10, 0x0b, 0x5c,
                    0xe2, 0xc2, 0x08,
                ],
                [
                    0x83, 0x14, 0x9c, 0x69, 0xb5, 0x61, 0xdd, 0x88, 0x29, 0x8a, 0x17, 0x98, 0xb1,
                    0x07, 0x16, 0xef,
                ],
                [
                    0x0e, 0xe1, 0xc1, 0x6b, 0xb7, 0x3f, 0x0f, 0x4f, 0xd1, 0x98, 0x81, 0x75, 0x3c,
                    0x01, 0xcd, 0xbe,
                ],
            ),
            (
                &[
                    0xab, 0x08, 0x12, 0x72, 0x4a, 0x7f, 0x1e, 0x34, 0x27, 0x42, 0xcb, 0xed, 0x37,
                    0x4d, 0x94, 0xd1, 0x36, 0xc6, 0xb8, 0x79, 0x5d, 0x45, 0xb3, 0x81, 0x98, 0x30,
                    0xf2, 0xc0, 0x44, 0x91, 0xfa, 0xf0, 0x99, 0x0c, 0x62, 0xe4, 0x8b, 0x80, 0x18,
                    0xb2, 0xc3, 0xe4, 0xa0, 0xfa, 0x31, 0x34, 0xcb, 0x67, 0xfa, 0x83, 0xe1, 0x58,
                    0xc9, 0x94, 0xd9, 0x61, 0xc4, 0xcb, 0x21, 0x09, 0x5c, 0x1b, 0xf9,
                ],
                [
                    0x12, 0x97, 0x6a, 0x08, 0xc4, 0x42, 0x6d, 0x0c, 0xe8, 0xa8, 0x24, 0x07, 0xc4,
                    0xf4, 0x82, 0x07,
                ],
                [
                    0x80, 0xf8, 0xc2, 0x0a, 0xa7, 0x12, 0x02, 0xd1, 0xe2, 0x91, 0x79, 0xcb, 0xcb,
                    0x55, 0x5a, 0x57,
                ],
                [
                    0x51, 0x54, 0xad, 0x0d, 0x2c, 0xb2, 0x6e, 0x01, 0x27, 0x4f, 0xc5, 0x11, 0x48,
                    0x49, 0x1f, 0x1b,
                ],
            ),
        ];

        for &(msg, ref r, ref aes, ref expected) in VALUES.iter() {
            let output = super::authenticate(msg, r, aes);
            assert_eq!(&output[..], &expected[..]);
        }
    }
}
