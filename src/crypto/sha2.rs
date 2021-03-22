// http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
// not seriously audited.
// no bit-level support. sorry

use std::num::Wrapping;

use byteorder::{BigEndian, ByteOrder};

static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

static INIT_VECTOR: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let len = msg.len();
    let mut msg = msg.to_vec(); // FIXME: do not allocate

    msg.push(0x80);
    let padding_len = ((64 - 8 - 1 as u64).wrapping_sub(len as u64)) & 63;
    for _ in 0..padding_len {
        msg.push(0);
    }

    let bitlen = (len as u64) * 8; // FIXME: disallow `len >= 2^64 / 8`
    for i in (0..8).rev() {
        let b = (bitlen >> (8 * i)) as u8;
        msg.push(b);
    }

    debug_assert_eq!(msg.len() % (512 / 8), 0);

    let nblk = msg.len() / (512 / 8);

    let mut val = INIT_VECTOR;

    for i in 0..nblk {
        let w = {
            let mut w = [0u32; 64];
            BigEndian::read_u32_into(&msg[i * 64..(i + 1) * 64], &mut w[..16]);

            for j in 16..64 {
                let wj15 = w[j - 15];
                let sig0 = wj15.rotate_right(7) ^ wj15.rotate_right(18) ^ (wj15 >> 3);

                let wj2 = w[j - 2];
                let sig1 = wj2.rotate_right(17) ^ wj2.rotate_right(19) ^ (wj2 >> 10);
                w[j] =
                    (Wrapping(sig0) + Wrapping(sig1) + Wrapping(w[j - 7]) + Wrapping(w[j - 16])).0;
            }

            w
        };

        let mut a = val[0];
        let mut b = val[1];
        let mut c = val[2];
        let mut d = val[3];
        let mut e = val[4];
        let mut f = val[5];
        let mut g = val[6];
        let mut h = val[7];

        for j in 0..64 {
            let ch = (e & f) ^ ((!e) & g);
            let maj = (a & b) ^ (a & c) ^ (b & c);

            let sig0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let sig1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);

            let t1 =
                (Wrapping(h) + Wrapping(sig1) + Wrapping(ch) + Wrapping(K[j]) + Wrapping(w[j])).0;

            let t2 = (Wrapping(sig0) + Wrapping(maj)).0;

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        val[0] = val[0].wrapping_add(a);
        val[1] = val[1].wrapping_add(b);
        val[2] = val[2].wrapping_add(c);
        val[3] = val[3].wrapping_add(d);
        val[4] = val[4].wrapping_add(e);
        val[5] = val[5].wrapping_add(f);
        val[6] = val[6].wrapping_add(g);
        val[7] = val[7].wrapping_add(h);
    }

    let mut ret = [0u8; 32];
    BigEndian::write_u32_into(&val, &mut ret);
    ret
}

#[cfg(test)]
mod test {
    use super::sha256;

    #[test]
    fn test_sha256() {
        static ANSWERS: &'static [(&'static [u8], &'static [u8])] = &[
            (
                b"",
                b"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
            ),
            (
                b"abc",
                b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                b"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1",
            ),
        ];

        for &(input, expected) in ANSWERS.iter() {
            let computed = sha256(input);
            assert_eq!(expected, &computed);
        }
    }
}
