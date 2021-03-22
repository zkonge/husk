// http://cr.yp.to/chacha/chacha-20080128.pdf
// http://cr.yp.to/chacha.html
// https://tools.ietf.org/html/rfc7539
// NOTICE: Chacha20 has 3 variants, TLS 1.2 finally uses Chacha20-ieft

use crate::crypto::wrapping::*;

// convert $e.slice($i, $i + 4) into u32
macro_rules! to_le_u32 {
    ($e:ident[$i:expr]) => ({
        let i: usize = $i;
        let v1 = w8($e[i + 0]).to_w32();
        let v2 = w8($e[i + 1]).to_w32();
        let v3 = w8($e[i + 2]).to_w32();
        let v4 = w8($e[i + 3]).to_w32();
        v1 | (v2 << 8) | (v3 << 16) | (v4 << 24)
    })
}

pub struct ChaCha20 {
    // SECRET
    vals: [w32; 16],
}

impl ChaCha20 {
    // key: SECRET
    pub fn new(key: &[u8], nonce: &[u8]) -> ChaCha20 {
        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 12);

        let mut vals = [w32(0u32); 16];

        // "expand 32-byte k"
        vals[0] = w32(0x61707865);
        vals[1] = w32(0x3320646e);
        vals[2] = w32(0x79622d32);
        vals[3] = w32(0x6b206574);

        for i in 0..8 {
            vals[4 + i] = to_le_u32!(key[4 * i]);
        }

        // counter
        vals[12] = w32(0);
        // vals[13] = w32(0);// Old Chacha20, deprecated

        vals[13] = to_le_u32!(nonce[0]);
        vals[14] = to_le_u32!(nonce[4]);
        vals[15] = to_le_u32!(nonce[8]);// TODO:support u96

        ChaCha20 { vals }
    }

    fn round20(&self) -> [w32; 16] {
        // $e must be > 0 and < 32
        macro_rules! rot {
            ($a:expr, $e:expr) => ({
                let a: w32 = $a;
                let e: usize = $e;
                (a << e) | (a >> (32 - e))
            })
        }

        macro_rules! quarter_round {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {{
                $a = $a + $b;
                $d = $d ^ $a;
                $d = rot!($d, 16);

                $c = $c + $d;
                $b = $b ^ $c;
                $b = rot!($b, 12);

                $a = $a + $b;
                $d = $d ^ $a;
                $d = rot!($d, 8);

                $c = $c + $d;
                $b = $b ^ $c;
                $b = rot!($b, 7);
            }};
        }

        macro_rules! quarter_round_idx {
            ($e:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
                quarter_round!($e[$a], $e[$b], $e[$c], $e[$d])
            };
        }

        let mut vals = self.vals;
        for _ in 0..10 {
            // column round
            quarter_round_idx!(vals, 0, 4, 8, 12);
            quarter_round_idx!(vals, 1, 5, 9, 13);
            quarter_round_idx!(vals, 2, 6, 10, 14);
            quarter_round_idx!(vals, 3, 7, 11, 15);

            // diagonal round
            quarter_round_idx!(vals, 0, 5, 10, 15);
            quarter_round_idx!(vals, 1, 6, 11, 12);
            quarter_round_idx!(vals, 2, 7, 8, 13);
            quarter_round_idx!(vals, 3, 4, 9, 14);
        }

        for i in 0..16 {
            vals[i] += self.vals[i];
        }

        vals
    }

    pub fn next(&mut self) -> [u8; 64] {
        let next = self.round20();

        // in TLS, vals[13] never increases
        {
            self.vals[12] += w32(1);
            // let mut count = (self.vals[12].to_w64()) | (self.vals[13].to_w64() << 32);
            // count += w64(1);
            // self.vals[12] = count.to_w32();
            // self.vals[13] = (count >> 32).to_w32();
        }

        let next_bytes = {
            let mut next_bytes = [0u8; 64];
            for i in 0..16 {
                next_bytes[4 * i] = next[i].to_w8().0;
                next_bytes[4 * i + 1] = (next[i] >> 8).to_w8().0;
                next_bytes[4 * i + 2] = (next[i] >> 16).to_w8().0;
                next_bytes[4 * i + 3] = (next[i] >> 24).to_w8().0;
            }
            next_bytes
        };

        next_bytes
    }

    // Do not use same nonce for more than 2^70 bytes.
    //
    // if data is 1 byte, it still produces 64 bytes then 63 bytes are just discarded.
    // so this is not suitable for "byte-streaming" mode.
    //
    // data: SECRET
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();

        for chunk in data.chunks(64) {
            let next = self.next();
            let xor_iter = next.iter().zip(chunk.iter()).map(|(&x, &y)| x ^ y);
            ret.extend(xor_iter);
        }

        ret
    }
}

#[cfg(test)]
mod test {
    use std::iter::repeat;

    use super::ChaCha20;

    fn check_keystream(key: &[u8], nonce: &[u8], keystream: &[u8]) {
        let mut chacha = ChaCha20::new(key, nonce);
        let input: Vec<_> = repeat(0u8).take(keystream.len()).collect();
        let output = chacha.encrypt(&input);
        assert_eq!(&output[..], keystream);
    }

    #[test]
    fn test_chacha20() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        let keystream = b"v\xb8\xe0\xad\xa0\xf1=\x90@]j\xe5S\x86\xbd(\xbd\xd2\x19\xb8\xa0\x8d\xed\x1a\xa86\xef\xcc\x8bw\r\xc7\xdaAY|QWH\x8dw$\xe0?\xb8\xd8J7jC\xb8\xf4\x15\x18\xa1\x1c\xc3\x87\xb6i\xb2\xeee\x86";
        check_keystream(&key, &nonce, keystream);

        key[31] = 1;
        let keystream = b"E@\xf0Z\x9f\x1f\xb2\x96\xd7sn{ \x8e<\x96\xebO\xe1\x83F\x88\xd2`OE\tR\xedC-A\xbb\xe2\xa0\xb6\xeauf\xd2\xa5\xd1\xe7\xe2\rB\xaf,S\xd7\x92\xb1\xc4?\xea\x81~\x9a\xd2u\xaeTic";
        check_keystream(&key, &nonce, keystream);

        key[31] = 0;
        nonce[11] = 1;
        let keystream = b"\xde\x9c\xba{\xf3\xd6\x9e\xf5\xe7\x86\xdcc\x97?e:\x0bI\xe0\x15\xad\xbf\xf7\x13O\xcb}\xf17\x82\x101\xe8Z\x05\x02x\xa7\x08E'!Os\xef\xc7\xfa[Rw\x06.\xb7\xa0C>D_A\xe3\x1a\xfa\xb7W";
        check_keystream(&key, &nonce, keystream);

        key[31] = 0;
        nonce[11] = 0;
        nonce[0] = 1;
        let keystream = b"=\xb4\x1d:\xa0\xd3)(]\xe6\xf2%\xe6\xe2K\xd5\x9c\x9a\x17\x00iC\xd5\xc9\xb6\x80\xe3\x87;\xdch:X\x19F\x98\x99\x98\x96\x90\xc2\x81\xcd\x17\xc9aY\xaf\x06\x82\xb5\xb9\x03F\x8aa\xf5\x02(\xcf\tb+Z";
        check_keystream(&key, &nonce, keystream);

        for i in 0..0x20 {
            key[i] = i as u8;
        }
        for i in 0..0x0c {
            nonce[i] = i as u8;
        }
        let keystream = b"\x10:\xf1\x11\xc1\x8bT\x9d9$\x8f\xb0}`\xc2\x9a\x95\xd1\xdb\x88\xd8\x92\xf7\xb4\xafp\x9a_\xd4z\x9eK\xd5\xff\x9ae\x8d\xd5,p\x8b\xef\x1f\x0fb+7G\x04\x0f\xa3U\x13\x00\xb1\xf2\x93\x15\n\x88b\r_\xed\x89\xfb\x08\x00)\x17\xa5@\xb7\x83?\xf3\x98\x1d\x0ec\xc9p\xb2\xe7Qt\xad\xb9\xe6\x97/\xc5u\xc0\xa6<\xec\x80,\xf3\xe6\x1e\xb1\x9872v\xd8e\x94\x8f#~\x84\xa9t\xfd(\xb8\x9b\x12\xb8\xd9\x07\x90O\x9e\xd6";
        check_keystream(&key, &nonce, keystream);
    }
}
