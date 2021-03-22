// In AEAD setting, PRF is only used for key calculation.
// SHA-256 only for now.

use crate::crypto::sha2::sha256;
use std::mem;

// key is SECRET, but the length is publicly known.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const B: usize = 64;

    if key.len() > B {
        // FIXME
        unimplemented!();
    }

    let mut i_msg = [0x36u8; B].to_vec();
    let mut o_msg = [0x5cu8; B].to_vec();
    for i in 0..key.len() {
        i_msg[i] ^= key[i];
        o_msg[i] ^= key[i];
    }

    i_msg.extend(msg);
    let h_i = sha256(&i_msg);
    o_msg.extend(&h_i);

    sha256(&o_msg)
}

pub struct Prf {
    secret: Vec<u8>, // SECRET
    seed: Vec<u8>,
    a: [u8; 32],
    buf: Vec<u8>,
}

impl Prf {
    pub fn new(secret: Vec<u8>, seed: Vec<u8>) -> Prf {
        let a1 = hmac_sha256(&secret, &seed);

        Prf {
            secret,
            seed,
            a: a1,
            buf: Vec::new(),
        }
    }

    // get 32-byte pseudorandom number.
    fn next_block(&mut self) -> [u8; 32] {
        let mut input = self.a.to_vec();
        input.extend(&self.seed);
        let next = hmac_sha256(&self.secret, &input);
        self.a = hmac_sha256(&self.secret, &self.a);

        next
    }

    pub fn get_bytes(&mut self, size: usize) -> Vec<u8> {
        let mut ret = {
            let buflen = self.buf.len();
            if buflen > 0 {
                if buflen <= size {
                    mem::replace(&mut self.buf, Vec::new())
                } else {
                    let rest = self.buf[size..].to_vec();
                    let mut buf = mem::replace(&mut self.buf, rest);
                    buf.truncate(size);
                    buf
                }
            } else {
                Vec::new()
            }
        };

        while ret.len() < size {
            let next_block = self.next_block();
            let slice_len = size - ret.len();
            if slice_len > 32 {
                ret.extend(&next_block);
            } else {
                ret.extend(&next_block[..slice_len]);
                self.buf = next_block[slice_len..].to_vec();
                break;
            };
        }

        ret
    }
}

#[cfg(test)]
mod test {
    use super::{hmac_sha256, Prf};

    #[test]
    fn test_hmac_sha256() {
        // some test vectors from RFC 4231
        static VALUES: &'static [(&'static [u8], &'static [u8], &'static [u8])] = &[
            (
                b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
               \x0b\x0b\x0b\x0b",
                b"\x48\x69\x20\x54\x68\x65\x72\x65",
                b"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\
               \x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",
            ),
            (
                b"\x4a\x65\x66\x65",
                b"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\
               \x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f",
                b"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\
               \x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43",
            ),
            (
                b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
               \xaa\xaa\xaa\xaa",
                b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
               \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
               \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
               \xdd\xdd",
                b"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\
               \x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe",
            ),
            (
                b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\
               \x11\x12\x13\x14\x15\x16\x17\x18\x19",
                b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
               \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
               \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
               \xcd\xcd",
                b"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a\
               \x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b",
            ),
        ];

        for &(key, input, expected) in VALUES.iter() {
            let actual = hmac_sha256(key, input);
            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn test_get_bytes() {
        let ret1 = {
            let mut prf = Prf::new(Vec::new(), Vec::new());
            let mut ret: Vec<u8> = Vec::new();
            for _ in 0..100 {
                ret.extend(&prf.get_bytes(1));
            }
            ret
        };

        let ret2 = {
            let mut prf = Prf::new(Vec::new(), Vec::new());
            prf.get_bytes(100)
        };

        assert_eq!(ret1, ret2);

        let ret3 = {
            let mut prf = Prf::new(Vec::new(), Vec::new());
            let mut b = prf.get_bytes(33);
            b.extend(&prf.get_bytes(33));
            b.extend(&prf.get_bytes(100 - 33 * 2));
            b
        };

        assert_eq!(ret1, ret3);
    }
    #[test]
    fn test_prf_vector() {
        let secret: Vec<u8> = vec![
            0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71,
            0xdb, 0x35,
        ];
        let seed: Vec<u8> = vec![
            0x74, 0x65, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0xa0, 0xba,
            0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c,
        ];
        let result: Vec<u8> = vec![
            0x7c, 0x74, 0xe9, 0x13, 0x6a, 0x4b, 0x6b, 0x45, 0x24, 0x91, 0x74, 0x5c, 0x1a, 0xec,
            0x66, 0xa3, 0x90, 0xda, 0x23, 0x04, 0xae, 0xed, 0x91, 0x47, 0x2b, 0xac, 0x54, 0x9c,
            0x90, 0x83, 0x23, 0x17, 0xe2, 0x57, 0xbe, 0xb8, 0x5d, 0x3b, 0x55, 0x76, 0x35, 0x6c,
            0x5f, 0x1d, 0x68, 0xed, 0xae, 0x05, 0xe4, 0x55, 0x28, 0xfe, 0xdd, 0x61, 0x72, 0x34,
            0x19, 0x47, 0x2d, 0x08, 0xab, 0x42, 0xa4, 0xd5, 0x73, 0x96, 0x16, 0x05, 0x57, 0xdf,
            0x2a, 0x43, 0xf8, 0xaa, 0xf6, 0x4c, 0x01, 0xf2, 0xe6, 0x00, 0x0e, 0x8e, 0xb0, 0x22,
            0xb7, 0x9b, 0x33, 0x94, 0xcd, 0x8b, 0x41, 0xb3, 0xb3, 0x7b, 0x29, 0x02, 0x26, 0xb8,
            0x02, 0x62,
        ];

        let mut prf = Prf::new(secret, seed);
        let r = prf.get_bytes(100);
        assert_eq!(result, r);
    }
}
