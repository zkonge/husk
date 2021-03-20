// Implements AEAD_CHACHA20_POLY1305
// unfortunately, there is no concrete standard yet. some drafts exist:
// http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-01
// http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
// they differ in detail, so here we follow google/boringssl implementation.
// openssl 1.0.2-aead branch seems to implement draft 01.

use super::{Aead, Decryptor, Encryptor};
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::poly1305;
use crate::tls_result::TlsErrorKind::BadRecordMac;
use crate::tls_result::TlsResult;
use crate::util::u64_le_array;

const KEY_LEN: usize = 256 / 8;
const EXPLICIT_IV_LEN: usize = 0;
const MAC_LEN: usize = 16;

fn compute_mac(poly_key: &[u8], encrypted: &[u8], ad: &[u8]) -> [u8; MAC_LEN] {
    let mut msg = Vec::new();

    // follow draft-agl-tls-chacha20poly1305-04: data first, length later
    // note that in draft-agl-tls-chacha20poly1305-01 length is first

    // Old chacha20poly1305
    // fn push_all_with_len(vec: &mut Vec<u8>, data: &[u8]) {
    //     vec.extend(data);
    //     vec.extend(&u64_le_array(data.len() as u64));
    // }

    // push_all_with_len(&mut msg, ad);
    // push_all_with_len(&mut msg, encrypted);

    // Chacha20Poly1305-ieft
    msg.extend(ad);
    msg.extend(encrypted);
    msg.extend(&u64_le_array(ad.len() as u64));
    msg.extend(&u64_le_array(encrypted.len() as u64));

    let mut r = [0u8; MAC_LEN];
    for i in 0..MAC_LEN {
        r[i] = poly_key[i];
    }
    let mut k = [0u8; MAC_LEN];
    for i in 0..MAC_LEN {
        k[i] = poly_key[MAC_LEN + i];
    }

    poly1305::authenticate(&msg, &r, &k)
}

struct ChaCha20Poly1305Encryptor {
    key: Vec<u8>,
}

impl Encryptor for ChaCha20Poly1305Encryptor {
    fn encrypt(&mut self, nonce: &[u8], data: &[u8], ad: &[u8]) -> Vec<u8> {
        let mut chacha20 = ChaCha20::new(&self.key, nonce);
        let poly1305_key = chacha20.next();

        let mut encrypted = chacha20.encrypt(data);
        let mac = compute_mac(&poly1305_key, &encrypted, ad);
        encrypted.extend(&mac);

        encrypted
    }
}

struct ChaCha20Poly1305Decryptor {
    key: Vec<u8>,
}

impl Decryptor for ChaCha20Poly1305Decryptor {
    fn decrypt(&mut self, nonce: &[u8], data: &[u8], ad: &[u8]) -> TlsResult<Vec<u8>> {
        let enc_len = data.len();
        if enc_len < MAC_LEN {
            return tls_err!(BadRecordMac, "message too short");
        }

        let encrypted = &data[..(enc_len - MAC_LEN)];
        let mac_expected = &data[(enc_len - MAC_LEN)..];

        let mut chacha20 = ChaCha20::new(&self.key, nonce);
        let poly1305_key = chacha20.next();

        let mac_computed = compute_mac(&poly1305_key, &encrypted, ad);

        // SECRET
        // even if `mac_computed != mac_expected`, decrypt the data to prevent timing attack.
        let plain = chacha20.encrypt(encrypted);

        let mut diff = 0u8;
        for i in 0..MAC_LEN {
            diff |= mac_computed[i] ^ mac_expected[i];
        }

        if diff != 0 {
            tls_err!(BadRecordMac, "wrong mac")
        } else {
            Ok(plain)
        }
    }

    #[inline(always)]
    fn mac_len(&self) -> usize {
        MAC_LEN
    }
}

pub struct ChaCha20Poly1305;

impl Aead for ChaCha20Poly1305 {
    #[inline(always)]
    fn key_size(&self) -> usize {
        KEY_LEN
    }

    #[inline(always)]
    fn fixed_iv_len(&self) -> usize {
        EXPLICIT_IV_LEN
    }

    #[inline(always)]
    fn mac_len(&self) -> usize {
        MAC_LEN
    }

    #[inline(always)]
    fn new_encryptor(&self, key: Vec<u8>) -> Box<dyn Encryptor + Send + 'static> {
        let encryptor = ChaCha20Poly1305Encryptor { key };
        Box::new(encryptor) as Box<dyn Encryptor + Send>
    }

    #[inline(always)]
    fn new_decryptor(&self, key: Vec<u8>) -> Box<dyn Decryptor + Send + 'static> {
        let decryptor = ChaCha20Poly1305Decryptor { key };
        Box::new(decryptor) as Box<dyn Decryptor + Send>
    }
}

#[cfg(test)]
mod test {
    use super::Aead;
    use super::ChaCha20Poly1305;

    #[test]
    fn test_chacha20_poly1305() {
        let key = vec![1u8; 32];
        let plain = vec![1u8; 32];
        let nonce = vec![1u8; 12];
        let mut enc = ChaCha20Poly1305 {}.new_encryptor(key);
        let r = enc.encrypt(&nonce, &plain, &[1u8; 32]);
        assert_eq!(r.as_slice(),b"\xf0/\xea.\xbd\xd0\xb1\xee\xc6\xc9'P\x9fL\xbb$\x10}\xc0b\xfa\x0b\xa7\\\xd3\x10Q\x98\xda\x00\xc9\x98%jK\x13\rH\xba\xd0&\x0cp|\xbbE\xbe\xf4");
    }
}
