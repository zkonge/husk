// Implements AEAD_CHACHA20_POLY1305
// unfortunately, there is no concrete standard yet. some drafts exist:
// http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-01
// http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
// they differ in detail, so here we follow google/boringssl implementation.
// openssl 1.0.2-aead branch seems to implement draft 01.

use std::iter;

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

    // Chacha20Poly1305-ieft
    msg.extend(ad);
    let padding_len = 16 - (ad.len() % 16);
    if padding_len != 16 {
        msg.extend(iter::repeat(0).take(padding_len));
    }
    msg.extend(encrypted);
    let padding_len = 16 - (encrypted.len() % 16);
    if padding_len != 16 {
        msg.extend(iter::repeat(0).take(padding_len));
    }
    msg.extend(&u64_le_array(ad.len() as u64));
    msg.extend(&u64_le_array(encrypted.len() as u64));

    let mut r = [0u8; MAC_LEN];
    r[..MAC_LEN].clone_from_slice(&poly_key[..MAC_LEN]);
    let mut k = [0u8; MAC_LEN];
    k[..MAC_LEN].clone_from_slice(&poly_key[MAC_LEN..(MAC_LEN + MAC_LEN)]);

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
        let key = vec![
            78, 124, 134, 194, 178, 159, 186, 121, 39, 150, 125, 52, 41, 43, 133, 188, 16, 113, 83,
            255, 47, 98, 231, 194, 142, 108, 49, 193, 59, 172, 221, 210,
        ];
        let plain = vec![
            20, 0, 0, 12, 82, 176, 48, 66, 102, 149, 142, 132, 230, 204, 153, 206,
        ];
        let nonce = vec![63, 143, 158, 193, 12, 74, 32, 200, 246, 116, 243, 3];
        let aad = vec![0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16];
        let mut enc = ChaCha20Poly1305 {}.new_encryptor(key.clone());
        let r = enc.encrypt(&nonce, &plain, &aad);
        assert_eq!(
            r.as_slice(),
            &[
                117, 99, 17, 144, 9, 64, 124, 90, 213, 214, 44, 59, 54, 152, 33, 165, 154, 213,
                114, 86, 225, 115, 178, 58, 128, 128, 233, 241, 148, 121, 248, 25
            ]
        );
        let mut dec = ChaCha20Poly1305 {}.new_decryptor(key);
        let r = dec.decrypt(&nonce, r.as_slice(), &aad).unwrap();
        assert_eq!(r, plain);
    }
}
