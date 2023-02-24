// Implements AEAD_CHACHA20_POLY1305
// unfortunately, there is& no concrete standard yet. some drafts exist:
// http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-01
// http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
// they differ in detail, so here we follow google/boringssl implementation.
// openssl 1.0.2-aead branch seems to implement draft 01.

use crate::tls_result::TlsErrorKind::BadRecordMac;
use crate::tls_result::TlsResult;

use super::{Aead, Decryptor, Encryptor};

const KEY_LEN: usize = 256 / 8;
const EXPLICIT_IV_LEN: usize = 0;
const MAC_LEN: usize = 16;

struct ChaCha20Poly1305Encryptor {
    key: Vec<u8>,
}

impl Encryptor for ChaCha20Poly1305Encryptor {
    fn encrypt(&mut self, nonce: &[u8], data: &[u8], ad: &[u8]) -> Vec<u8> {
        use primit::aead::chacha20poly1305::Chacha20Poly1305;
        use primit::aead::{Aead, Encryptor};
        let mut ret = data.to_vec();

        let alg = Chacha20Poly1305::new(self.key.as_slice().try_into().unwrap());
        let enc = alg.encryptor(nonce.try_into().unwrap(), ad);

        let mac=enc.finalize(&mut ret);
        ret.extend_from_slice(&mac);

        ret
    }
    #[inline(always)]
    fn fixed_iv_len(&self) -> usize {
        EXPLICIT_IV_LEN
    }
}

struct ChaCha20Poly1305Decryptor {
    key: Vec<u8>,
}

impl Decryptor for ChaCha20Poly1305Decryptor {
    fn decrypt(&mut self, nonce: &[u8], data: &[u8], ad: &[u8]) -> TlsResult<Vec<u8>> {
        use primit::aead::chacha20poly1305::Chacha20Poly1305;
        use primit::aead::{Aead, Decryptor};
        let enc_len = data.len();
        if enc_len < MAC_LEN {
            return tls_err!(BadRecordMac, "message too short");
        }

        let encrypted = &data[..(enc_len - MAC_LEN)];
        let mac_expected = &data[(enc_len - MAC_LEN)..];

        let mut ret = encrypted.to_vec();

        let alg = Chacha20Poly1305::new(self.key.as_slice().try_into().unwrap());
        let dec = alg.decryptor(nonce.try_into().unwrap(), ad);

        match dec.finalize(&mut ret, mac_expected.try_into().unwrap()) {
            Ok(()) => Ok(ret),
            Err(_) => tls_err!(BadRecordMac, "wrong mac"),
        }
    }
    #[inline(always)]
    fn fixed_iv_len(&self) -> usize {
        EXPLICIT_IV_LEN
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
