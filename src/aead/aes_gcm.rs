//! AES-GCM AEAD algorytm implementation.

use aes_gcm::{aead::Aead as _, Key, NewAead, Nonce};

use crate::errors::{AeadError, AeadResult};

pub struct Aead(::aes_gcm::Aes256Gcm);

impl super::Aead for Aead {
    const NONCE_LEN: usize = 12;

    fn new(key: &[u8]) -> Self {
        let key = Key::from_slice(key);
        Self(::aes_gcm::Aes256Gcm::new(key))
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> AeadResult<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.0.encrypt(nonce, data).or(Err(AeadError))
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> AeadResult<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.0.decrypt(nonce, data).or(Err(AeadError))
    }
}
