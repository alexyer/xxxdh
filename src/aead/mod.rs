//! AEAD cipher.
#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

use crate::errors::AeadResult;

pub trait Aead {
    const NONCE_LEN: usize;

    fn new(key: &[u8]) -> Self;
    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> AeadResult<Vec<u8>>;
    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> AeadResult<Vec<u8>>;
}
