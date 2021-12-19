use hkdf::Hkdf;
use sha2::Sha256;

use crate::errors::{KdfError, KdfResult};

pub struct Kdf(Hkdf<Sha256>);

impl super::Kdf for Kdf {
    fn new(salt: Option<&[u8]>, data: &[u8]) -> Self {
        Self(Hkdf::<Sha256>::new(salt, data))
    }

    fn expand(&self, info: &[u8], okm: &mut [u8]) -> KdfResult<()> {
        self.0.expand(info, okm).or(Err(KdfError::InvalidLength))
    }
}
