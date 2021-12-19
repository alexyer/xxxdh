use crate::errors::KdfResult;

/// X3DH KDF trait.
pub trait Kdf {
    fn new(salt: Option<&[u8]>, data: &[u8]) -> Self;
    fn expand(&self, info: &[u8], okm: &mut [u8]) -> KdfResult<()>;
}

#[cfg(feature = "sha256")]
pub mod sha256;

#[cfg(feature = "sha512")]
pub mod sha512;
