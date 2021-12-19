//! Signature traits.

use crate::{
    errors::SignatureResult,
    traits::{FromBytes, ToVec},
};

pub trait Signature: FromBytes + ToVec + Copy + Clone {}

/// Sign a message.
pub trait Sign {
    type S: Signature;

    /// Sign a message.
    fn sign(&self, data: &[u8]) -> Self::S
    where
        Self: Sized;
}

/// Verify a signature
pub trait Verify {
    type S: Signature;

    /// Verify a signature
    fn verify(&self, data: &[u8], signature: &Self::S) -> SignatureResult<()>;
}
