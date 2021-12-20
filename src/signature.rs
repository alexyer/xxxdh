//! Signature traits.

use crate::{
    errors::SignatureResult,
    traits::{FromBytes, ToVec},
};

pub trait Signature: FromBytes + ToVec + Copy + Clone + PartialEq {}

/// Sign a message.
pub trait Sign {
    type SIG: Signature;

    /// Sign a message.
    fn sign(&self, data: &[u8]) -> Self::SIG
    where
        Self: Sized;
}

/// Verify a signature
pub trait Verify {
    type SIG: Signature;

    /// Verify a signature
    fn verify(&self, data: &[u8], signature: &Self::SIG) -> SignatureResult<()>;
}
