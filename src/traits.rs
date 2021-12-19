//! Generic utility traits.

use crate::errors::KeyResult;

pub trait FromBytes {
    const LEN: usize;

    /// Construct a key from a slice of bytes.
    fn from_bytes(bytes: &[u8]) -> KeyResult<Self>
    where
        Self: Sized;
}

pub trait ToVec {
    const LEN: usize;

    /// Convert a key into a vec of bytes.
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized;
}
