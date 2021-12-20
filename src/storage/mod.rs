//! Key storage.
mod inmem;

use crate::{errors::StorageResult, KeyPair, PublicKey, SecretKey};

/// Identity keys storage.
pub trait IdentityKeyStorage<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
{
    /// Create a new storage.
    fn new(identity_key_pair: KeyPair<SK, PK>) -> Self;

    /// Get an identity `KeyPair`.
    fn get_identity_key_pair(&self) -> &KeyPair<SK, PK>;

    /// Save a known identity.
    fn save_identity(&mut self, identity: &PK) -> StorageResult<()>;

    /// Check if an identity is known.
    fn is_known_identity(&self, identity: &PK) -> StorageResult<bool>;
}
