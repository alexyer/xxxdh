//! Key storage.
mod inmem;

use crate::{
    errors::StorageResult, IdentityKeyPair, OnetimeKeyPair, PreKeyPair, PublicKey, SecretKey,
    Signature,
};

/// Identity keys storage.
pub trait IdentityKeyStorage<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
{
    /// Get an identity `IdentityKeyPair`.
    fn get_identity_key_pair(&self) -> &IdentityKeyPair<SK, PK>;

    /// Save a known identity.
    fn save_identity(&mut self, identity: &PK) -> StorageResult<()>;

    /// Check if an identity is known.
    fn is_known_identity(&self, identity: &PK) -> StorageResult<bool>;
}

///  Prekeys storage.
pub trait PreKeyStorage<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
{
    /// Get a prekey `PreKeyPair`.
    fn get_prekey_pair(&self) -> &PreKeyPair<SK, PK>;

    /// Save a known identity.
    fn save_prekey(&mut self, prekey: &PK) -> StorageResult<()>;

    /// Check if a prekey is known.
    fn is_known_prekey(&self, prekey: &PK) -> StorageResult<bool>;
}

///  Prekeys signature storage.
pub trait SignatureStorage<PK, SIG>
where
    PK: PublicKey,
    SIG: Signature,
{
    /// Get a signature for a key.
    fn get_signature(&self, key: &PK) -> StorageResult<Option<&SIG>>;

    /// Save a signature.
    fn save_signature(&mut self, key: PK, signature: SIG) -> StorageResult<()>;
}

///  One-time keys storage.
pub trait OnetimeKeyStorage<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
{
    /// Get a `OnetimeKeyPair`.
    fn get_onetime_keypair(&self, key: &PK) -> StorageResult<Option<&OnetimeKeyPair<SK, PK>>>;

    /// Save a `OnetimeKeyPair`.
    fn save_onetime_keypair(
        &mut self,
        key: PK,
        onetime_keypair: OnetimeKeyPair<SK, PK>,
    ) -> StorageResult<()>;

    /// Forget a `OnetimeKeyPair`.
    fn forget_onetime_keypair(&mut self, key: &PK) -> StorageResult<()>;

    /// Check if there are keys available.
    fn is_onetime_keys_empty(&self) -> StorageResult<bool>;
}

pub trait ProtocolStorage<SK, PK, S>:
    IdentityKeyStorage<SK, PK>
    + PreKeyStorage<SK, PK>
    + SignatureStorage<PK, S>
    + OnetimeKeyStorage<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
    S: Signature,
{
    fn new(identity_keypair: IdentityKeyPair<SK, PK>, prekey_keypair: PreKeyPair<SK, PK>) -> Self;
}
