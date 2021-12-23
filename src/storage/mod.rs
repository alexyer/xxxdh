//! Key storage.
pub mod inmem;

use cryptimitives::key::KeyPair;
use cryptraits::{
    key::{PublicKey, SecretKey},
    signature::Signature,
};

use crate::errors::StorageResult;

/// Identity keys storage.
pub trait IdentityKeyStorage<SK>
where
    SK: SecretKey,
{
    /// Get an identity `IdentityKeyPair`.
    fn get_identity_key_pair(&self) -> &KeyPair<SK>;

    /// Save a known identity.
    fn save_identity(&mut self, identity: &SK::PK) -> StorageResult<()>;

    /// Check if an identity is known.
    fn is_known_identity(&self, identity: &SK::PK) -> StorageResult<bool>;
}

///  Prekeys storage.
pub trait PreKeyStorage<SK>
where
    SK: SecretKey,
{
    /// Get a prekey `PreKeyPair`.
    fn get_prekey_pair(&self) -> &KeyPair<SK>;

    /// Save a known identity.
    fn save_prekey(&mut self, key: &SK::PK) -> StorageResult<()>;

    /// Check if a prekey is known.
    fn is_known_prekey(&self, key: &SK::PK) -> StorageResult<bool>;
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
pub trait OnetimeKeyStorage<SK>
where
    SK: SecretKey,
{
    /// Get a `OnetimeKeyPair`.
    fn get_onetime_keypair(&self, key: &SK::PK) -> StorageResult<Option<&KeyPair<SK>>>;

    /// Save a `OnetimeKeyPair`.
    fn save_onetime_keypair(&mut self, keypair: KeyPair<SK>) -> StorageResult<()>;

    /// Forget a `OnetimeKeyPair`.
    fn forget_onetime_keypair(&mut self, key: &SK::PK) -> StorageResult<()>;

    /// Check if there are keys available.
    fn is_onetime_keys_empty(&self) -> StorageResult<bool>;

    /// Provide a single onetime key. Returns `None` if storage is empty.
    fn provide_ontime_key(&self) -> StorageResult<Option<&SK::PK>>;
}

pub trait ProtocolStorage<SK, PK, S>:
    IdentityKeyStorage<SK> + PreKeyStorage<SK> + SignatureStorage<PK, S> + OnetimeKeyStorage<SK>
where
    SK: SecretKey,
    PK: PublicKey,
    S: Signature,
{
    fn new(identity_keypair: KeyPair<SK>, prekey_keypair: KeyPair<SK>) -> Self;
}
