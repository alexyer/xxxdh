//! In-Memory key storage.

use core::hash::Hash;
use std::collections::HashSet;

use crate::{
    errors::{StorageError, StorageResult},
    KeyPair, PublicKey, SecretKey,
};

use super::IdentityKeyStorage;

pub struct Storage<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey + Eq + Hash,
{
    identity_key_pair: KeyPair<SK, PK>,
    known_identities: HashSet<PK>,
}

impl<SK, PK> IdentityKeyStorage<SK, PK> for Storage<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey + Eq + Hash,
{
    fn new(identity_key_pair: KeyPair<SK, PK>) -> Self {
        Self {
            identity_key_pair,
            known_identities: HashSet::new(),
        }
    }
    fn get_identity_key_pair(&self) -> &KeyPair<SK, PK> {
        &self.identity_key_pair
    }

    fn save_identity(&mut self, identity: &PK) -> StorageResult<()> {
        match self.known_identities.insert(identity.to_owned()) {
            true => Ok(()),
            false => Err(StorageError::UnknownError),
        }
    }

    fn is_known_identity(&self, identity: &PK) -> StorageResult<bool> {
        match self.known_identities.contains(identity) {
            true => Ok(true),
            false => Ok(false),
        }
    }
}
