//! X3DH protocol implementation.

use std::marker::PhantomData;

use crate::{storage::ProtocolStorage, IdentityKeyPair, PreKeyPair, PublicKey, SecretKey};

pub struct Protocol<SK, PK, S>
where
    SK: SecretKey,
    PK: PublicKey,
    S: ProtocolStorage<SK, PK>,
{
    storage: S,
    _sk: PhantomData<SK>,
    _pk: PhantomData<PK>,
}

impl<SK, PK, S> Protocol<SK, PK, S>
where
    SK: SecretKey,
    PK: PublicKey,
    S: ProtocolStorage<SK, PK>,
{
    pub fn new(
        identity_keypair: IdentityKeyPair<SK, PK>,
        prekey_keypair: PreKeyPair<SK, PK>,
    ) -> Self {
        Self {
            storage: S::new(identity_keypair, prekey_keypair),
            _sk: PhantomData::default(),
            _pk: PhantomData::default(),
        }
    }
}
