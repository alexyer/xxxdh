//! X3DH protocol implementation.

use std::marker::PhantomData;

use crate::{storage::IdentityKeyStorage, KeyPair, PublicKey, SecretKey};

pub struct Protocol<SK, PK, IKS>
where
    SK: SecretKey,
    PK: PublicKey,
    IKS: IdentityKeyStorage<SK, PK>,
{
    identity_key_storage: IKS,
    _sk: PhantomData<SK>,
    _pk: PhantomData<PK>,
}

impl<SK, PK, IKS> Protocol<SK, PK, IKS>
where
    SK: SecretKey,
    PK: PublicKey,
    IKS: IdentityKeyStorage<SK, PK>,
{
    pub fn new(identity_key_pair: KeyPair<SK, PK>) -> Self {
        Self {
            identity_key_storage: IKS::new(identity_key_pair),
            _sk: PhantomData::default(),
            _pk: PhantomData::default(),
        }
    }
}
