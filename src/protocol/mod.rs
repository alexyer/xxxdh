//! X3DH protocol implementation.

use std::marker::PhantomData;

use crate::{
    storage::ProtocolStorage, IdentityKeyPair, PreKeyPair, PublicKey, SecretKey, Signature,
};

/// X3DH Protocol.
pub struct Protocol<SK, PK, SIG, S>
where
    SK: SecretKey,
    PK: PublicKey,
    SIG: Signature,
    S: ProtocolStorage<SK, PK, SIG>,
{
    /// `Protocol` key storage.
    storage: S,
    _sk: PhantomData<SK>,
    _pk: PhantomData<PK>,
    _sig: PhantomData<SIG>,
}

impl<SK, PK, SIG, S> Protocol<SK, PK, SIG, S>
where
    SK: SecretKey,
    PK: PublicKey,
    SIG: Signature,
    S: ProtocolStorage<SK, PK, SIG>,
{
    pub fn new(
        identity_keypair: IdentityKeyPair<SK, PK>,
        prekey_keypair: PreKeyPair<SK, PK>,
    ) -> Self {
        Self {
            storage: S::new(identity_keypair, prekey_keypair),
            _sk: PhantomData::default(),
            _pk: PhantomData::default(),
            _sig: PhantomData::default(),
        }
    }
}
