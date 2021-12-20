//! X3DH protocol implementation.

use crate::{KeyPair, PublicKey, SecretKey};

pub struct Protocol<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
{
    identity: KeyPair<SK, PK>,
}

impl<SK, PK> Protocol<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
{
    pub fn new(identity: KeyPair<SK, PK>) -> Self {
        Self { identity }
    }
}
