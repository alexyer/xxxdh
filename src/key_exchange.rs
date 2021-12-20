//! Key exchange traits.

use crate::keys::{PublicKey, SharedSecretKey};

pub trait DiffieHellman {
    type SS: SharedSecretKey;
    type PK: PublicKey;

    fn diffie_hellman(&self, peer_public: &Self::PK) -> Self::SS;
}
