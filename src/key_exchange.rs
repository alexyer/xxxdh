//! Key exchange traits.

use crate::keys::{PublicKey, SharedSecretKey};

pub trait DiffieHellman {
    type S: SharedSecretKey;
    type P: PublicKey;

    fn diffie_hellman(&self, peer_public: &Self::P) -> Self::S;
}
