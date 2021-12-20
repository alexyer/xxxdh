//! X3DH implemetation using Curve25519 with Ristretto point compression.

use std::fmt::Debug;

use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
};
use zeroize::Zeroize;

use crate::{
    errors::{KeyResult, KeypairError, SignatureError, SignatureResult},
    key_exchange, keys,
    signature::{self, Sign},
    traits,
};

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct IdentitySecretKey(schnorrkel::SecretKey);

impl keys::SecretKey for IdentitySecretKey {
    type PK = IdentityPublicKey;

    fn generate_with<R: rand_core::CryptoRng + rand_core::RngCore>(csprng: R) -> Self
    where
        Self: Sized,
    {
        Self(schnorrkel::SecretKey::generate_with(csprng))
    }

    fn to_public(&self) -> Self::PK {
        IdentityPublicKey(self.0.to_public())
    }
}

impl traits::FromBytes for IdentitySecretKey {
    const LEN: usize = 64;

    fn from_bytes(bytes: &[u8]) -> KeyResult<Self>
    where
        Self: Sized,
    {
        let secret = schnorrkel::SecretKey::from_bytes(bytes)
            .or_else(|e| Err(KeypairError::UnderlyingError(e.to_string())))?;

        Ok(IdentitySecretKey(secret))
    }
}

impl traits::ToVec for IdentitySecretKey {
    const LEN: usize = 64;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signature(schnorrkel::Signature);
impl signature::Signature for Signature {}

impl traits::FromBytes for Signature {
    const LEN: usize = 64;

    fn from_bytes(bytes: &[u8]) -> KeyResult<Self>
    where
        Self: Sized,
    {
        let signature = schnorrkel::Signature::from_bytes(bytes)
            .or_else(|e| Err(KeypairError::UnderlyingError(e.to_string())))?;

        Ok(Signature(signature))
    }
}

impl traits::ToVec for Signature {
    const LEN: usize = 64;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

impl<'a> Sign for IdentitySecretKey {
    type S = Signature;

    fn sign(&self, data: &[u8]) -> Self::S
    where
        Self: Sized,
    {
        Signature(self.0.sign_simple(b"X3DH", &data, &self.0.to_public()))
    }
}

impl key_exchange::DiffieHellman for IdentitySecretKey {
    type S = SharedSecret;
    type P = IdentityPublicKey;

    fn diffie_hellman(&self, peer_public: &Self::P) -> Self::S {
        let mut secret_bytes: [u8; 32] = [0; 32];

        secret_bytes.copy_from_slice(&self.0.to_bytes()[..32]);

        let scalar = Scalar::from_canonical_bytes(secret_bytes).unwrap();

        SharedSecret(scalar * peer_public.0.as_point())
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct IdentityPublicKey(schnorrkel::PublicKey);

impl keys::PublicKey for IdentityPublicKey {}

impl traits::FromBytes for IdentityPublicKey {
    const LEN: usize = 32;

    fn from_bytes(bytes: &[u8]) -> KeyResult<Self>
    where
        Self: Sized,
    {
        let public = schnorrkel::PublicKey::from_bytes(bytes)
            .or_else(|e| Err(KeypairError::UnderlyingError(e.to_string())))?;

        Ok(IdentityPublicKey(public))
    }
}

impl From<EphemeralPublicKey> for IdentityPublicKey {
    fn from(epk: EphemeralPublicKey) -> Self {
        // FIXME(alexyer): unwrap
        Self(schnorrkel::PublicKey::from_compressed(epk.0.compress()).unwrap())
    }
}

impl Into<EphemeralPublicKey> for &IdentityPublicKey {
    fn into(self) -> EphemeralPublicKey {
        EphemeralPublicKey(RistrettoPoint::from(*self.0.as_point()))
    }
}

impl traits::ToVec for IdentityPublicKey {
    const LEN: usize = 32;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

impl signature::Verify for IdentityPublicKey {
    type S = Signature;

    fn verify(&self, data: &[u8], signature: &Self::S) -> SignatureResult<()> {
        match self.0.verify_simple(b"X3DH", data, &signature.0) {
            Ok(_) => Ok(()),
            Err(schnorrkel::SignatureError::EquationFalse) => Err(SignatureError::EquationFalse),
            Err(e) => panic!("Unknown error: {:?}", e),
        }
    }
}

impl Debug for IdentityPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PublicKey")
            .field(
                &self
                    .0
                    .to_bytes()
                    .iter()
                    .map(|b| format!("{:02X}", *b))
                    .collect::<Vec<_>>()
                    .join(""),
            )
            .finish()
    }
}

pub type IdentityKeyPair = keys::KeyPair<IdentitySecretKey, IdentityPublicKey>;

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
/// A Diffie-Hellman secret key used to derive a shared secret when
/// combined with a public key, that only exists for a short time.
pub struct EphemeralSecretKey(Scalar);

impl keys::SecretKey for EphemeralSecretKey {
    type PK = EphemeralPublicKey;

    fn generate_with<R: rand_core::CryptoRng + rand_core::RngCore>(mut csprng: R) -> Self
    where
        Self: Sized,
    {
        Self(Scalar::random(&mut csprng))
    }

    fn to_public(&self) -> Self::PK {
        EphemeralPublicKey(&self.0 * &RISTRETTO_BASEPOINT_TABLE)
    }
}

impl key_exchange::DiffieHellman for EphemeralSecretKey {
    type S = SharedSecret;
    type P = EphemeralPublicKey;

    fn diffie_hellman(&self, peer_public: &Self::P) -> Self::S {
        SharedSecret(self.0 * peer_public.0)
    }
}

/// The public key derived from an ephemeral secret key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EphemeralPublicKey(RistrettoPoint);

impl keys::PublicKey for EphemeralPublicKey {}

impl From<IdentityPublicKey> for EphemeralPublicKey {
    fn from(ik: IdentityPublicKey) -> Self {
        Self(RistrettoPoint::from(*ik.0.as_point()))
    }
}

impl traits::ToVec for EphemeralPublicKey {
    const LEN: usize = 32;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.compress().to_bytes())
    }
}

impl traits::ToVec for EphemeralSecretKey {
    const LEN: usize = 32;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

/// A Diffie-Hellman shared secret derived from an `EphemeralSecretKey`
/// and the other party's `PublicKey`.
pub struct SharedSecret(RistrettoPoint);

impl keys::SharedSecretKey for SharedSecret {}

impl From<SharedSecret> for [u8; 32] {
    fn from(shared_secret: SharedSecret) -> Self {
        shared_secret.0.compress().to_bytes()
    }
}

impl traits::ToVec for SharedSecret {
    const LEN: usize = 32;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.compress().to_bytes())
    }
}

#[allow(unused_imports)]
mod tests {
    use super::EphemeralSecretKey;
    use crate::errors::SignatureError;
    use crate::key_exchange::DiffieHellman;
    use crate::keys::SecretKey;
    use crate::signature::{self, Sign, Verify};
    use crate::traits::{FromBytes, ToVec};
    use crate::x25519_ristretto::IdentityKeyPair;
    use rand_core::OsRng;

    #[test]
    fn identity_key_construct_from_bytes() {
        let bytes = vec![
            163, 32, 145, 4, 0, 205, 62, 240, 59, 87, 154, 77, 76, 172, 14, 144, 106, 224, 121,
            160, 178, 53, 227, 200, 15, 100, 125, 223, 69, 79, 178, 6, 249, 60, 236, 118, 88, 251,
            237, 212, 121, 28, 158, 94, 173, 159, 109, 18, 119, 32, 95, 39, 151, 112, 222, 230,
            246, 253, 15, 253, 139, 251, 161, 240, 172, 234, 111, 40, 46, 158, 32, 9, 119, 8, 125,
            180, 202, 113, 253, 218, 95, 6, 129, 230, 117, 54, 144, 169, 174, 74, 105, 33, 243,
            176, 206, 32,
        ];

        assert!(IdentityKeyPair::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn identity_key_to_vec() {
        let bytes = [
            163, 32, 145, 4, 0, 205, 62, 240, 59, 87, 154, 77, 76, 172, 14, 144, 106, 224, 121,
            160, 178, 53, 227, 200, 15, 100, 125, 223, 69, 79, 178, 6, 249, 60, 236, 118, 88, 251,
            237, 212, 121, 28, 158, 94, 173, 159, 109, 18, 119, 32, 95, 39, 151, 112, 222, 230,
            246, 253, 15, 253, 139, 251, 161, 240, 172, 234, 111, 40, 46, 158, 32, 9, 119, 8, 125,
            180, 202, 113, 253, 218, 95, 6, 129, 230, 117, 54, 144, 169, 174, 74, 105, 33, 243,
            176, 206, 32,
        ];

        assert_eq!(
            &IdentityKeyPair::from_bytes(&bytes).unwrap().to_vec(),
            &bytes
        );
    }

    #[test]
    fn identity_key_should_verify_signature() {
        const MSG: &[u8] = b"sw0rdfish";

        let alice_keypair = IdentityKeyPair::default();
        let bob_keypair = IdentityKeyPair::default();
        let alice_public = alice_keypair.to_public();

        let signature = alice_keypair.sign(MSG);

        assert_eq!(
            bob_keypair.verify(MSG, &signature),
            Err(SignatureError::EquationFalse)
        );

        assert!(alice_public.verify(MSG, &signature).is_ok());
    }

    #[test]
    fn random_dh() {
        let alice_secret = EphemeralSecretKey::generate_with(&mut OsRng);
        let alice_public = alice_secret.to_public();

        let bob_secret = EphemeralSecretKey::generate_with(&mut OsRng);
        let bob_public = bob_secret.to_public();

        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(
            <[u8; 32]>::from(alice_shared_secret),
            <[u8; 32]>::from(bob_shared_secret)
        );
    }
}
