use std::fmt::Debug;

use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroize;

use crate::{
    errors::{KeyResult, KeypairError},
    signature::{Sign, Verify},
    traits::{FromBytes, ToVec},
    DiffieHellman,
};

#[cfg(feature = "x25519-ristretto")]
pub mod x25519_ristretto;

/// A public key for use in X3DH protocol.
pub trait PublicKey: Debug + Copy + PartialEq {}

/// A secret key for use in X3DH protocol.
pub trait SecretKey: Zeroize + Debug {
    type P: PublicKey;

    /// Generate an "unbiased" `SecretKey` directly from a user
    /// suplied `csprng` uniformly.
    fn generate_with<R: CryptoRng + RngCore>(csprng: R) -> Self
    where
        Self: Sized;

    /// Derive the `PublicKey` corresponding to this `SecretKey`.
    fn to_public(&self) -> Self::P;
}

pub trait SharedSecretKey {}

pub struct KeyPair<S, P>
where
    S: SecretKey,
    P: PublicKey,
{
    secret: S,
    public: P,
}

impl<S, P> Zeroize for KeyPair<S, P>
where
    S: SecretKey,
    P: PublicKey,
{
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<S, P> Drop for KeyPair<S, P>
where
    S: SecretKey,
    P: PublicKey,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// X3DH Keypair.
impl<S, P> SecretKey for KeyPair<S, P>
where
    S: SecretKey<P = P>,
    P: PublicKey,
{
    type P = P;

    /// Generate a `KeyPair`;
    fn generate_with<R>(csprng: R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let secret: S = S::generate_with(csprng);
        let public = secret.to_public();

        KeyPair { secret, public }
    }

    /// Get a `PublicKey` of `KeyPair`.
    fn to_public(&self) -> S::P {
        self.public
    }
}

impl<S, P> FromBytes for KeyPair<S, P>
where
    S: SecretKey<P = P> + FromBytes,
    P: PublicKey + FromBytes,
{
    const LEN: usize = S::LEN + P::LEN;

    /// Deserialize a `IdentityKeyPair` from bytes.
    ///
    /// # Inputs
    ///
    /// * `bytes`: an `&[u8]` consisting of byte representations of
    /// first a `SecretKey` and then the corresponding `PublicKey`.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is a `Keypair` or whose error value
    /// is an `KeypairError` describing the error that occurred.
    fn from_bytes(bytes: &[u8]) -> KeyResult<KeyPair<S, P>> {
        if bytes.len() != Self::LEN {
            return Err(KeypairError::BytesLengthError);
        }

        let secret = S::from_bytes(&bytes[..S::LEN])?;
        let public = P::from_bytes(&bytes[S::LEN..])?;

        Ok(KeyPair { secret, public })
    }
}

impl<S, P> ToVec for KeyPair<S, P>
where
    S: SecretKey<P = P> + ToVec,
    P: PublicKey + ToVec,
{
    const LEN: usize = S::LEN + P::LEN;

    fn to_vec(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(self.secret.to_vec());
        bytes.extend(self.public.to_vec());

        bytes
    }
}

impl<S, P> Sign for KeyPair<S, P>
where
    S: SecretKey<P = P> + Sign,
    P: PublicKey,
{
    type S = <S as Sign>::S;

    fn sign(&self, data: &[u8]) -> Self::S
    where
        Self: Sized,
    {
        self.secret.sign(data)
    }
}

impl<S, P> DiffieHellman for KeyPair<S, P>
where
    S: SecretKey<P = P> + Sign + DiffieHellman,
    P: PublicKey,
{
    type S = <S as DiffieHellman>::S;
    type P = <S as DiffieHellman>::P;

    fn diffie_hellman(&self, peer_public: &Self::P) -> <S as DiffieHellman>::S {
        self.secret.diffie_hellman(peer_public)
    }
}

impl<'a, S, P> Verify for KeyPair<S, P>
where
    S: SecretKey<P = P>,
    P: PublicKey + Verify,
{
    type S = <P as Verify>::S;

    fn verify(&self, data: &[u8], signature: &Self::S) -> crate::errors::SignatureResult<()> {
        self.public.verify(data, signature)
    }
}

impl<S, P> Debug for KeyPair<S, P>
where
    S: SecretKey,
    P: PublicKey,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("secret", &String::from("<erased>"))
            .field("public", &self.public)
            .finish()
    }
}

impl<S, P> Default for KeyPair<S, P>
where
    S: SecretKey<P = P>,
    P: PublicKey,
{
    fn default() -> Self {
        let secret: S = SecretKey::generate_with(OsRng);
        let public = secret.to_public();

        Self { secret, public }
    }
}
