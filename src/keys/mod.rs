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
    type PK: PublicKey;

    /// Generate an "unbiased" `SecretKey` directly from a user
    /// suplied `csprng` uniformly.
    fn generate_with<R: CryptoRng + RngCore>(csprng: R) -> Self
    where
        Self: Sized;

    /// Derive the `PublicKey` corresponding to this `SecretKey`.
    fn to_public(&self) -> Self::PK;
}

pub trait SharedSecretKey {}

pub struct KeyPair<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
{
    secret: SK,
    public: PK,
}

impl<SK, PK> Zeroize for KeyPair<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
{
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<SK, PK> Drop for KeyPair<SK, PK>
where
    SK: SecretKey,
    PK: PublicKey,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// X3DH Keypair.
impl<SK, PK> SecretKey for KeyPair<SK, PK>
where
    SK: SecretKey<PK = PK>,
    PK: PublicKey,
{
    type PK = PK;

    /// Generate a `KeyPair`;
    fn generate_with<R>(csprng: R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let secret: SK = SK::generate_with(csprng);
        let public = secret.to_public();

        KeyPair { secret, public }
    }

    /// Get a `PublicKey` of `KeyPair`.
    fn to_public(&self) -> SK::PK {
        self.public
    }
}

impl<S, P> FromBytes for KeyPair<S, P>
where
    S: SecretKey<PK = P> + FromBytes,
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

impl<SK, PK> ToVec for KeyPair<SK, PK>
where
    SK: SecretKey<PK = PK> + ToVec,
    PK: PublicKey + ToVec,
{
    const LEN: usize = SK::LEN + PK::LEN;

    fn to_vec(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(self.secret.to_vec());
        bytes.extend(self.public.to_vec());

        bytes
    }
}

impl<SK, PK> Sign for KeyPair<SK, PK>
where
    SK: SecretKey<PK = PK> + Sign,
    PK: PublicKey,
{
    type S = <SK as Sign>::S;

    fn sign(&self, data: &[u8]) -> Self::S
    where
        Self: Sized,
    {
        self.secret.sign(data)
    }
}

impl<SK, PK> DiffieHellman for KeyPair<SK, PK>
where
    SK: SecretKey<PK = PK> + Sign + DiffieHellman,
    PK: PublicKey,
{
    type S = <SK as DiffieHellman>::S;
    type P = <SK as DiffieHellman>::P;

    fn diffie_hellman(&self, peer_public: &Self::P) -> <SK as DiffieHellman>::S {
        self.secret.diffie_hellman(peer_public)
    }
}

impl<SK, PK> Verify for KeyPair<SK, PK>
where
    SK: SecretKey<PK = PK>,
    PK: PublicKey + Verify,
{
    type S = <PK as Verify>::S;

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
    S: SecretKey<PK = P>,
    P: PublicKey,
{
    fn default() -> Self {
        let secret: S = SecretKey::generate_with(OsRng);
        let public = secret.to_public();

        Self { secret, public }
    }
}

/// Identity keypair type alias;
pub type IdentityKeyPair<SK, PK> = KeyPair<SK, PK>;

/// Prekeypair type alias;
pub type PreKeyPair<SK, PK> = KeyPair<SK, PK>;

#[cfg(test)]
pub mod tests {
    use crate::Signature;

    use super::*;

    #[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
    pub struct TestPublicKey([u8; 5]);

    impl PublicKey for TestPublicKey {}

    impl FromBytes for TestPublicKey {
        const LEN: usize = 5;

        fn from_bytes(bytes: &[u8]) -> KeyResult<Self>
        where
            Self: Sized,
        {
            let mut key: [u8; Self::LEN] = [0; Self::LEN];

            for i in 0..Self::LEN {
                key[i] = bytes[i];
            }

            Ok(Self(key))
        }
    }

    #[derive(Debug, Zeroize)]
    #[zeroize(drop)]
    pub struct TestSecretKey([u8; 5]);

    impl SecretKey for TestSecretKey {
        type PK = TestPublicKey;

        fn generate_with<R: CryptoRng + RngCore>(_csprng: R) -> Self
        where
            Self: Sized,
        {
            todo!()
        }

        fn to_public(&self) -> Self::PK {
            todo!()
        }
    }

    impl FromBytes for TestSecretKey {
        const LEN: usize = 5;

        fn from_bytes(bytes: &[u8]) -> KeyResult<Self>
        where
            Self: Sized,
        {
            let mut key: [u8; Self::LEN] = [0; Self::LEN];

            for i in 0..Self::LEN {
                key[i] = bytes[i];
            }

            Ok(Self(key))
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct TestSignature([u8; 2]);

    impl Signature for TestSignature {}

    impl ToVec for TestSignature {
        const LEN: usize = 2;

        fn to_vec(&self) -> Vec<u8>
        where
            Self: Sized,
        {
            Vec::from(self.0)
        }
    }

    impl FromBytes for TestSignature {
        const LEN: usize = 2;

        fn from_bytes(bytes: &[u8]) -> KeyResult<Self>
        where
            Self: Sized,
        {
            let mut signature: [u8; 2] = [0; 2];

            for i in 0..2 {
                signature[i] = bytes[i];
            }

            Ok(Self(signature))
        }
    }

    pub type TestIdentityKeyPair<TestSecretKey, TestPublicKey> =
        KeyPair<TestSecretKey, TestPublicKey>;

    pub type TestPreKeyPair<TestSecretKey, TestPublicKey> = KeyPair<TestSecretKey, TestPublicKey>;
}
