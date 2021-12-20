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

pub struct KeyPair<SK>
where
    SK: SecretKey,
{
    secret: SK,
    public: SK::PK,
}

impl<SK> KeyPair<SK>
where
    SK: SecretKey,
{
    pub fn generate_with<R>(csprng: R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let secret: SK = SK::generate_with(csprng);
        let public = secret.to_public();

        KeyPair { secret, public }
    }

    /// Get a `PublicKey` of `KeyPair`.
    pub fn to_public(&self) -> SK::PK {
        self.public
    }

    /// Get a `PublicKey` of `KeyPair`.
    pub fn to_secret(&self) -> &SK {
        &self.secret
    }
}

impl<SK> Zeroize for KeyPair<SK>
where
    SK: SecretKey,
{
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<SK> Drop for KeyPair<SK>
where
    SK: SecretKey,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<SK> FromBytes for KeyPair<SK>
where
    SK: SecretKey + FromBytes,
    SK::PK: FromBytes,
{
    const LEN: usize = SK::LEN + <<SK as SecretKey>::PK as FromBytes>::LEN;

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
    fn from_bytes(bytes: &[u8]) -> KeyResult<KeyPair<SK>> {
        if bytes.len() != Self::LEN {
            return Err(KeypairError::BytesLengthError);
        }

        let secret = SK::from_bytes(&bytes[..SK::LEN])?;
        let public = SK::PK::from_bytes(&bytes[SK::LEN..])?;

        Ok(KeyPair { secret, public })
    }
}

impl<SK> ToVec for KeyPair<SK>
where
    SK: SecretKey + ToVec,
    SK::PK: ToVec,
{
    const LEN: usize = SK::LEN + <SK::PK as ToVec>::LEN;

    fn to_vec(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(self.secret.to_vec());
        bytes.extend(self.public.to_vec());

        bytes
    }
}

impl<SK> Sign for KeyPair<SK>
where
    SK: SecretKey + Sign,
{
    type SIG = <SK as Sign>::SIG;

    fn sign(&self, data: &[u8]) -> Self::SIG
    where
        Self: Sized,
    {
        self.secret.sign(data)
    }
}

impl<SK> DiffieHellman for KeyPair<SK>
where
    SK: SecretKey + Sign + DiffieHellman,
{
    type SS = <SK as DiffieHellman>::SS;
    type PK = <SK as DiffieHellman>::PK;

    fn diffie_hellman(&self, peer_public: &Self::PK) -> <SK as DiffieHellman>::SS {
        self.secret.diffie_hellman(peer_public)
    }
}

impl<SK> Verify for KeyPair<SK>
where
    SK: SecretKey,
    SK::PK: Verify,
{
    type SIG = <SK::PK as Verify>::SIG;

    fn verify(&self, data: &[u8], signature: &Self::SIG) -> crate::errors::SignatureResult<()> {
        self.public.verify(data, signature)
    }
}

impl<SK> Debug for KeyPair<SK>
where
    SK: SecretKey,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("secret", &String::from("<erased>"))
            .field("public", &self.public)
            .finish()
    }
}

impl<SK> Default for KeyPair<SK>
where
    SK: SecretKey,
{
    fn default() -> Self {
        let secret: SK = SecretKey::generate_with(OsRng);
        let public = secret.to_public();

        Self { secret, public }
    }
}

/// Identity keypair type alias;
pub type IdentityKeyPair<SK> = KeyPair<SK>;

/// Prekeypair type alias;
pub type PreKeyPair<SK> = KeyPair<SK>;

/// One-time keypair type alias;
pub type OnetimeKeyPair<SK> = KeyPair<SK>;

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
            let mut key: [u8; <Self as FromBytes>::LEN] = [0; <Self as FromBytes>::LEN];

            for i in 0..<Self as FromBytes>::LEN {
                key[i] = bytes[i];
            }

            Ok(Self(key))
        }
    }

    impl ToVec for TestPublicKey {
        const LEN: usize = 5;

        fn to_vec(&self) -> Vec<u8>
        where
            Self: Sized,
        {
            Vec::from(self.0)
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

    pub type TestIdentityKeyPair<TestSecretKey> = KeyPair<TestSecretKey>;

    pub type TestPreKeyPair<TestSecretKey> = KeyPair<TestSecretKey>;
}
