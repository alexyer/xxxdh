mod aead;
mod errors;
mod kdf;
mod key_exchange;
mod keys;
mod protocol;
mod signature;
mod storage;
mod traits;

use std::marker::PhantomData;

pub use aead::*;
use errors::{XxxDhError, XxxDhResult};
pub use kdf::*;
pub use key_exchange::*;
pub use keys::*;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
pub use signature::*;
pub use traits::*;

/// X3DH keys bundle.
pub struct KeysBundle<SK, PK, ESK, EPK, H, CIPHER, S>
where
    SK: SecretKey,
    PK: PublicKey,
    ESK: SecretKey,
    EPK: PublicKey + ToVec,
    H: Kdf,
    KeyPair<SK, PK>: Sign,
    CIPHER: Aead,
    S: Signature,
{
    identity_key: KeyPair<SK, PK>,
    signed_prekey: SK,
    prekey_signature: <KeyPair<SK, PK> as Sign>::S,
    onetime_prekeys: Vec<SK>,
    _hash: PhantomData<H>,
    _esk: PhantomData<ESK>,
    _epk: PhantomData<EPK>,
    _aead: PhantomData<CIPHER>,
    _signature: PhantomData<S>,
}

pub struct PublicKeysBundle<PK, S>
where
    PK: PublicKey,
    S: Signature,
{
    pub identity_key: PK,
    pub signed_prekey: PK,
    pub prekey_signature: S,
    pub onetime_prekeys: Vec<PK>,
}

#[derive(Debug)]
pub struct InitialMessageBundle<PK, EPK>
where
    PK: PublicKey,
    EPK: PublicKey,
{
    pub identity_key: PK,
    pub ephemeral_key: EPK,
    pub signed_prekey: PK,
    pub onetime_prekey: PK,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl<'s, SK, PK, ESK, EPK, H, CIPHER, S> KeysBundle<SK, PK, ESK, EPK, H, CIPHER, S>
where
    SK: SecretKey<PK = PK> + DiffieHellman<P = PK>,
    PK: PublicKey + ToVec + Verify<S = S> + From<EPK>,
    ESK: SecretKey + DiffieHellman + SecretKey<PK = EPK>,
    EPK: PublicKey + ToVec,
    H: Kdf,
    KeyPair<SK, PK>: Sign<S = S> + SecretKey<PK = PK> + DiffieHellman<P = PK>,
    <ESK as DiffieHellman>::S: ToVec,
    <ESK as DiffieHellman>::P: From<PK>,
    <KeyPair<SK, PK> as DiffieHellman>::S: ToVec,
    <SK as key_exchange::DiffieHellman>::S: ToVec,
    CIPHER: Aead,
    S: Signature + ToVec,
{
    pub fn new(identity_key: KeyPair<SK, PK>, prekeys_num: usize) -> Self {
        let signed_prekey = SK::generate_with(OsRng);
        let signed_prekey_public_bytes = signed_prekey.to_public().to_vec();
        let prekey_signature = identity_key.sign(&signed_prekey_public_bytes);

        let mut prekeys: Vec<SK> = Vec::new();

        for _ in 0..prekeys_num {
            prekeys.push(SK::generate_with(OsRng));
        }

        Self {
            identity_key,
            signed_prekey,
            prekey_signature,
            onetime_prekeys: prekeys,
            _hash: PhantomData::default(),
            _esk: PhantomData::default(),
            _epk: PhantomData::default(),
            _aead: PhantomData::default(),
            _signature: PhantomData::default(),
        }
    }

    pub fn public_bundle(&self) -> PublicKeysBundle<PK, S> {
        PublicKeysBundle {
            identity_key: self.identity_key.to_public(),
            signed_prekey: self.signed_prekey.to_public(),
            prekey_signature: self.prekey_signature.clone(),
            onetime_prekeys: self.onetime_prekeys.iter().map(SK::to_public).collect(),
        }
    }

    pub fn initial_msg(
        &self,
        bundle: &mut PublicKeysBundle<PK, S>,
    ) -> XxxDhResult<(Vec<u8>, InitialMessageBundle<PK, EPK>)> {
        let (sk, ephemeral_key, onetime_prekey) = {
            bundle
                .identity_key
                .verify(&bundle.signed_prekey.to_vec(), &bundle.prekey_signature)
                .or_else(|e| Err(XxxDhError::SignatureError(format!("{:?}", e))))?;

            let ephemeral_key = ESK::generate_with(OsRng);

            let onetime_prekey = &bundle
                .onetime_prekeys
                .pop()
                .ok_or(XxxDhError::EmptyPrekeyList)?;

            let mut dh1 = self
                .identity_key
                .diffie_hellman(&bundle.signed_prekey)
                .to_vec();
            let mut dh2 = ephemeral_key
                .diffie_hellman(&bundle.identity_key.into())
                .to_vec();
            let mut dh3 = ephemeral_key
                .diffie_hellman(&bundle.signed_prekey.into())
                .to_vec();
            let mut dh4 = ephemeral_key
                .diffie_hellman(&<ESK as key_exchange::DiffieHellman>::P::from(
                    *onetime_prekey,
                ))
                .to_vec();

            let mut data = Vec::new();

            data.append(&mut vec![0_u8; PK::LEN]);
            data.append(&mut dh1);
            data.append(&mut dh2);
            data.append(&mut dh3);
            data.append(&mut dh4);

            let h = ::hkdf::Hkdf::<Sha256>::new(
                Some(&vec![
                    0_u8;
                    <<KeyPair<SK, PK> as DiffieHellman>::S as ToVec>::LEN
                ]),
                &data,
            );

            let mut okm = vec![0_u8; <<KeyPair<SK, PK> as DiffieHellman>::S as ToVec>::LEN];
            let info = b"xxxdh";

            h.expand(info, &mut okm)
                .or_else(|e| Err(XxxDhError::KdfError(e.to_string())))?;

            (okm, ephemeral_key.to_public(), *onetime_prekey)
        };

        let mut nonce = vec![0; CIPHER::NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let mut data = self.identity_key.to_public().to_vec();
        data.extend(&bundle.identity_key.to_vec());

        let cipher = CIPHER::new(&sk);

        let ciphertext = cipher
            .encrypt(&nonce, &data)
            .or(Err(XxxDhError::AeadError))?;

        Ok((
            sk,
            InitialMessageBundle {
                identity_key: self.identity_key.to_public(),
                ephemeral_key,
                signed_prekey: bundle.signed_prekey,
                onetime_prekey,
                ciphertext,
                nonce,
            },
        ))
    }

    pub fn received_msg(
        &self,
        initial_msg: &InitialMessageBundle<PK, EPK>,
    ) -> XxxDhResult<Vec<u8>> {
        let onetime_prekey = self
            .onetime_prekeys
            .iter()
            .find(|k| k.to_public() == initial_msg.onetime_prekey)
            .ok_or(XxxDhError::UnknownPrekey)?;

        let mut dh1 = self
            .signed_prekey
            .diffie_hellman(&initial_msg.identity_key)
            .to_vec();
        let mut dh2 = self
            .identity_key
            .diffie_hellman(&PK::from(initial_msg.ephemeral_key))
            .to_vec();
        let mut dh3 = self
            .signed_prekey
            .diffie_hellman(&PK::from(initial_msg.ephemeral_key))
            .to_vec();
        let mut dh4 = onetime_prekey
            .diffie_hellman(&PK::from(initial_msg.ephemeral_key))
            .to_vec();

        let mut data = Vec::new();

        data.append(&mut vec![0_u8; PK::LEN]);
        data.append(&mut dh1);
        data.append(&mut dh2);
        data.append(&mut dh3);
        data.append(&mut dh4);

        let h = ::hkdf::Hkdf::<Sha256>::new(
            Some(&vec![
                0_u8;
                <<KeyPair<SK, PK> as DiffieHellman>::S as ToVec>::LEN
            ]),
            &data,
        );

        let mut sk = vec![0_u8; <<KeyPair<SK, PK> as DiffieHellman>::S as ToVec>::LEN];
        let info = b"xxxdh";

        h.expand(info, &mut sk)
            .or_else(|e| Err(XxxDhError::KdfError(e.to_string())))?;

        let cipher = CIPHER::new(&sk);
        cipher
            .decrypt(&initial_msg.nonce, &initial_msg.ciphertext)
            .or(Err(XxxDhError::AeadError))?;

        Ok(sk)
    }
}

#[cfg(test)]
mod tests {
    use crate::{aead, sha256, x25519_ristretto, KeysBundle};

    #[test]
    fn it_should_exchange_keys() {
        let alice_identity = x25519_ristretto::IdentityKey::default();
        let bob_identity = x25519_ristretto::IdentityKey::default();

        let alice_bundle: KeysBundle<
            x25519_ristretto::IdentitySecretKey,
            x25519_ristretto::IdentityPublicKey,
            x25519_ristretto::EphemeralSecretKey,
            x25519_ristretto::EphemeralPublicKey,
            sha256::Kdf,
            aead::aes_gcm::Aead,
            x25519_ristretto::Signature,
        > = KeysBundle::new(alice_identity, 1);

        let bob_bundle: KeysBundle<
            x25519_ristretto::IdentitySecretKey,
            x25519_ristretto::IdentityPublicKey,
            x25519_ristretto::EphemeralSecretKey,
            x25519_ristretto::EphemeralPublicKey,
            sha256::Kdf,
            aead::aes_gcm::Aead,
            x25519_ristretto::Signature,
        > = KeysBundle::new(bob_identity, 1);
        let mut bob_public_bundle = bob_bundle.public_bundle();

        let (alice_sk, initial_msg) = alice_bundle.initial_msg(&mut bob_public_bundle).unwrap();
        let bob_sk = bob_bundle.received_msg(&initial_msg).unwrap();

        assert_eq!(alice_sk, bob_sk);
    }
}
