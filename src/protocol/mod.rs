//! X3DH protocol implementation.

use std::marker::PhantomData;

use cryptimitives::key::KeyPair;
use cryptraits::{
    aead::Aead,
    convert::{Len, ToVec},
    kdf::Kdf,
    key::{KeyPair as _, SecretKey},
    key_exchange::DiffieHellman,
    signature::{Signature, Verify},
};
use rand_core::{OsRng, RngCore};

use crate::{
    errors::{XxxDhError, XxxDhResult},
    storage::ProtocolStorage,
};

pub const PROTOCOL_INFO: &'static str = "X3DH";

/// X3DH Protocol.
pub struct Protocol<SK, ESK, SIG, S, KDF, CIPHER>
where
    SK: SecretKey,
    ESK: SecretKey,
    SIG: Signature,
    S: ProtocolStorage<SK, SK::PK, SIG>,
    KDF: Kdf,
    CIPHER: Aead,
{
    /// `Protocol` key storage.
    pub storage: S,
    _sk: PhantomData<SK>,
    _esk: PhantomData<ESK>,
    _sig: PhantomData<SIG>,
    _kdf: PhantomData<KDF>,
    _cipher: PhantomData<CIPHER>,
}

impl<SK, ESK, SIG, S, KDF, CIPHER> Protocol<SK, ESK, SIG, S, KDF, CIPHER>
where
    SK: SecretKey + DiffieHellman<PK = <SK as SecretKey>::PK> + From<ESK>,
    <SK as SecretKey>::PK: ToVec + Verify<SIG = SIG>,
    ESK: SecretKey,
    SIG: Signature,
    S: ProtocolStorage<SK, <SK as SecretKey>::PK, SIG>,
    KDF: Kdf,
    <SK as DiffieHellman>::SSK: ToVec,
    CIPHER: Aead,
    XxxDhError: From<<<SK as cryptraits::key::SecretKey>::PK as Verify>::E>
        + From<<CIPHER as Aead>::E>
        + From<<KDF as cryptraits::kdf::Kdf>::E>,
{
    pub fn new(
        identity_keypair: KeyPair<SK>,
        prekey_keypair: KeyPair<SK>,
        prekey_signature: SIG,
        onetime_keypairs: Option<Vec<KeyPair<SK>>>,
    ) -> Self {
        let prekey_public = prekey_keypair.to_public();
        let mut storage = S::new(identity_keypair, prekey_keypair);

        storage
            .save_signature(prekey_public, prekey_signature)
            .unwrap();

        if let Some(onetime_keypairs) = onetime_keypairs {
            for keypair in onetime_keypairs {
                storage.save_onetime_keypair(keypair).unwrap();
            }
        }

        Self {
            storage,
            _sk: PhantomData::default(),
            _esk: PhantomData::default(),
            _sig: PhantomData::default(),
            _kdf: PhantomData::default(),
            _cipher: PhantomData::default(),
        }
    }

    /// Derive secret key and create initial message using receiver's keys.
    pub fn prepare_init_msg(
        &mut self,
        receiver_identity: &<SK as SecretKey>::PK,
        receiver_prekey: &<SK as SecretKey>::PK,
        receiver_prekey_signature: &SIG,
        receiver_onetime_key: &<SK as SecretKey>::PK,
    ) -> XxxDhResult<(
        <SK as SecretKey>::PK,
        <SK as SecretKey>::PK,
        <SK as SecretKey>::PK,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    )> {
        receiver_identity.verify(&receiver_prekey.to_vec(), receiver_prekey_signature)?;
        self.storage.save_identity(&receiver_identity)?;

        let ephemeral_key: SK = ESK::generate_with(OsRng).into();

        let sk = self._derive_sk([
            (
                self.storage.get_identity_key_pair().secret(),
                &receiver_prekey,
            ),
            (&ephemeral_key, receiver_identity),
            (&ephemeral_key, receiver_prekey),
            (&ephemeral_key, receiver_onetime_key),
        ])?;

        let mut nonce = vec![0; CIPHER::NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let mut data = self.storage.get_identity_key_pair().to_public().to_vec();
        data.extend(&receiver_identity.to_vec());

        let cipher = CIPHER::new(&sk);

        let ciphertext = cipher.encrypt(&nonce, &data, None).unwrap();

        Ok((
            self.storage.get_identity_key_pair().to_public(),
            ephemeral_key.to_public(),
            *receiver_onetime_key,
            sk,
            nonce,
            ciphertext,
        ))
    }

    /// Derive secret key from sender's message.
    pub fn derive_shared_secret(
        &mut self,
        sender_identity: &<SK as SecretKey>::PK,
        sender_ephemeral_key: &<SK as SecretKey>::PK,
        receiver_onetime_key: &<SK as SecretKey>::PK,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> XxxDhResult<Vec<u8>> {
        let identity_secret = self.storage.get_identity_key_pair().secret();
        let prekey_secret = self.storage.get_prekey_pair().secret();
        let onetime_keypair = self
            .storage
            .get_onetime_keypair(receiver_onetime_key)
            .unwrap()
            .ok_or(XxxDhError::UnknownPrekey)?;

        let sk = self._derive_sk([
            (prekey_secret, sender_identity),
            (&identity_secret, sender_ephemeral_key),
            (prekey_secret, sender_ephemeral_key),
            (onetime_keypair.secret(), sender_ephemeral_key),
        ])?;

        let cipher = CIPHER::new(&sk);
        cipher.decrypt(nonce, ciphertext, None)?;

        self.storage.save_identity(sender_identity)?;

        Ok(sk)
    }

    /// Derive secret key.
    fn _derive_sk(
        &self,
        source_data: [(&SK, &<SK as DiffieHellman>::PK); 4],
    ) -> XxxDhResult<Vec<u8>> {
        let mut data = vec![0_u8; <<SK as DiffieHellman>::PK as Len>::LEN];

        for (sk, pk) in source_data {
            data.extend(sk.diffie_hellman(pk).to_vec());
        }

        let h = KDF::new(
            Some(&vec![0_u8; <<SK as DiffieHellman>::SSK as Len>::LEN]),
            &data,
        );

        let mut sk = vec![0_u8; <<SK as DiffieHellman>::SSK as Len>::LEN];

        h.expand(PROTOCOL_INFO.as_bytes(), &mut sk)?;

        Ok(sk)
    }
}

#[cfg(all(
    test,
    feature = "x25519-ristretto",
    feature = "hkdf-sha256",
    feature = "aead-aes-gcm"
))]
mod tests {
    use cryptimitives::{aead::aes_gcm::Aes256Gcm, kdf::sha256, key::x25519_ristretto};
    use cryptraits::signature::Sign;

    use crate::storage::{
        inmem, IdentityKeyStorage, OnetimeKeyStorage, PreKeyStorage, SignatureStorage,
    };

    use super::*;

    #[test]
    fn it_should_exchange_keys() {
        let alice_identity = x25519_ristretto::KeyPair::generate_with(OsRng);
        let alice_prekey = x25519_ristretto::KeyPair::generate_with(OsRng);
        let alice_signature = alice_identity.sign(&alice_prekey.to_public().to_vec());
        let mut alice_protocol = Protocol::<
            x25519_ristretto::SecretKey,
            x25519_ristretto::EphemeralSecretKey,
            x25519_ristretto::Signature,
            inmem::Storage<_, _>,
            sha256::Kdf,
            Aes256Gcm,
        >::new(alice_identity, alice_prekey, alice_signature, None);

        let onetime_keypair = x25519_ristretto::KeyPair::generate_with(OsRng);

        let bob_identity = x25519_ristretto::KeyPair::generate_with(OsRng);
        let bob_prekey = x25519_ristretto::KeyPair::generate_with(OsRng);
        let bob_signature = bob_identity.sign(&bob_prekey.to_public().to_vec());
        let mut bob_protocol = Protocol::<
            x25519_ristretto::SecretKey,
            x25519_ristretto::EphemeralSecretKey,
            x25519_ristretto::Signature,
            inmem::Storage<x25519_ristretto::SecretKey, x25519_ristretto::Signature>,
            sha256::Kdf,
            Aes256Gcm,
        >::new(
            bob_identity,
            bob_prekey,
            bob_signature,
            Some(vec![onetime_keypair]),
        );

        let bob_identity = bob_protocol.storage.get_identity_key_pair().to_public();
        let bob_prekey = bob_protocol.storage.get_prekey_pair().to_public();
        let bob_signature = bob_protocol
            .storage
            .get_signature(&bob_prekey)
            .unwrap()
            .unwrap();
        let onetime_key = bob_protocol.storage.provide_ontime_key().unwrap().unwrap();

        let (alice_identity, alice_ephemeral_key, bob_onetime_key, alice_sk, nonce, ciphertext) =
            alice_protocol
                .prepare_init_msg(&bob_identity, &bob_prekey, bob_signature, onetime_key)
                .unwrap();

        let bob_sk = bob_protocol
            .derive_shared_secret(
                &alice_identity,
                &alice_ephemeral_key,
                &bob_onetime_key,
                &nonce,
                &ciphertext,
            )
            .unwrap();

        assert_eq!(alice_sk, bob_sk);
    }
}
