//! Basic example.

use rand_core::OsRng;
use xxxdh::{
    aes_gcm, inmem, sha256, x25519_ristretto, IdentityKeyStorage, OnetimeKeyStorage, PreKeyStorage,
    Protocol, Sign, SignatureStorage, ToVec,
};

fn main() {
    // Instantiate Alice protocol.

    let alice_identity = x25519_ristretto::IdentityKeyPair::generate_with(OsRng);
    let alice_prekey = x25519_ristretto::PreKeyPair::generate_with(OsRng);
    let alice_signature = alice_identity.sign(&alice_prekey.to_public().to_vec());
    let mut alice_protocol = Protocol::<
        x25519_ristretto::IdentitySecretKey,
        x25519_ristretto::EphemeralSecretKey,
        x25519_ristretto::Signature,
        inmem::Storage<_, _>,
        sha256::Kdf,
        aes_gcm::Aead,
    >::new(alice_identity, alice_prekey, alice_signature, None);

    // Instantiate Bob protocol.

    let onetime_keypair = x25519_ristretto::OnetimeKeyPair::generate_with(OsRng);

    let bob_identity = x25519_ristretto::IdentityKeyPair::generate_with(OsRng);
    let bob_prekey = x25519_ristretto::IdentityKeyPair::generate_with(OsRng);
    let bob_signature = bob_identity.sign(&bob_prekey.to_public().to_vec());
    let mut bob_protocol = Protocol::<
        x25519_ristretto::IdentitySecretKey,
        x25519_ristretto::EphemeralSecretKey,
        x25519_ristretto::Signature,
        inmem::Storage<_, _>,
        sha256::Kdf,
        aes_gcm::Aead,
    >::new(
        bob_identity,
        bob_prekey,
        bob_signature,
        Some(vec![onetime_keypair]),
    );

    // Derive shared secret for Alice and prepare message for Bob.

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

    // Derive shared secret for Bob using Alice credentials.

    let bob_sk = bob_protocol
        .derive_shared_secret(
            &alice_identity,
            &alice_ephemeral_key,
            &bob_onetime_key,
            &nonce,
            &ciphertext,
        )
        .unwrap();

    println!("Alice shared secret: {:?}", alice_sk);
    println!("Bob shared secret: {:?}", bob_sk);
}
