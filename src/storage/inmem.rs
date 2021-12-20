//! In-Memory key storage.

use core::hash::Hash;
use std::collections::{HashMap, HashSet};

use crate::{
    errors::StorageResult, IdentityKeyPair, OnetimeKeyPair, PreKeyPair, SecretKey, Signature,
};

use super::{
    IdentityKeyStorage, OnetimeKeyStorage, PreKeyStorage, ProtocolStorage, SignatureStorage,
};

/// In-Memory key storage.
#[derive(Debug)]
pub struct Storage<SK, SIG>
where
    SK: SecretKey,
    SIG: Signature,
{
    identity_key_pair: IdentityKeyPair<SK>,
    known_identities: HashSet<SK::PK>,

    prekey_pair: PreKeyPair<SK>,
    known_prekeys: HashSet<SK::PK>,

    signatures: HashMap<SK::PK, SIG>,

    onetime_keys: HashMap<SK::PK, OnetimeKeyPair<SK>>,
}

impl<SK, SIG> IdentityKeyStorage<SK> for Storage<SK, SIG>
where
    SK: SecretKey,
    SK::PK: Eq + Hash,
    SIG: Signature,
{
    fn get_identity_key_pair(&self) -> &IdentityKeyPair<SK> {
        &self.identity_key_pair
    }

    fn save_identity(&mut self, identity: &SK::PK) -> StorageResult<()> {
        self.known_identities.insert(identity.to_owned());

        Ok(())
    }

    fn is_known_identity(&self, identity: &SK::PK) -> StorageResult<bool> {
        Ok(self.known_identities.contains(identity))
    }
}

impl<SK, SIG> PreKeyStorage<SK> for Storage<SK, SIG>
where
    SK: SecretKey,
    SK::PK: Eq + Hash,
    SIG: Signature,
{
    fn get_prekey_pair(&self) -> &PreKeyPair<SK> {
        &self.prekey_pair
    }

    fn save_prekey(&mut self, key: &SK::PK) -> StorageResult<()> {
        self.known_prekeys.insert(key.to_owned());

        Ok(())
    }

    fn is_known_prekey(&self, key: &SK::PK) -> StorageResult<bool> {
        Ok(self.known_prekeys.contains(key))
    }
}

impl<SK, SIG> SignatureStorage<SK::PK, SIG> for Storage<SK, SIG>
where
    SK: SecretKey,
    SK::PK: Eq + Hash,
    SIG: Signature,
{
    fn get_signature(&self, key: &SK::PK) -> StorageResult<Option<&SIG>> {
        Ok(self.signatures.get(key))
    }

    fn save_signature(&mut self, key: SK::PK, signature: SIG) -> StorageResult<()> {
        self.signatures.insert(key, signature);

        Ok(())
    }
}

impl<SK, SIG> OnetimeKeyStorage<SK> for Storage<SK, SIG>
where
    SK: SecretKey,
    SK::PK: Eq + Hash,
    SIG: Signature,
{
    fn get_onetime_keypair(&self, key: &SK::PK) -> StorageResult<Option<&OnetimeKeyPair<SK>>> {
        Ok(self.onetime_keys.get(key))
    }

    fn save_onetime_keypair(&mut self, keypair: OnetimeKeyPair<SK>) -> StorageResult<()> {
        self.onetime_keys.insert(keypair.to_public(), keypair);

        Ok(())
    }

    fn forget_onetime_keypair(&mut self, key: &SK::PK) -> StorageResult<()> {
        self.onetime_keys.remove(key);

        Ok(())
    }

    fn is_onetime_keys_empty(&self) -> StorageResult<bool> {
        Ok(self.onetime_keys.is_empty())
    }

    fn provide_ontime_key(&self) -> StorageResult<Option<&SK::PK>> {
        Ok(self.onetime_keys.keys().next())
    }
}

impl<SK, SIG> ProtocolStorage<SK, SK::PK, SIG> for Storage<SK, SIG>
where
    SK: SecretKey,
    SK::PK: Eq + Hash,
    SIG: Signature,
{
    fn new(identity_key_pair: IdentityKeyPair<SK>, prekey_pair: PreKeyPair<SK>) -> Self {
        Self {
            identity_key_pair,
            known_identities: HashSet::new(),
            prekey_pair,
            known_prekeys: HashSet::new(),
            signatures: HashMap::new(),
            onetime_keys: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::tests::{
        TestIdentityKeyPair, TestPreKeyPair, TestPublicKey, TestSecretKey, TestSignature,
    };
    use crate::traits::FromBytes;

    use super::*;

    fn get_test_storage() -> Storage<TestSecretKey, TestSignature> {
        let identity_keypair = TestIdentityKeyPair::from_bytes(b"teststestp").unwrap();
        let pre_keypair = TestPreKeyPair::from_bytes(b"teststestp").unwrap();

        Storage::new(identity_keypair, pre_keypair)
    }

    #[test]
    fn it_should_create_protocol_storage() {
        let public = TestPublicKey::from_bytes(b"testp").unwrap();

        let identity_keypair = TestIdentityKeyPair::from_bytes(b"teststestp").unwrap();
        let pre_keypair = TestPreKeyPair::from_bytes(b"teststestp").unwrap();

        let storage: Storage<TestSecretKey, TestSignature> =
            Storage::new(identity_keypair, pre_keypair);

        assert_eq!(storage.get_identity_key_pair().to_public(), public);
        assert_eq!(storage.get_identity_key_pair().to_public(), public);
    }

    #[test]
    fn it_should_save_identity() {
        let mut storage = get_test_storage();

        let identity = TestPublicKey::from_bytes(b"ident").unwrap();

        assert!(!storage.is_known_identity(&identity).unwrap());

        storage.save_identity(&identity).unwrap();

        assert!(storage.is_known_identity(&identity).unwrap());
    }

    #[test]
    fn it_should_save_prekey() {
        let mut storage = get_test_storage();

        let identity = TestPublicKey::from_bytes(b"prkey").unwrap();

        assert!(!storage.is_known_prekey(&identity).unwrap());

        storage.save_prekey(&identity).unwrap();

        assert!(storage.is_known_prekey(&identity).unwrap());
    }

    #[test]
    fn it_should_save_signature() {
        let mut storage = get_test_storage();
        let key = TestPublicKey::from_bytes(b"sikey").unwrap();
        let signature = TestSignature::from_bytes(b"si").unwrap();

        assert!(storage.get_signature(&key).unwrap().is_none());

        storage
            .save_signature(key.clone(), signature.clone())
            .unwrap();

        assert_eq!(storage.get_signature(&key).unwrap(), Some(&signature));
    }

    #[test]
    fn it_should_save_onetime_keypair() {
        let mut storage = get_test_storage();
        let onetime_keypair = TestPreKeyPair::from_bytes(b"teststestp").unwrap();
        let onetime_public = onetime_keypair.to_public();

        assert!(storage.is_onetime_keys_empty().unwrap());
        storage.save_onetime_keypair(onetime_keypair).unwrap();

        assert!(!storage.is_onetime_keys_empty().unwrap());

        let public = storage
            .get_onetime_keypair(&onetime_public)
            .unwrap()
            .unwrap()
            .to_public();
        assert_eq!(public, onetime_public);

        storage.forget_onetime_keypair(&onetime_public).unwrap();

        assert!(storage.is_onetime_keys_empty().unwrap());
    }
}
