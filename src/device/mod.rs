use std::time::Duration;

use serde::{Deserialize, Serialize};

use rand::{CryptoRng, Rng};

use libsignal_protocol::error::Result;
use libsignal_protocol::{
    message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    CiphertextMessage, PreKeyBundle, PreKeySignalMessage, ProtocolAddress, SignalMessage,
};
use libsignal_protocol::{
    IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
};

mod creds;
mod keys;
mod stores;

pub use creds::{DeviceAuth, DeviceCreds, Username};
pub use keys::{DeviceKeys, PreKey, SignedPreKey};

#[derive(Serialize, Deserialize)]
pub struct Device {
    pub creds: DeviceCreds,
    #[serde(flatten)]
    pub keys: DeviceKeys,
}

impl Device {
    pub fn new(creds: DeviceCreds, keys: DeviceKeys) -> Self {
        Self { creds, keys }
    }

    #[allow(dead_code)]
    pub fn clean_signed_pre_keys_older_than(&mut self, _age: Duration) {
        todo!()
    }

    // Make it public?
    fn stores(
        &mut self,
    ) -> (
        impl IdentityKeyStore + '_,
        impl PreKeyStore + '_,
        impl SignedPreKeyStore + '_,
        impl SessionStore + '_,
        impl SenderKeyStore + '_,
    ) {
        (
            stores::DeviceIdentityKeyStore {
                identity_key_pair: &self.keys.identity_key_pair,
                local_registration_id: self.creds.registration_id,
                trusted_keys: &mut self.keys.trusted_keys,
            },
            stores::DevicePreKeyStore {
                pre_keys: &mut self.keys.pre_keys,
            },
            stores::DeviceSignedPreKeyStore {
                signed_pre_key: &mut self.keys.signed_pre_key,
                old_signed_prekeys: &mut self.keys.old_signed_prekeys,
            },
            stores::DeviceSessionStore {
                sessions: &mut self.keys.sessions,
            },
            stores::DeviceSenderKeyStore {
                sender_keys: &mut self.keys.sender_keys,
            },
        )
    }

    pub async fn message_encrypt(
        &mut self,
        remote_address: &ProtocolAddress,
        plaintext: &[u8],
    ) -> Result<CiphertextMessage> {
        let (mut identity_key_store, _, _, mut session_store, _) = self.stores();
        message_encrypt(
            plaintext,
            remote_address,
            &mut session_store,
            &mut identity_key_store,
            None,
        )
        .await
    }

    pub async fn message_decrypt_prekey<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
        remote_address: &ProtocolAddress,
        ciphertext: &PreKeySignalMessage,
    ) -> Result<Vec<u8>> {
        let (
            mut identity_key_store,
            mut prekey_store,
            mut signed_prekey_store,
            mut session_store,
            _,
        ) = self.stores();
        message_decrypt_prekey(
            ciphertext,
            remote_address,
            &mut session_store,
            &mut identity_key_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            csprng,
            None,
        )
        .await
    }

    pub async fn message_decrypt_signal<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
        remote_address: &ProtocolAddress,
        ciphertext: &SignalMessage,
    ) -> Result<Vec<u8>> {
        let (mut identity_key_store, _, _, mut session_store, _) = self.stores();
        message_decrypt_signal(
            ciphertext,
            remote_address,
            &mut session_store,
            &mut identity_key_store,
            csprng,
            None,
        )
        .await
    }

    pub async fn process_prekey_bundle<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
        remote_address: &ProtocolAddress,
        bundle: &PreKeyBundle,
    ) -> Result<()> {
        let (mut identity_key_store, _, _, mut session_store, _) = self.stores();
        process_prekey_bundle(
            remote_address,
            &mut session_store,
            &mut identity_key_store,
            bundle,
            csprng,
            None,
        )
        .await
    }
}
