use std::collections::HashMap;

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};

use libsignal_protocol::error::Result;
use libsignal_protocol::{
    message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    CiphertextMessage, IdentityKey, PreKeyBundle, PreKeySignalMessage, ProtocolAddress,
    SignalMessage,
};
use libsignal_protocol::{
    IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
};
use rand::{CryptoRng, Rng};

mod creds;
mod device_store;
mod keys;
mod stores;

pub use creds::{DeviceAuth, DeviceCreds, Username};
pub use device_store::DeviceStore;
pub use keys::{DeviceKeys, PreKey, SignedPreKey};

use crate::helpers::serde as serde_helpers;
use crate::{Group, ParticipantIdentity};

#[derive(Serialize, Deserialize)]
pub struct Device {
    pub(crate) creds: DeviceCreds,
    #[serde(flatten)]
    keys: DeviceKeys,
    #[serde(
        with = "serde_helpers::hash_map::UsingWrappers::<serde_helpers::protocol_address::Wrapper, serde_helpers::identity_key::Wrapper>"
    )]
    trusted_parties: HashMap<ProtocolAddress, IdentityKey>,
}

impl Device {
    pub(crate) fn new(creds: DeviceCreds, keys: DeviceKeys) -> Self {
        Self {
            creds,
            keys,
            trusted_parties: Default::default(),
        }
    }

    pub fn trust_to(&mut self, group: &Group) -> anyhow::Result<()> {
        for party in &group.participants {
            if party == &self.me() {
                continue;
            }
            if let Some(existing) = self.trusted_parties.get(&party.addr) {
                if existing != &party.public_key {
                    bail!(
                        "party {} already in list of trusted with different public key",
                        party.addr
                    );
                }
            }
        }

        for party in &group.participants {
            if party == &self.me() {
                continue;
            }
            let _ = self
                .trusted_parties
                .insert(party.addr.clone(), party.public_key);
        }
        Ok(())
    }

    pub fn is_known_party(&self, address: &ProtocolAddress) -> bool {
        self.trusted_parties.contains_key(address)
    }

    pub fn is_trusted_party(&self, address: &ProtocolAddress, public_key: &IdentityKey) -> bool {
        self.trusted_parties
            .get(address)
            .map(|k| k == public_key)
            .unwrap_or(false)
    }

    pub fn me(&self) -> ParticipantIdentity {
        ParticipantIdentity {
            addr: ProtocolAddress::new(
                self.creds.username.name.clone(),
                self.creds.username.device_id,
            ),
            public_key: *self.keys.identity_key_pair.identity_key(),
        }
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
                trusted_keys: &mut self.trusted_parties,
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

    pub async fn message_decrypt<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
        remote_address: &ProtocolAddress,
        ciphertext: &CiphertextMessage,
    ) -> anyhow::Result<Vec<u8>> {
        match ciphertext {
            CiphertextMessage::SignalMessage(msg) => self
                .message_decrypt_signal(csprng, remote_address, msg)
                .await
                .map_err(|e| anyhow!("{}", e)),
            CiphertextMessage::PreKeySignalMessage(msg) => self
                .message_decrypt_prekey(csprng, remote_address, msg)
                .await
                .map_err(|e| anyhow!("{}", e)),
            _ => bail!("unexpected cipher message"),
        }
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

    // TODO: implement clean_signed_pre_keys_older_than
    // pub fn clean_signed_pre_keys_older_than(&mut self, _age: Duration) {
    //
    // }
}
