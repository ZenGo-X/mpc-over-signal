use std::collections::HashMap;
use std::time::SystemTime;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use libsignal_protocol::{
    IdentityKeyPair, KeyPair, PreKeyRecord, ProtocolAddress, SenderKeyName, SenderKeyRecord,
    SessionRecord,
};

use crate::helpers::serde as serde_helpers;

#[derive(Serialize, Deserialize)]
pub struct DeviceKeys {
    #[serde(with = "crate::helpers::serde::identity_key_pair")]
    pub identity_key_pair: IdentityKeyPair,
    pub signed_pre_key: SignedPreKey,
    pub pre_keys: Vec<PreKey>,

    pub old_signed_prekeys: Vec<SignedPreKey>,
    #[serde(
        with = "serde_helpers::hash_map::UsingWrappers::<serde_helpers::protocol_address::Wrapper, serde_helpers::session_record::Wrapper>"
    )]
    pub sessions: HashMap<ProtocolAddress, SessionRecord>,
    #[serde(
        with = "serde_helpers::hash_map::UsingWrappers::<serde_helpers::sender_key_name::Wrapper, serde_helpers::sender_key_record::Wrapper>"
    )]
    pub sender_keys: HashMap<SenderKeyName, SenderKeyRecord>,
}

#[derive(Serialize, Deserialize)]
pub struct SignedPreKey {
    pub id: u32,
    pub created: SystemTime,
    #[serde(with = "crate::helpers::serde::key_pair")]
    pub key_pair: KeyPair,
    #[serde(with = "crate::helpers::serde::base64_encoded")]
    pub signature: Box<[u8]>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreKey {
    pub id: u32,
    #[serde(with = "crate::helpers::serde::key_pair")]
    pub key_pair: KeyPair,
}

impl From<&PreKey> for PreKeyRecord {
    fn from(k: &PreKey) -> Self {
        PreKeyRecord::new(k.id, &k.key_pair)
    }
}

impl DeviceKeys {
    pub fn generate<R: rand::Rng + rand::CryptoRng>(
        rnd: &mut R,
        identity_key_pair: IdentityKeyPair,
    ) -> Result<DeviceKeys> {
        Self::generate_with_options(rnd, identity_key_pair, 0, 0, 5)
    }

    pub fn generate_with_options<R: rand::Rng + rand::CryptoRng>(
        rnd: &mut R,
        identity_key_pair: IdentityKeyPair,
        signed_pre_key_id: u32,
        first_pre_key_id: u32,
        pre_keys_count: usize,
    ) -> Result<DeviceKeys> {
        let signed_pre_key = KeyPair::generate(rnd);
        let signed_pre_key_public = signed_pre_key.public_key.serialize();
        let signature = identity_key_pair
            .private_key()
            .calculate_signature(&signed_pre_key_public, rnd)
            .map_err(|e| anyhow!("sign pre key: {}", e))?;

        let signed_pre_key = SignedPreKey {
            id: signed_pre_key_id,
            created: SystemTime::now(),
            key_pair: signed_pre_key,
            signature,
        };

        let pre_keys = (first_pre_key_id..)
            .take(pre_keys_count)
            .map(|id| {
                let key_pair = KeyPair::generate(rnd);
                PreKey { id, key_pair }
            })
            .collect();

        Ok(Self {
            identity_key_pair,
            signed_pre_key,
            pre_keys,
            old_signed_prekeys: Default::default(),
            sessions: Default::default(),
            sender_keys: Default::default(),
        })
    }
}
