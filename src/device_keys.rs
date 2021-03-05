use std::time::SystemTime;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use libsignal_protocol::{IdentityKeyPair, KeyPair};

use crate::webapi::DeviceCreds;

#[derive(Serialize, Deserialize)]
pub struct Device {
    pub creds: DeviceCreds,
    #[serde(flatten)]
    pub keys: DeviceKeys,
}

#[derive(Serialize, Deserialize)]
pub struct DeviceKeys {
    #[serde(with = "crate::helpers::serde::identity_key_pair")]
    pub identity_key_pair: IdentityKeyPair,
    pub signed_pre_key: SignedPreKey,
    pub pre_keys: Vec<PreKey>,
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

#[derive(Serialize, Deserialize)]
pub struct PreKey {
    pub id: u32,
    #[serde(with = "crate::helpers::serde::key_pair")]
    pub key_pair: KeyPair,
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
        })
    }
}
