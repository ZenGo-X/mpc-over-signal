use derivative::Derivative;
use serde::{Deserialize, Serialize};

use libsignal_protocol::{IdentityKey, PublicKey};

use crate::device::DeviceKeys;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitDevicePublicKeys {
    #[serde(with = "crate::helpers::serde::identity_key")]
    pub identity_key: IdentityKey,
    pub signed_pre_key: SignedPublicPreKey,
    pub pre_keys: Vec<PublicPreKey>,
}

impl From<&DeviceKeys> for SubmitDevicePublicKeys {
    fn from(private_keys: &DeviceKeys) -> Self {
        Self {
            identity_key: private_keys.identity_key_pair.identity_key().clone(),
            signed_pre_key: SignedPublicPreKey {
                key_id: private_keys.signed_pre_key.id,
                public_key: private_keys.signed_pre_key.key_pair.public_key.clone(),
                signature: private_keys.signed_pre_key.signature.clone(),
            },
            pre_keys: private_keys
                .pre_keys
                .iter()
                .map(|k| PublicPreKey {
                    key_id: k.id,
                    public_key: k.key_pair.public_key.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct RetrievedDevicePublicKeysResponse {
    #[serde(with = "crate::helpers::serde::identity_key")]
    #[derivative(Debug(format_with = "crate::helpers::fmt::identity_key"))]
    pub identity_key: IdentityKey,
    pub devices: Vec<RetrievedDevicePublicKeysItem>,
}

#[derive(Serialize, Deserialize, Derivative, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct RetrievedDevicePublicKeysItem {
    pub device_id: u32,
    pub signed_pre_key: SignedPublicPreKey,
    #[serde(default)]
    pub pre_key: Option<PublicPreKey>,
    pub registration_id: u32,
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignedPublicPreKey {
    pub key_id: u32,
    #[serde(with = "crate::helpers::serde::public_key")]
    #[derivative(Debug(format_with = "crate::helpers::fmt::public_key"))]
    pub public_key: PublicKey,
    #[serde(with = "crate::helpers::serde::base64_encoded")]
    #[derivative(Debug(format_with = "crate::helpers::fmt::base64_encoded"))]
    pub signature: Box<[u8]>,
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
#[serde(rename_all = "camelCase")]
pub struct PublicPreKey {
    pub key_id: u32,
    #[serde(with = "crate::helpers::serde::public_key")]
    #[derivative(Debug(format_with = "crate::helpers::fmt::public_key"))]
    pub public_key: PublicKey,
}
