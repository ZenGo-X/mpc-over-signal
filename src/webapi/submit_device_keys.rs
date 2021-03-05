use awc::http::StatusCode;
use awc::Client;
use serde::Serialize;

use anyhow::{anyhow, ensure, Result};

use super::create_device::DeviceCreds;
use crate::device_keys::DeviceKeys;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitDeviceKeysRequest {
    identity_key: String,
    signed_pre_key: SignedPublicPreKey,
    pre_keys: Vec<PublicPreKey>,
    last_resort_key: LastResortKey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedPublicPreKey {
    key_id: u32,
    public_key: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicPreKey {
    key_id: u32,
    public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LastResortKey {
    key_id: u32,
    public_key: String,
}

pub async fn submit_device_keys(
    client: &Client,
    creds: &DeviceCreds,
    keys: &DeviceKeys,
) -> Result<()> {
    let identity_key = keys.identity_key_pair.serialize();
    let identity_key = base64::encode(identity_key);

    let signed_pre_key_pk = base64::encode(keys.signed_pre_key.key_pair.public_key.serialize());
    let signed_pre_key_signature = base64::encode(&keys.signed_pre_key.signature);
    let signed_pre_key = SignedPublicPreKey {
        key_id: keys.signed_pre_key.id,
        public_key: signed_pre_key_pk,
        signature: signed_pre_key_signature,
    };

    let pre_keys = keys
        .pre_keys
        .iter()
        .map(|pre_key| PublicPreKey {
            key_id: pre_key.id,
            public_key: base64::encode(pre_key.key_pair.public_key.serialize()),
        })
        .collect();

    let request_body = SubmitDeviceKeysRequest {
        identity_key,
        signed_pre_key,
        pre_keys,
        last_resort_key: LastResortKey {
            key_id: 0x7fffffff,
            public_key: base64::encode("42"),
        },
    };

    let response = client
        .put("https://textsecure-service.whispersystems.org/v2/keys")
        .basic_auth(&creds.username, Some(&creds.password_64))
        .send_json(&request_body)
        .await
        .map_err(|e| anyhow!("submitting keys: {}", e))?;

    ensure!(
        response.status() == StatusCode::NO_CONTENT,
        "submitting device keys: server returned {}",
        response.status()
    );

    Ok(())
}
