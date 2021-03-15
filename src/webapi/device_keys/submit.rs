use awc::Client;

use anyhow::{anyhow, ensure, Result};

use super::types::SubmitDevicePublicKeys;
use crate::device::{DeviceAuth, DeviceCreds};

pub async fn submit_device_keys(
    client: &Client,
    creds: &DeviceCreds,
    keys: &SubmitDevicePublicKeys,
) -> Result<()> {
    let response = client
        .put("https://textsecure-service.whispersystems.org/v2/keys")
        .device_auth(&creds)
        .send_json(keys)
        .await
        .map_err(|e| anyhow!("submitting keys: {}", e))?;

    ensure!(
        response.status().is_success(),
        "submitting device keys: server returned {}",
        response.status()
    );

    Ok(())
}
