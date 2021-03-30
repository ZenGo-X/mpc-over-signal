use anyhow::{anyhow, ensure, Result};

use super::types::SubmitDevicePublicKeys;
use crate::device::{DeviceAuth, DeviceCreds};
use crate::webapi::WebAPIClient;

impl WebAPIClient {
    pub async fn submit_device_keys(
        &self,
        creds: &DeviceCreds,
        keys: &SubmitDevicePublicKeys,
    ) -> Result<()> {
        let response = self
            .http_client
            .put(format!("{}/v2/keys", self.server_host))
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
}
