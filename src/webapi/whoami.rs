use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::device::{DeviceAuth, DeviceCreds};

use super::WebAPIClient;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Whoami {
    pub uuid: String,
    pub storage_capable: bool,
}

impl WebAPIClient {
    #[allow(dead_code)]
    pub async fn whoami(&self, creds: &DeviceCreds) -> Result<Whoami> {
        let mut response = self
            .http_client
            .get("https://textsecure-service.whispersystems.org/v1/accounts/whoami")
            .device_auth(&creds)
            .send()
            .await
            .map_err(|e| anyhow!("whoami: {}", e))?;
        ensure!(
            response.status().is_success(),
            "server returned an error code {}",
            response.status()
        );
        response.json().await.context("parse response")
    }
}
