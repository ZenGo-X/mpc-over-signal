use awc::Client;
use serde::{Deserialize, Serialize};

use crate::webapi::DeviceCreds;
use anyhow::{anyhow, ensure, Context, Result};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Whoami {
    pub uuid: String,
    pub storage_capable: bool,
}

pub async fn whoami(client: &Client, creds: &DeviceCreds) -> Result<Whoami> {
    let mut response = client
        .get("https://textsecure-service.whispersystems.org/v1/accounts/whoami")
        .basic_auth(&creds.username, Some(&creds.password_64))
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
