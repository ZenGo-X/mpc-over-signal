use std::fmt;

use awc::http::StatusCode;
use awc::Client;
use serde::{Deserialize, Serialize};

use anyhow::{anyhow, ensure, Context, Result};
use derivative::Derivative;
use rand::{CryptoRng, Rng};

use super::link_device::DecryptedProvision;

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct DeviceCreds {
    pub username: Username,
    #[derivative(Debug(format_with = "crate::helpers::fmt::hide_content"))]
    pub password_64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Username {
    pub name: String,
    pub device_id: u32,
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.name, self.device_id)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateDeviceRequest {
    pub name: String,
    pub fetches_messages: bool,
    pub registration_id: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateDeviceResponse {
    pub device_id: u32,
}

pub async fn create_device<R: Rng + CryptoRng>(
    rnd: &mut R,
    client: &Client,
    provision: &DecryptedProvision,
    device_name: String,
) -> Result<DeviceCreds> {
    let mut password = [0u8; 16];
    rnd.fill_bytes(&mut password);
    let mut password_64 = base64::encode(password);
    password_64.drain(password_64.len() - 2..);

    let registration_id = rnd.gen::<u16>() & 0x3fff;

    let request_body = CreateDeviceRequest {
        name: device_name,
        fetches_messages: true,
        registration_id,
    };

    let mut response = client
        .put(format!(
            "https://textsecure-service.whispersystems.org/v1/devices/{}",
            provision.provisioning_code
        ))
        .basic_auth(&provision.number, Some(&password_64))
        .send_json(&request_body)
        .await
        .map_err(|e| anyhow!("creating new device: {}", e))?;

    ensure!(
        response.status() == StatusCode::OK,
        "creating new device: server returned {}",
        response.status()
    );

    let created_device: CreateDeviceResponse =
        response.json().await.context("parse server response")?;

    Ok(DeviceCreds {
        username: Username {
            name: provision.number.clone(),
            device_id: created_device.device_id,
        },
        password_64,
    })
}
