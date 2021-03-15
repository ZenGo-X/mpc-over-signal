use std::iter;
use std::time::SystemTime;
use std::{future::Future, pin::Pin};

use awc::http::StatusCode;
use awc::Client;

use anyhow::{anyhow, bail, Context, Result};
use derivative::Derivative;
use serde::{Deserialize, Serialize};

use libsignal_protocol::ProtocolAddress;

use crate::device::{DeviceAuth, DeviceCreds};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SendMessagesRequest<'m> {
    pub messages: &'m [Message<'m>],
    pub timestamp: u64,
    pub online: bool,
}

#[derive(Serialize, Derivative)]
#[derivative(Debug)]
#[serde(rename_all = "camelCase")]
struct Message<'m> {
    #[serde(rename = "type")]
    pub type_: u8,
    pub destination: &'m str,
    pub destination_device_id: u32,
    pub destination_registration_id: i64,
    #[serde(with = "crate::helpers::serde::base64_encoded")]
    #[derivative(Debug(format_with = "crate::helpers::fmt::base64_encoded"))]
    pub content: &'m [u8],
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MismatchedDevices {
    pub missing_devices: Vec<u32>,
    pub extra_devices: Vec<u32>,
}

fn noop_message(destination: &str, destination_device_id: u32) -> Message {
    Message {
        type_: 0,
        destination,
        destination_device_id,
        destination_registration_id: -1,
        content: &[],
    }
}

pub async fn send_messages(
    client: &Client,
    creds: &DeviceCreds,
    message_type: u8,
    destination: &ProtocolAddress,
    destination_registration_id: Option<u32>,
    message: impl AsRef<[u8]>,
) -> Result<()> {
    send_messages_with_known_total_devices(
        client,
        creds,
        message_type,
        destination,
        destination_registration_id,
        message.as_ref(),
        None,
    )
    .await
}

fn send_messages_with_known_total_devices<'s>(
    client: &'s Client,
    creds: &'s DeviceCreds,
    message_type: u8,
    destination: &'s ProtocolAddress,
    destination_registration_id: Option<u32>,
    message_content: &'s [u8],
    total_devices: Option<u32>,
) -> Pin<Box<dyn Future<Output = Result<()>> + 's>> {
    Box::pin(async move {
        let message = Message {
            type_: message_type,
            destination: destination.name(),
            destination_device_id: destination.device_id(),
            destination_registration_id: destination_registration_id.map(i64::from).unwrap_or(-1),
            content: message_content,
        };
        let noop_messages_before =
            (1..destination.device_id()).map(|i| noop_message(destination.name(), i));
        let noop_messages_after = total_devices
            .map(|n| (destination.device_id() + 1..=n))
            .into_iter()
            .flatten()
            .map(|i| noop_message(destination.name(), i));
        let messages: Vec<_> = noop_messages_before
            .chain(iter::once(message))
            .chain(noop_messages_after)
            .collect();

        let response_body = SendMessagesRequest {
            messages: messages.as_ref(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .context("broken clocks")?
                .as_secs(),
            online: false,
        };
        println!("Send request: {:#?}", response_body);
        let mut response = client
            .put(format!(
                "https://textsecure-service.whispersystems.org/v1/messages/{}",
                destination.name()
            ))
            .device_auth(&creds)
            .send_json(&response_body)
            .await
            .map_err(|e| anyhow!("sending messages: {}", e))?;

        if response.status() == StatusCode::CONFLICT {
            let mismatched_devices: MismatchedDevices = response
                .json()
                .await
                .map_err(|e| anyhow!("failed to parse mismatched devices: {}", e))?;
            if !mismatched_devices.extra_devices.is_empty() {
                bail!("server returned 409 Conflict: {:?}", mismatched_devices);
            }
            if mismatched_devices.missing_devices.is_empty() {
                bail!("server returned 409 Conflict: {:?}", mismatched_devices);
            }

            let max_device_id = *mismatched_devices
                .missing_devices
                .iter()
                .max()
                .expect("guaranteed by if statement above");
            if Some(max_device_id) != total_devices {
                return send_messages_with_known_total_devices(
                    client,
                    creds,
                    message_type,
                    destination,
                    destination_registration_id,
                    message_content,
                    Some(max_device_id),
                )
                .await;
            } else {
                bail!(
                    "sending messages: server returned {}, response: {:?}",
                    response.status(),
                    mismatched_devices
                );
            }
        } else if !response.status().is_success() {
            let body = response.body().await.context("receiving body")?;
            bail!(
                "sending messages: server returned {}, response: {}",
                response.status(),
                String::from_utf8_lossy(&body)
            );
        }

        Ok(())
    })
}
