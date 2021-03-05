use std::fmt;

use actix::utils::Condition;
use awc::ws::{Frame, Message};
use awc::Client;
use futures::{SinkExt, StreamExt};
use prost::Message as _;

use anyhow::{anyhow, bail, ensure, Context, Result};
use derivative::Derivative;
use rand::{CryptoRng, Rng};

mod provision_cipher;
use provision_cipher::ProvisionCipher;

use crate::proto;
use crate::proto::web_socket_message::Type;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct DecryptedProvision {
    #[derivative(Debug(format_with = "crate::helpers::fmt::hide_content"))]
    pub identity_key_pair: libsignal_protocol::IdentityKeyPair,
    pub number: String,
    pub uuid: String,
    pub provisioning_code: String,
    pub user_agent: String,
    pub read_receipts: bool,
    #[derivative(Debug(format_with = "crate::helpers::fmt::hide_content"))]
    pub profile_key: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct ProvisioningUrl(String);

impl fmt::Display for ProvisioningUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub async fn link_device<R: Rng + CryptoRng>(
    rnd: &mut R,
    client: &Client,
    provisioning_url: Condition<ProvisioningUrl>,
) -> Result<DecryptedProvision> {
    // Generate provision cipher
    let provision_cipher = ProvisionCipher::generate(rnd);

    // Connect to provisioning API
    let (_resp, mut conn) = client
        .ws("wss://textsecure-service.whispersystems.org/v1/websocket/provisioning/?agent=mpc-over-signal&version=0.1")
        .connect()
        .await
        .map_err(|e| anyhow!("connecting to Signal Provisioning API: {:?}", e))?;

    // Receive provisioning address
    let msg = conn
        .next()
        .await
        .context("receiving address")?
        .context("receiving address")?;
    let msg = match msg {
        Frame::Binary(msg) => msg,
        _ => bail!("unexpected msg: {:?}", msg),
    };

    let req = proto::WebSocketMessage::decode(msg.as_ref()).context("parse address req")?;
    ensure!(
        req.r#type() == Type::Request,
        "expected to receive request, received {:?}",
        req.r#type()
    );
    ensure!(req.request.is_some(), "missing request body");

    let req = req.request.expect("guaranteed by ensure! above");
    let req_id = req.id;
    ensure!(
        req.verb() == "PUT" && req.path() == "/v1/address",
        "expected PUT /v1/address request, received {} {}",
        req.verb(),
        req.path(),
    );

    let req = proto::ProvisioningUuid::decode(req.body()).context("parse request body")?;
    let signal_provisioning_url = format!(
        "tsdevice:/?uuid={}&pub_key={}",
        req.uuid(),
        urlencoding::encode(&base64::encode(&provision_cipher.public_key()))
    );

    let resp = proto::WebSocketMessage {
        r#type: Some(Type::Response as _),
        request: None,
        response: Some(proto::WebSocketResponseMessage {
            id: req_id,
            status: Some(200),
            message: Some("OK".into()),
            headers: vec![],
            body: None,
        }),
    };
    let mut resp_bytes: Vec<u8> = vec![];
    resp.encode(&mut resp_bytes).context("encode response")?;
    conn.send(Message::Binary(resp_bytes.into()))
        .await
        .context("send response")?;

    // Display provisioning url
    provisioning_url.set(ProvisioningUrl(signal_provisioning_url));

    // Receive provisioning message
    let msg = conn
        .next()
        .await
        .context("receiving provisioning message")?
        .context("receiving provisioning message")?;
    let msg = match msg {
        Frame::Binary(msg) => msg,
        _ => bail!("unexpected msg: {:?}", msg),
    };

    let req = proto::WebSocketMessage::decode(msg.as_ref()).context("parse address req")?;
    ensure!(
        req.r#type() == Type::Request,
        "expected to receive request, received {:?}",
        req.r#type()
    );
    ensure!(req.request.is_some(), "missing request body");

    let req = req.request.expect("guaranteed by ensure! above");
    let req_id = req.id;
    ensure!(
        req.verb() == "PUT" && req.path() == "/v1/message",
        "expected PUT /v1/message request, received {} {}",
        req.verb(),
        req.path(),
    );

    let req = proto::ProvisionEnvelope::decode(req.body()).context("parse request body")?;

    let resp = proto::WebSocketMessage {
        r#type: Some(Type::Response as _),
        request: None,
        response: Some(proto::WebSocketResponseMessage {
            id: req_id,
            status: Some(200),
            message: Some("OK".into()),
            headers: vec![],
            body: None,
        }),
    };
    let mut resp_bytes: Vec<u8> = vec![];
    resp.encode(&mut resp_bytes).context("encode response")?;
    conn.send(Message::Binary(resp_bytes.into()))
        .await
        .context("send response")?;
    SinkExt::close(&mut conn)
        .await
        .context("close provision connection")?;

    provision_cipher.decrypt(req)
}
