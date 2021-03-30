use std::fmt;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use derivative::Derivative;

use futures::channel::oneshot;
use prost::Message as _;

use rand::{CryptoRng, Rng};

mod provision_cipher;
use provision_cipher::ProvisionCipher;

use crate::proto;
use crate::webapi::sub_protocol::{RequestHandler, SubProtocol, SubProtocolCtx};

use super::WebAPIClient;

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

impl WebAPIClient {
    pub async fn link_device<R: Rng + CryptoRng>(
        &self,
        rnd: &mut R,
        provisioning_url: oneshot::Sender<ProvisioningUrl>,
    ) -> Result<DecryptedProvision> {
        // Generate provision cipher
        let provision_cipher = ProvisionCipher::generate(rnd);

        // Connect to provisioning API
        let (provision_msg_tx, mut provision_msg) = oneshot::channel();
        let provisioning_url = Some(provisioning_url);
        SubProtocol::connect(
            &self.http_client,
            format!(
                "{}/v1/websocket/provisioning/?agent=mpc-over-signal&version=0.1",
                self.ws_host()
            ),
            "/v1/keepalive/provisioning",
            Handler {
                provisioning_url,
                provision_cipher,
                provision_msg: Some(provision_msg_tx),
            },
        )
        .await?;

        provision_msg
            .try_recv()
            .context("receive provision msg has been canceled")?
            .ok_or_else(|| anyhow!("provision message must be here at this point"))
    }
}

pub struct Handler {
    provisioning_url: Option<oneshot::Sender<ProvisioningUrl>>,
    provision_cipher: ProvisionCipher,
    provision_msg: Option<oneshot::Sender<DecryptedProvision>>,
}

#[async_trait]
impl RequestHandler for Handler {
    async fn handle_request(
        &mut self,
        req: proto::WebSocketRequestMessage,
        ctx: &mut SubProtocolCtx,
    ) -> Result<proto::WebSocketResponseMessage> {
        if req.verb() == "PUT" && req.path() == "/v1/address" {
            let req = proto::ProvisioningUuid::decode(req.body()).context("parse request body")?;
            let signal_provisioning_url = format!(
                "tsdevice:/?uuid={}&pub_key={}",
                req.uuid(),
                urlencoding::encode(&base64::encode(self.provision_cipher.public_key()))
            );
            if let Some(provisioning_url) = self.provisioning_url.take() {
                provisioning_url
                    .send(ProvisioningUrl(signal_provisioning_url))
                    .map_err(|_| anyhow!("cannot send provisioning url: oneshot is canceled"))?
            }
        } else if req.verb() == "PUT" && req.path() == "/v1/message" {
            let req = proto::ProvisionEnvelope::decode(req.body()).context("parse request body")?;
            let mut msg = self.provision_cipher.decrypt(req)?;
            msg.uuid.make_ascii_lowercase();
            if let Some(provision_msg) = self.provision_msg.take() {
                provision_msg
                    .send(msg)
                    .map_err(|_| anyhow!("cannot send provisioning url: oneshot is canceled"))?
            }
            ctx.terminate();
        } else {
            eprintln!("Received unexpected request {} {}", req.verb(), req.path());
            return Ok(proto::WebSocketResponseMessage {
                id: None,
                status: Some(404),
                message: Some("Not Found".into()),
                headers: vec![],
                body: None,
            });
        }
        Ok(proto::WebSocketResponseMessage {
            id: None,
            status: Some(200),
            message: Some("OK".into()),
            headers: vec![],
            body: None,
        })
    }
}
