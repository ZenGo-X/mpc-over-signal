use anyhow::{Context, Result};
use async_trait::async_trait;

use futures::channel::mpsc::Sender;
use futures::SinkExt;
use prost::Message as _;

use crate::device::DeviceCreds;
use crate::proto;
use crate::webapi::sub_protocol::{RequestHandler, SubProtocol, SubProtocolCtx};

use super::WebAPIClient;

impl WebAPIClient {
    pub async fn receive_messages(
        &self,
        creds: &DeviceCreds,
        messages: Sender<proto::Envelope>,
    ) -> Result<()> {
        SubProtocol::connect(
            &self.http_client,
            format!(
                "{}/v1/websocket/?login={}&password={}&agent=mpc-over-signal&version=0.1",
                self.ws_host(),
                creds.login(),
                creds.password(),
            ),
            "/v1/keepalive",
            Handler { messages },
        )
        .await
    }
}

struct Handler {
    messages: Sender<proto::Envelope>,
}

#[async_trait]
impl RequestHandler for Handler {
    async fn handle_request(
        &mut self,
        req: proto::WebSocketRequestMessage,
        _ctx: &mut SubProtocolCtx,
    ) -> Result<proto::WebSocketResponseMessage> {
        if !(req.verb() == "PUT" && req.path() == "/api/v1/message") {
            return Ok(proto::WebSocketResponseMessage {
                id: req.id,
                status: Some(200),
                message: Some("OK".into()),
                headers: vec![],
                body: None,
            });
        }

        if req
            .headers
            .iter()
            .any(|h| h.as_str() == "X-Signal-Key: true")
        {
            // TODO: implement signalling decryption
            eprintln!("Signalling message is encrypted, decryption is not implemented!");
            return Ok(proto::WebSocketResponseMessage {
                id: req.id,
                status: Some(500),
                message: Some("Internal Error".into()),
                headers: vec![],
                body: None,
            });
        }

        let mut msg = proto::Envelope::decode(req.body()).context("parse Envelope message")?;
        // Shadow sender's phone number
        msg.source = None;

        self.messages
            .send(msg)
            .await
            .context("message receiving stopped")?;

        Ok(proto::WebSocketResponseMessage {
            id: req.id,
            status: Some(200),
            message: Some("OK".into()),
            headers: vec![],
            body: None,
        })
    }
}
