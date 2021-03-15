use awc::Client;

use anyhow::{anyhow, bail, ensure, Context, Result};

use awc::ws::{Frame, Message};
use futures::channel::mpsc::Sender;
use futures::{SinkExt, StreamExt};
use prost::Message as _;

use crate::device::DeviceCreds;
use crate::proto;
use crate::proto::web_socket_message::Type;

pub async fn receive_messages(
    client: &Client,
    creds: &DeviceCreds,
    mut messages: Sender<proto::Envelope>,
) -> Result<()> {
    // Connect to provisioning API
    let (_resp, mut conn) = client
        .ws(format!("wss://textsecure-service.whispersystems.org/v1/websocket/?login={}&password={}&agent=mpc-over-signal&version=0.1",
            creds.login(),
            creds.password(),
        ))
        .connect()
        .await
        .map_err(|e| anyhow!("connecting to Signal Provisioning API: {:?}", e))?;

    loop {
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
        if !(req.verb() == "PUT" && req.path() == "/api/v1/message") {
            // TODO: implement handling of other requests
            eprintln!(
                "Received {} {} that cannot be handled (not implemented)",
                req.verb(),
                req.path()
            );
            continue;
        }

        if req
            .headers
            .iter()
            .find(|h| h.as_str() == "X-Signal-Key: true")
            .is_some()
        {
            // TODO: implement signalling decryption
            eprintln!("Signalling message is encrypted, decryption is not implemented!");
            continue;
        }

        let msg = proto::Envelope::decode(req.body()).context("parse Envelope message")?;

        messages
            .send(msg)
            .await
            .context("message receiving stopped")?;

        // Inform server that message is received
        // TODO: inform server when message is not handled
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
    }
}
