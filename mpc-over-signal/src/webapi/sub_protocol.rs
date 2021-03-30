use std::convert::TryFrom;
use std::ops::DerefMut;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use actix_codec::Framed;
use awc::error::WsProtocolError;
use awc::ws::{Codec, Frame, Message};
use awc::{http, BoxedSocket, Client};
use futures::stream::SplitSink;
use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

use prost::Message as _;

use anyhow::{anyhow, bail, ensure, Context, Result};
use async_trait::async_trait;

use crate::proto;
use crate::proto::web_socket_message::Type;

pub struct SubProtocol {
    output: Mutex<SplitSink<Framed<BoxedSocket, Codec>, Message>>,
    last_time_we_received_message: LastSeenMessageTime,
}

struct LastSeenMessageTime {
    protocol_start: Instant,
    last_seen_from_start_in_secs: AtomicU64,
}

impl LastSeenMessageTime {
    pub fn never_received() -> Self {
        Self {
            protocol_start: Instant::now(),
            last_seen_from_start_in_secs: AtomicU64::new(0),
        }
    }

    pub fn when(&self) -> Option<Instant> {
        let secs_from_start = self.last_seen_from_start_in_secs.load(Ordering::Relaxed);
        if secs_from_start == 0 {
            None
        } else {
            Some(self.protocol_start + Duration::from_secs(secs_from_start))
        }
    }

    pub fn received_now(&self) {
        let secs = Instant::now().duration_since(self.protocol_start).as_secs();
        self.last_seen_from_start_in_secs
            .store(u64::min(secs, 1), Ordering::Relaxed);
    }
}

pub struct SubProtocolCtx {
    terminated: bool,
}

impl SubProtocolCtx {
    fn new() -> Self {
        Self { terminated: false }
    }
    pub fn terminate(&mut self) {
        self.terminated = true
    }
}

impl SubProtocol {
    pub async fn connect<U, H>(
        client: &Client,
        url: U,
        keepalive_path: &str,
        handler: H,
    ) -> Result<()>
    where
        http::Uri: TryFrom<U>,
        <http::Uri as TryFrom<U>>::Error: Into<http::Error>,
        H: RequestHandler,
    {
        let (_resp, conn) = client
            .ws(url)
            .connect()
            .await
            .map_err(|e| anyhow!("establish websocket connection: {}", e))?;

        let (output, input) = conn.split();

        let sub_protocol = Arc::new(SubProtocol {
            output: Mutex::new(output),
            last_time_we_received_message: LastSeenMessageTime::never_received(),
        });

        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                tokio::task::spawn_local(run_keepalive(
                    sub_protocol.clone(),
                    keepalive_path.into(),
                ));
                process_incoming(sub_protocol, input, handler).await
            })
            .await?;
        Ok(())
    }
}

async fn process_incoming<S, H>(
    sub_protocol: Arc<SubProtocol>,
    mut input: S,
    mut handler: H,
) -> Result<()>
where
    S: Stream<Item = Result<Frame, WsProtocolError>> + Unpin,
    H: RequestHandler,
{
    loop {
        let msg = input
            .next()
            .await
            .context("receiving next sub protocol message")?
            .context("receiving next sub protocol message")?;

        sub_protocol.last_time_we_received_message.received_now();

        let msg = match msg {
            Frame::Binary(msg) => msg,
            _ => bail!("unexpected msg: {:?}", msg),
        };

        let req = proto::WebSocketMessage::decode(msg.as_ref()).context("parse address req")?;
        if req.r#type() != Type::Request {
            eprintln!("Received Response, it cannot be handled now (not implemented)");
            continue;
        }
        ensure!(req.request.is_some(), "missing request body");

        let req = req.request.expect("guaranteed by ensure! above");
        let req_id = req.id;

        let mut ctx = SubProtocolCtx::new();
        let mut response = handler.handle_request(req, &mut ctx).await?;
        response.id = req_id;
        let mut response = proto::WebSocketMessage {
            r#type: None,
            request: None,
            response: Some(response),
        };
        response.set_type(Type::Response);

        let mut response_bytes: Vec<u8> = vec![];
        response
            .encode(&mut response_bytes)
            .context("encode response")?;

        let mut output = sub_protocol.output.lock().await;
        output
            .send(Message::Binary(response_bytes.into()))
            .await
            .context("send response")?;
        drop(output);

        if ctx.terminated {
            return Ok(());
        }
    }
}

async fn run_keepalive(sub_protocol: Arc<SubProtocol>, path: String) -> Result<()> {
    let interval = Duration::from_secs(55);

    tokio::time::sleep(interval).await;
    loop {
        let now = Instant::now();
        let last_received_message_time = sub_protocol.last_time_we_received_message.when();
        let need_to_send_keepalive = last_received_message_time
            .map(|t| t + interval < now)
            .unwrap_or(true);

        let sleep_until;
        if need_to_send_keepalive {
            let mut output = sub_protocol.output.lock().await;
            send_keepalive(path.clone(), output.deref_mut()).await?;
            sleep_until = now + interval;
        } else {
            let t = last_received_message_time.expect("guaranteed by need_to_send_keepalive");
            sleep_until = t + interval;
        }

        tokio::time::sleep_until(sleep_until).await;
    }
}

async fn send_keepalive<S>(path: String, output: &mut S) -> Result<()>
where
    S: Sink<Message, Error = WsProtocolError> + Unpin,
{
    let request = proto::WebSocketRequestMessage {
        id: None,
        verb: Some("GET".into()),
        path: Some(path),
        headers: vec![],
        body: None,
    };
    let mut request = proto::WebSocketMessage {
        r#type: None,
        request: Some(request),
        response: None,
    };
    request.set_type(Type::Request);

    let mut request_bytes: Vec<u8> = vec![];
    request
        .encode(&mut request_bytes)
        .context("encode response")?;
    output
        .send(Message::Binary(request_bytes.into()))
        .await
        .context("send response")?;

    Ok(())
}

#[async_trait]
pub trait RequestHandler {
    async fn handle_request(
        &mut self,
        request: proto::WebSocketRequestMessage,
        ctx: &mut SubProtocolCtx,
    ) -> Result<proto::WebSocketResponseMessage>;
}
