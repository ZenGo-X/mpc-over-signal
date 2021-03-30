use std::{
    iter,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

use actix::Actor;
use actix_rt::task::JoinHandle;
use awc::Connector;
use futures::channel::{mpsc, oneshot};
use futures::{stream, Sink, SinkExt, Stream, StreamExt, TryStreamExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::PollSemaphore;

use tracing::{event, span, Instrument, Level};

use libsignal_protocol::ProtocolAddress;
use rand::{CryptoRng, Rng};
use round_based::Msg;

use crate::device::{DeviceCreds, DeviceKeys, DeviceStore};
use crate::webapi::{ProvisioningUrl, WebAPIClient};
use crate::{actors, proto, Device, Group};

static MPC_MESSAGE_TAG: &[u8] = b"MPC_OVER_SIGNAL_MESSAGE:";

pub struct SignalClient {
    webapi_client: WebAPIClient,
}

impl SignalClient {
    pub fn new() -> Result<Self> {
        Ok(Self::builder()?.finish())
    }

    pub fn builder() -> Result<SignalClientBuilder> {
        SignalClientBuilder::new()
    }

    pub async fn login<R: Rng + CryptoRng>(
        &self,
        rnd: &mut R,
        provision_url: oneshot::Sender<ProvisioningUrl>,
        device_name: String,
    ) -> Result<Device> {
        let provision_msg = self
            .webapi_client
            .link_device(rnd, provision_url)
            .await
            .context("obtaining provision message")?;
        let creds = self
            .webapi_client
            .create_device(rnd, &provision_msg, device_name)
            .await
            .context("creating new device")?;
        let device_keys = DeviceKeys::generate(rnd, provision_msg.identity_key_pair)
            .context("generate device keys")?;
        self.webapi_client
            .submit_device_keys(&creds, &(&device_keys).into())
            .await
            .context("register device keys")?;
        Ok(Device::new(creds, device_keys))
    }

    pub async fn start_listening_for_incoming_messages(
        self,
        device_secrets: DeviceStore,
    ) -> Result<SignalClientConnected> {
        SignalClientConnected::connect(self.webapi_client, device_secrets).await
    }
}

pub struct SignalClientBuilder {
    webapi_client: WebAPIClient,
}

impl SignalClientBuilder {
    pub fn new() -> Result<Self> {
        let http_client = Self::default_http_client()?;
        let server_host = "https://textsecure-service.whispersystems.org".into();
        Ok(Self {
            webapi_client: WebAPIClient {
                http_client,
                server_host,
            },
        })
    }

    pub fn set_server_host(&mut self, mut host: String) -> Result<&mut Self> {
        if host.ends_with('/') {
            host.pop();
        }
        self.webapi_client.server_host = host;
        Ok(self)
    }

    pub fn set_http_client(&mut self, http_client: awc::Client) -> &mut Self {
        self.webapi_client.http_client = http_client;
        self
    }

    pub fn finish(self) -> SignalClient {
        SignalClient {
            webapi_client: self.webapi_client,
        }
    }

    fn default_http_client() -> Result<awc::Client> {
        let mut root_certs = rustls::RootCertStore::empty();
        root_certs
            .add_pem_file(&mut &include_bytes!("../signal-server.pem")[..])
            .map_err(|()| anyhow!("read root ca"))?;

        let mut tls_config = rustls::ClientConfig::new();
        tls_config.root_store = root_certs;

        let client = awc::Client::builder()
            .connector(
                Connector::new()
                    .rustls(tls_config.into())
                    .timeout(Duration::from_secs(30))
                    .finish(),
            )
            .disable_timeout()
            .finish();

        Ok(client)
    }
}

pub struct SignalClientConnected {
    device_secrets: DeviceStore,
    worker: actix::Addr<actors::TransportWorker>,
    outgoing_tx: mpsc::Sender<(ProtocolAddress, Box<[u8]>, OwnedSemaphorePermit)>,
    listening: JoinHandle<()>,
    forwarding: JoinHandle<()>,
    sending: JoinHandle<()>,
}

impl SignalClientConnected {
    pub async fn join_computation<T>(
        &mut self,
        me: ProtocolAddress,
        group: Group,
    ) -> Result<(
        impl Stream<Item = Result<Msg<T>>> + Unpin,
        impl Sink<Msg<T>, Error = anyhow::Error> + Unpin,
    )>
    where
        T: Serialize + DeserializeOwned,
    {
        let computation_id = [0; 32]; // TODO

        let parties = group.parties_count();
        let me_ind = group
            .party_index(&me)
            .context("group doesn't include this party")?;

        {
            let device = self.device_secrets.read().await;
            // Check if we trust to every party
            let me = device.me();
            let untrusted: Vec<_> = group
                .parties()
                .filter(|p| p != &&me && !device.is_trusted_party(&p.addr, &p.public_key))
                .collect();
            if !untrusted.is_empty() {
                bail!("parties are not trusted: {:?}", untrusted)
            }
        }

        let (incoming, outgoing) = self.join(computation_id, group).await?;
        let incoming = incoming.and_then(move |(sender, plaintext)| {
            Box::pin(async move {
                let msg: Msg<T> = serde_json::from_slice(&plaintext)
                    .context("failed to deserialize a message")?;
                if msg.receiver.is_some() && msg.receiver != Some(me_ind) {
                    bail!("received msg addressed to another party");
                }
                if msg.sender != sender {
                    bail!("sender tried to forge sender index")
                }
                Ok(msg)
            })
        });

        let outgoing = outgoing
            .with_flat_map(move |(recipient, serialized): (Option<u16>, Box<[u8]>)| {
                let range: Box<dyn Iterator<Item = u16>> = if let Some(i) = recipient {
                    Box::new(iter::once(i))
                } else {
                    Box::new((1..=parties).filter(move |&i| i != me_ind))
                };
                let messages_to_send = range.map(move |i| (i, serialized.clone()));
                stream::iter(messages_to_send.map(Ok))
            })
            .with(move |msg: Msg<T>| {
                Box::pin(async move {
                    event!(
                        Level::TRACE,
                        from = msg.sender,
                        to = ?msg.receiver,
                        "send message"
                    );
                    let recipient = msg.receiver;

                    let mut serialized = computation_id.to_vec();
                    serde_json::to_writer(&mut serialized, &msg).context("serialize msg")?;
                    Ok((recipient, serialized.into_boxed_slice()))
                })
            });

        Ok((incoming, outgoing))
    }

    async fn join(
        &self,
        computation_id: actors::ComputationID,
        group: Group,
    ) -> Result<(
        impl Stream<Item = Result<(u16, Box<[u8]>)>> + Unpin,
        impl Sink<(u16, Box<[u8]>), Error = anyhow::Error> + Unpin,
    )> {
        let (incoming_tx, incoming_rx) = mpsc::channel(10);
        let earlier_received_messages: actors::EarlierReceivedMessages = self
            .worker
            .send(actors::Subscribe {
                id: computation_id,
                group: group.clone(),
                channel: incoming_tx,
            })
            .await
            .context("transport actor is down")?;
        let incoming = stream::iter(earlier_received_messages.0)
            .chain(incoming_rx)
            .map(Ok);
        let outgoing = GroupSender {
            permit: None,
            tx_ready: false,
            semaphore: PollSemaphore::new(Arc::new(Semaphore::new(5))),
            group,
            tx: self.outgoing_tx.clone(),
        };

        Ok((incoming, outgoing))
    }

    async fn connect(webapi_client: WebAPIClient, device_secrets: DeviceStore) -> Result<Self> {
        let pending_messages = actors::PendingMessages::new(device_secrets.clone()).start();
        let worker = actors::TransportWorker::new(device_secrets.clone(), pending_messages).start();
        let (incoming_tx, incoming_rx) = mpsc::channel(10);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(10);
        let creds = {
            let device = device_secrets.read().await;
            device.creds.clone()
        };
        let listening = actix::spawn({
            let span = span!(Level::TRACE, "listening incoming");
            Self::start_listening(webapi_client.clone(), incoming_tx, creds).instrument(span)
        });
        let forwarding = actix::spawn(Self::forward_incoming(incoming_rx, worker.clone()));
        let sending = actix::spawn({
            let span = span!(Level::TRACE, "sending outgoing");
            let device_secrets = device_secrets.clone();
            async move {
                let result: Result<()> =
                    Self::start_sending(webapi_client, device_secrets, outgoing_rx)
                        .instrument(span)
                        .await;
                eprintln!("Sending outgoing messages resulted in error: {:?}", result);
            }
        });
        Ok(Self {
            device_secrets,
            worker,
            outgoing_tx,
            listening,
            forwarding,
            sending,
        })
    }

    async fn start_listening(
        webapi_client: WebAPIClient,
        sink: mpsc::Sender<proto::Envelope>,
        creds: DeviceCreds,
    ) {
        // TODO: reconnect to server if error occur using some retry policy
        let err = webapi_client.receive_messages(&creds, sink).await.err();
        match err {
            Some(err) => event!(
                Level::ERROR,
                %err,
                "listening for incoming messages resulted in error"
            ),
            None => event!(
                Level::ERROR,
                "listening for incoming messages resulted in error"
            ),
        }
    }

    async fn forward_incoming(
        mut from: mpsc::Receiver<proto::Envelope>,
        to: actix::Addr<actors::TransportWorker>,
    ) {
        while let Some(mut msg) = from.next().await {
            if msg.content.is_none() {
                event!(Level::WARN, sender = %msg.source_uuid(), "type" = ?msg.r#type(), "received legacy message (no content field), ignore it");
                continue;
            }
            let ciphertext = match Self::untag(
                msg.content.expect("guaranteed by if statement above"),
            ) {
                Some(c) => c,
                None => {
                    event!(Level::WARN, sender = ?msg.source_uuid, "type" = ?msg.r#type, "received non-mpc message, ignore it");
                    continue;
                }
            };
            msg.content = Some(ciphertext);

            event!(Level::TRACE, sender = %msg.source_uuid(), "received message, forwarding it to TransportWorker");
            if let Err(e) = to.send(actors::ReceivedMessage(msg)).await {
                event!(
                    Level::ERROR,
                    err = %e,
                    "TransportWorker disconnected, stop forwarding messages",
                );
                return;
            }
        }
        event!(
            Level::ERROR,
            "incoming channel broken, stop forwarding messages"
        );
    }

    async fn start_sending<T>(
        webapi_client: WebAPIClient,
        device_secrets: DeviceStore,
        mut messages: mpsc::Receiver<(ProtocolAddress, Box<[u8]>, OwnedSemaphorePermit)>,
    ) -> Result<T> {
        // TODO: Add DeadQueueLetter

        use libsignal_protocol::{CiphertextMessageType, PreKeyBundle, SignalProtocolError};
        use rand::rngs::OsRng;

        let csprng = &mut OsRng;
        while let Some((remote_address, plaintext, _permit)) = messages.next().await {
            event!(Level::TRACE, recipient = %remote_address, "got message to send");

            let mut device = device_secrets.write().await;
            let me = device.me();
            let exclude_device_id = if remote_address.name() == me.addr.name() {
                Some(me.addr.device_id())
            } else {
                None
            };

            let result = device.message_encrypt(&remote_address, &plaintext).await;

            let remote_registration_id: Option<u32>;

            let c = match result {
                Err(SignalProtocolError::SessionNotFound(_)) => {
                    event!(
                        Level::TRACE,
                        "no session found, retrieving keys from server"
                    );
                    let remote_keys = webapi_client
                        .get_device_keys(&device.creds, &remote_address)
                        .await?;
                    remote_registration_id = Some(remote_keys.registration_id);
                    // TODO: PreKey = Some(..) breaks decryption
                    let bundle = PreKeyBundle::new(
                        remote_keys.registration_id,
                        remote_address.device_id(),
                        None, // remote_keys.pre_key.map(|k| (k.key_id, k.public_key)),
                        remote_keys.signed_pre_key.key_id,
                        remote_keys.signed_pre_key.public_key,
                        remote_keys.signed_pre_key.signature.into(),
                        remote_keys.identity_key,
                    )
                    .map_err(|e| anyhow!("make a pre key bundle: {}", e))?;
                    device
                        .process_prekey_bundle(csprng, &remote_address, &bundle)
                        .await
                        .map_err(|e| anyhow!("process a prekey bundle: {}", e))?;
                    let c = device
                        .message_encrypt(&remote_address, &plaintext)
                        .await
                        .map_err(|e| anyhow!("failed to encrypt a message: {}", e))?;
                    event!(Level::TRACE, "message encrypted as prekey bundle");
                    c
                }
                Err(e) => {
                    bail!("failed to encrypt a message: {}", e)
                }
                Ok(c) => {
                    event!(Level::TRACE, "message encrypted as signal message");
                    remote_registration_id = None;
                    c
                }
            };

            event!(Level::TRACE, "sending message");
            webapi_client
                .send_message(
                    &device.creds,
                    match c.message_type() {
                        CiphertextMessageType::PreKey => 3,
                        CiphertextMessageType::Whisper => 1,
                        _ => bail!("got unexpected ciphertext type"),
                    },
                    &remote_address,
                    remote_registration_id,
                    exclude_device_id,
                    Self::put_tag(c.serialize()),
                )
                .await
                .context("send message")?;
            event!(Level::TRACE, "message sent");
        }
        Err(anyhow!(
            "Sending messages stopped as there's no one left who can send a message"
        ))
    }

    fn put_tag(ciphertext: &[u8]) -> Box<[u8]> {
        let mut ciphertext = ciphertext.to_vec();
        let ciphertext_len = ciphertext.len();
        let tag_len = MPC_MESSAGE_TAG.len();
        ciphertext.resize(ciphertext_len + tag_len, 0);
        ciphertext.copy_within(0..ciphertext_len, tag_len);
        (&mut ciphertext[0..tag_len]).copy_from_slice(&MPC_MESSAGE_TAG[..]);

        ciphertext.into()
    }

    fn untag(mut ciphertext: Vec<u8>) -> Option<Vec<u8>> {
        if ciphertext.len() >= MPC_MESSAGE_TAG.len()
            && &ciphertext[..MPC_MESSAGE_TAG.len()] == MPC_MESSAGE_TAG
        {
            ciphertext.drain(..MPC_MESSAGE_TAG.len());
            Some(ciphertext)
        } else {
            None
        }
    }
}

impl Drop for SignalClientConnected {
    fn drop(&mut self) {
        self.listening.abort();
        self.forwarding.abort();
        self.sending.abort();
    }
}

pub struct GroupSender {
    permit: Option<OwnedSemaphorePermit>,
    tx_ready: bool,
    semaphore: PollSemaphore,
    group: Group,
    tx: mpsc::Sender<(ProtocolAddress, Box<[u8]>, OwnedSemaphorePermit)>,
}

impl Sink<(u16, Box<[u8]>)> for GroupSender {
    type Error = anyhow::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.permit.is_none() {
            match self.semaphore.poll_acquire(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Err(anyhow!("semaphore has been closed"))),
                Poll::Ready(Some(permit)) => self.permit = Some(permit),
            }
        }

        if !self.tx_ready {
            match self.tx.poll_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(anyhow!("outgoing channel has benn closed: {}", e)))
                }
                Poll::Ready(Ok(())) => self.tx_ready = true,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        (party_ind, plaintext): (u16, Box<[u8]>),
    ) -> Result<(), Self::Error> {
        if self.permit.is_none() || !self.tx_ready {
            bail!("there was no prior poll_ready call");
        }

        let remote_address = self
            .group
            .lookup_party_addr_by_index(party_ind)
            .context("unknown party")?
            .clone();
        let permit = self
            .permit
            .take()
            .expect("guaranteed by if-statement above");

        self.tx
            .start_send((remote_address, plaintext, permit))
            .context("send to outgoing channel")
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.tx).poll_flush(cx) {
            Poll::Ready(res) => Poll::Ready(res.context("poll flush")),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match Pin::new(&mut self.tx).poll_flush(cx) {
            Poll::Ready(res) => Poll::Ready(res.context("poll close")),
            Poll::Pending => Poll::Pending,
        }
    }
}
