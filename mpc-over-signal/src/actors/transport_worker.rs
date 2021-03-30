use std::collections::HashMap;
use std::convert::TryFrom;

use anyhow::{anyhow, bail};

use actix::dev::MessageResponse;
use actix::fut::{ActorFutureExt, WrapFuture};
use actix::{ActorContext, AtomicResponse};
use futures::channel::mpsc;
use futures::SinkExt;

use tracing::{event, span, Instrument, Level};

use libsignal_protocol::{CiphertextMessage, PreKeySignalMessage, ProtocolAddress, SignalMessage};
use rand::rngs::OsRng;

use super::pending_messages::{
    PendingMessages, SavePendingDecryptedMessage, SavePendingEncryptedMessage,
};
use crate::actors::pending_messages::{
    GetPendingMessages, PendingDecryptedMessage, PendingEncryptedMessage,
};
use crate::device::DeviceStore;
use crate::{
    proto::{self, envelope},
    Group,
};

pub type ComputationID = [u8; 32];

pub struct TransportWorker {
    pending: actix::Addr<PendingMessages>,
    subscriptions: HashMap<ComputationID, (Group, mpsc::Sender<(u16, Box<[u8]>)>)>,
    secrets_store: DeviceStore,
}

impl TransportWorker {
    pub fn new(secrets_store: DeviceStore, pending: actix::Addr<PendingMessages>) -> Self {
        Self {
            pending,
            secrets_store,
            subscriptions: Default::default(),
        }
    }
}

#[derive(actix::Message)]
#[rtype(result = "()")]
pub struct ReceivedMessage(pub proto::Envelope);

impl actix::Actor for TransportWorker {
    type Context = actix::Context<Self>;
}

impl actix::Handler<ReceivedMessage> for TransportWorker {
    type Result = actix::AtomicResponse<Self, ()>;

    fn handle(&mut self, msg: ReceivedMessage, ctx: &mut actix::Context<Self>) -> Self::Result {
        let span = span!(
            Level::TRACE,
            "TransportWorker received message",
            source_uuid = %msg.0.source_uuid(),
            source_device = %msg.0.source_device()
        );
        let _enter = span.enter();

        if !self.pending.connected() {
            event!(
                Level::ERROR,
                "PendingMessages actor got disconnected, shutdown"
            );
            ctx.stop();
            return AtomicResponse::new(ready(()));
        }

        let msg = msg.0;

        let remote_address = ProtocolAddress::new(msg.source_uuid().into(), msg.source_device());
        let remote_address2 = remote_address.clone();

        let ciphertext = match msg.r#type() {
            envelope::Type::PrekeyBundle => PreKeySignalMessage::try_from(msg.content())
                .map(CiphertextMessage::PreKeySignalMessage),
            envelope::Type::Ciphertext => {
                SignalMessage::try_from(msg.content()).map(CiphertextMessage::SignalMessage)
            }
            other => {
                event!(
                    Level::ERROR,
                    "type" = ?other,
                    "received message of unexpected type"
                );
                return AtomicResponse::new(ready(()));
            }
        };
        let ciphertext = match ciphertext {
            Ok(c) => c,
            Err(e) => {
                event!(Level::ERROR, "type" = ?msg.r#type(), err = %e, "failed to parse message");
                return AtomicResponse::new(ready(()));
            }
        };

        let secrets_store = self.secrets_store.clone();
        let pending = self.pending.clone();
        let pending2 = pending.clone();
        AtomicResponse::new(Box::pin(
            async {}
                .into_actor(self)
                .then(|(), actor, _ctx| {
                    async move {
                        let mut device = secrets_store.write().await;
                        if !device.is_known_party(&remote_address) {
                            // We don't know this party, but may get familiar soon, save the message
                            return Self::save_encrypted_message_to_pending(
                                pending,
                                remote_address,
                                ciphertext,
                            )
                            .await;
                        }
                        device
                            .message_decrypt(&mut OsRng, &remote_address, &ciphertext)
                            .await
                            .map(Self::extract_computation_id)
                            .map_err(|e| anyhow!("{}", e))
                    }
                    .in_current_span()
                    .into_actor(actor)
                })
                .then(move |msg, actor: &mut Self, _ctx| {
                    let remote_address = remote_address2;
                    let pending = pending2;
                    let id_msg_subscriber = match msg {
                        Ok(Some((id, msg))) => {
                            Ok(Some((id, msg, actor.subscriptions.get(&id).cloned())))
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    };
                    async move {
                        match id_msg_subscriber {
                            Ok(Some((id, msg, Some((group, mut subscriber))))) => {
                                Self::send_message_to_subscriber(
                                    &mut subscriber,
                                    &group,
                                    &remote_address,
                                    msg.into(),
                                )
                                .await
                                // if subscriber disconnected, we should delete it from table
                                .map(|ok| {
                                    if !ok {
                                        Some(id)
                                    } else {
                                        None
                                    }
                                })
                            }
                            // Nobody subscribed to this computation id, but can subscribe soon, save it
                            Ok(Some((id, msg, None))) => Self::save_decrypted_message_to_pending(
                                pending,
                                id,
                                remote_address,
                                msg.into(),
                            )
                            .await
                            .and(Ok(None)),
                            Ok(None) => {
                                bail!("failed to decrypt a message")
                            }
                            Err(e) => {
                                bail!("failed to decrypt a message: {}", e)
                            }
                        }
                    }
                    .in_current_span()
                    .into_actor(actor)
                })
                .map({
                    let span = span.clone();
                    move |result, actor: &mut Self, _ctx| {
                        let _enter = span.enter();
                        match result {
                            Ok(Some(remove_subscription_id)) => {
                                event!(Level::TRACE, "subscriber is gone, message won't be handled");
                                let _ = actor.subscriptions.remove(&remove_subscription_id);
                            }
                            Ok(None) => {
                                event!(Level::TRACE, "message was handled")
                            }
                            Err(e) => {
                                event!(Level::ERROR, err = %e, "handling incoming message resulted in error");
                            }
                        }
                    }
                }),
        ))
    }
}

impl TransportWorker {
    async fn save_encrypted_message_to_pending<T>(
        pending: actix::Addr<PendingMessages>,
        sender: ProtocolAddress,
        msg: CiphertextMessage,
    ) -> anyhow::Result<Option<T>> {
        event!(Level::TRACE, "saving encrypted message to pending");
        let msg = match msg {
            CiphertextMessage::PreKeySignalMessage(ciphertext) => {
                PendingEncryptedMessage::PreKey { sender, ciphertext }
            }
            CiphertextMessage::SignalMessage(ciphertext) => {
                PendingEncryptedMessage::Signal { sender, ciphertext }
            }
            _ => {
                bail!("Saving message of unknown type (should be unreachable)");
            }
        };
        if pending
            .send(SavePendingEncryptedMessage(msg))
            .await
            .is_err()
        {
            bail!("PendingMessages actor got stopped");
        }
        event!(Level::TRACE, "encrypted message saved to pending");
        Ok(None)
    }

    async fn save_decrypted_message_to_pending(
        pending: actix::Addr<PendingMessages>,
        computation_id: ComputationID,
        sender: ProtocolAddress,
        plaintext: Box<[u8]>,
    ) -> anyhow::Result<()> {
        event!(Level::TRACE, "saving decrypted message to pending");
        let msg = PendingDecryptedMessage {
            computation_id,
            sender,
            plaintext,
        };
        if pending
            .send(SavePendingDecryptedMessage(msg))
            .await
            .is_err()
        {
            bail!("PendingMessages actor got stopped");
        }
        event!(Level::TRACE, "decrypted message saved to pending");
        Ok(())
    }

    fn extract_computation_id(mut plaintext: Vec<u8>) -> Option<(ComputationID, Vec<u8>)> {
        if plaintext.len() < 32 {
            event!(
                Level::WARN,
                "decrypted message is too short to contain conversation id"
            );
            return None;
        }
        let mut conv_id = [0u8; 32];
        conv_id.copy_from_slice(&plaintext[0..32]);
        plaintext.drain(0..32);

        event!(Level::TRACE, id = %hex::encode(&conv_id), "recognized message conv id");
        return Some((conv_id, plaintext));
    }

    async fn send_message_to_subscriber(
        subscriber: &mut mpsc::Sender<(u16, Box<[u8]>)>,
        group: &Group,
        sender: &ProtocolAddress,
        plaintext: Box<[u8]>,
    ) -> anyhow::Result<bool> {
        let i = group
            .party_index(sender)
            .ok_or_else(|| anyhow!("sender not in the group {}", sender))?;
        let result = subscriber.send((i, plaintext)).await;
        Ok(result.is_ok())
    }
}

#[derive(actix::Message)]
#[rtype(result = "EarlierReceivedMessages")]
pub struct Subscribe {
    pub id: ComputationID,
    pub group: Group,
    pub channel: mpsc::Sender<(u16, Box<[u8]>)>,
}

#[derive(MessageResponse)]
pub struct EarlierReceivedMessages(pub Vec<(u16, Box<[u8]>)>);

impl actix::Handler<Subscribe> for TransportWorker {
    type Result = actix::ResponseFuture<EarlierReceivedMessages>;

    fn handle(&mut self, req: Subscribe, ctx: &mut actix::Context<Self>) -> Self::Result {
        let span =
            span!(Level::TRACE, "subscribe request", id = %hex::encode(req.id), group = ?req.group);
        let _enter = span.enter();

        if !self.pending.connected() {
            event!(Level::ERROR, "PendingMessages actor disconnected, shutdown");
            ctx.stop();
            return Box::pin(futures::future::ready(EarlierReceivedMessages(vec![])));
        }

        // TODO: should it raise an error if `id` was already subscribed?
        let was_subscription = self
            .subscriptions
            .insert(req.id, (req.group.clone(), req.channel.clone()));
        if was_subscription.is_some() {
            event!(
                Level::WARN,
                "someone was already subscribed to this computation id: he was silently unsubscribed"
            )
        }
        Box::pin(
            Self::get_pending_messages(self.pending.clone(), req.id, req.group).in_current_span(),
        )
    }
}

impl TransportWorker {
    async fn get_pending_messages(
        pending: actix::Addr<PendingMessages>,
        id: ComputationID,
        group: Group,
    ) -> EarlierReceivedMessages {
        let msgs = match pending.send(GetPendingMessages { id }).await {
            Ok(msgs) => msgs.0,
            Err(e) => {
                event!(Level::ERROR, err = %e, "cannot retrieve pending messages: PendingMessages actor is stopped");
                return EarlierReceivedMessages(vec![]);
            }
        };
        let earlier_received_messages: Vec<_> = msgs
            .into_iter()
            .map(|m: PendingDecryptedMessage| {
                group.party_index(&m.sender).map(|i| (i, m.plaintext))
            })
            .flatten()
            .collect();
        event!(Level::TRACE, amount = %earlier_received_messages.len(), "found earlier received messages");
        EarlierReceivedMessages(earlier_received_messages)
    }
}

fn ready<I: 'static, A: actix::Actor>(v: I) -> actix::ResponseActFuture<A, I> {
    Box::pin(actix::fut::wrap_future(futures::future::ready(v)))
}
