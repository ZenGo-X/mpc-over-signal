use actix::{ActorFutureExt, AtomicResponse, WrapFuture};

use libsignal_protocol::{CiphertextMessage, PreKeySignalMessage, ProtocolAddress, SignalMessage};
use rand::rngs::OsRng;

use super::transport_worker::ComputationID;
use crate::device::DeviceStore;

const GARBAGE_UPPER_BOUND: usize = 1000;

pub struct PendingMessages {
    decrypted_messages: Vec<PendingDecryptedMessage>,
    encrypted_messages: Vec<PendingEncryptedMessage>,
    device_store: DeviceStore,
}

impl PendingMessages {
    pub fn new(device_store: DeviceStore) -> Self {
        Self {
            device_store,
            decrypted_messages: Default::default(),
            encrypted_messages: Default::default(),
        }
    }
}

#[derive(Clone)]
pub struct PendingDecryptedMessage {
    pub computation_id: ComputationID,
    pub sender: ProtocolAddress,
    pub plaintext: Box<[u8]>,
}

#[derive(Clone)]
pub enum PendingEncryptedMessage {
    PreKey {
        sender: ProtocolAddress,
        ciphertext: PreKeySignalMessage,
    },
    Signal {
        sender: ProtocolAddress,
        ciphertext: SignalMessage,
    },
}

#[derive(actix::Message)]
#[rtype(result = "()")]
pub struct TriggerGarbageCollection;

#[derive(actix::Message)]
#[rtype(result = "()")]
pub struct SavePendingEncryptedMessage(pub PendingEncryptedMessage);

#[derive(actix::Message)]
#[rtype(result = "()")]
pub struct SavePendingDecryptedMessage(pub PendingDecryptedMessage);

#[derive(actix::Message)]
#[rtype(result = "ObtainedPendingMessages")]
pub struct GetPendingMessages {
    pub id: ComputationID,
}

#[derive(actix::MessageResponse)]
pub struct ObtainedPendingMessages(pub Vec<PendingDecryptedMessage>);

#[derive(actix::Message)]
#[rtype(result = "()")]
pub struct DecryptPendingMessages;

impl actix::Actor for PendingMessages {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut actix::Context<Self>) {
        ctx.set_mailbox_capacity(1)
    }
}

impl actix::Handler<SavePendingDecryptedMessage> for PendingMessages {
    type Result = ();

    fn handle(
        &mut self,
        msg: SavePendingDecryptedMessage,
        ctx: &mut actix::Context<Self>,
    ) -> Self::Result {
        self.decrypted_messages.push(msg.0);

        if self.decrypted_messages.len() >= GARBAGE_UPPER_BOUND {
            self.handle(TriggerGarbageCollection, ctx);
        }
    }
}

impl actix::Handler<SavePendingEncryptedMessage> for PendingMessages {
    type Result = ();

    fn handle(
        &mut self,
        msg: SavePendingEncryptedMessage,
        ctx: &mut actix::Context<Self>,
    ) -> Self::Result {
        if let PendingEncryptedMessage::Signal { sender, .. } = &msg.0 {
            if !self.encrypted_messages.iter().any(|m| match m {
                PendingEncryptedMessage::PreKey { sender: s, .. } => s == sender,
                _ => false,
            }) {
                eprintln!("Encrypted Signal message won't be handled because sender ({}) haven't sent prior PreKey message", sender);
                return;
            }
        }
        self.encrypted_messages.push(msg.0);

        if self.encrypted_messages.len() >= GARBAGE_UPPER_BOUND {
            self.handle(TriggerGarbageCollection, ctx);
        }
    }
}

impl actix::Handler<DecryptPendingMessages> for PendingMessages {
    type Result = actix::AtomicResponse<Self, ()>;

    fn handle(
        &mut self,
        _msg: DecryptPendingMessages,
        _ctx: &mut actix::Context<Self>,
    ) -> Self::Result {
        actix::AtomicResponse::new(Box::pin(
            Self::decrypt_pending_messages(
                self.device_store.clone(),
                self.encrypted_messages.clone(),
            )
            .into_actor(self)
            .map(Self::update_state_after_decrypting_pending_messages),
        ))
    }
}

impl PendingMessages {
    async fn decrypt_pending_messages(
        device_store: DeviceStore,
        encrypted_messages: Vec<PendingEncryptedMessage>,
    ) -> Vec<(usize, Option<PendingDecryptedMessage>)> {
        let mut device = device_store.write().await;
        let mut decrypted_messages = vec![];
        for (i, encrypted_msg) in encrypted_messages.into_iter().enumerate() {
            let (sender, ciphertext) = match encrypted_msg {
                PendingEncryptedMessage::PreKey { sender, ciphertext } => {
                    (sender, CiphertextMessage::PreKeySignalMessage(ciphertext))
                }
                PendingEncryptedMessage::Signal { sender, ciphertext } => {
                    (sender, CiphertextMessage::SignalMessage(ciphertext))
                }
            };

            if !device.is_known_party(&sender) {
                continue;
            }

            let decrypted = device
                .message_decrypt(&mut OsRng, &sender, &ciphertext)
                .await
                .map(Self::extract_computation_id);
            decrypted_messages.push(match decrypted {
                Ok(Some((computation_id, plaintext))) => (
                    i,
                    Some(PendingDecryptedMessage {
                        computation_id,
                        sender,
                        plaintext: plaintext.into(),
                    }),
                ),
                Ok(None) | Err(_) => (i, None),
            });
        }
        decrypted_messages
    }

    fn update_state_after_decrypting_pending_messages(
        decrypted_messages: Vec<(usize, Option<PendingDecryptedMessage>)>,
        actor: &mut Self,
        _ctx: &mut actix::Context<Self>,
    ) {
        if decrypted_messages.is_empty() {
            return;
        }
        for (i, _) in decrypted_messages.iter().rev() {
            actor.encrypted_messages.remove(*i);
        }
        for (_, msg) in decrypted_messages {
            if let Some(msg) = msg {
                actor.decrypted_messages.push(msg)
            }
        }
    }

    fn extract_computation_id(mut plaintext: Vec<u8>) -> Option<(ComputationID, Vec<u8>)> {
        if plaintext.len() < 32 {
            return None;
        }
        let mut conv_id = [0u8; 32];
        conv_id.copy_from_slice(&plaintext[0..32]);
        plaintext.drain(0..32);

        return Some((conv_id, plaintext));
    }
}

impl actix::Handler<GetPendingMessages> for PendingMessages {
    type Result = actix::AtomicResponse<Self, ObtainedPendingMessages>;

    fn handle(&mut self, msg: GetPendingMessages, _ctx: &mut actix::Context<Self>) -> Self::Result {
        AtomicResponse::new(Box::pin(
            Self::decrypt_pending_messages(
                self.device_store.clone(),
                self.encrypted_messages.clone(),
            )
            .into_actor(self)
            .map(Self::update_state_after_decrypting_pending_messages)
            .map(move |(), actor, _ctx| {
                let msg_id = msg.id;
                ObtainedPendingMessages(
                    actor
                        .decrypted_messages
                        .drain_filter(|msg| msg.computation_id == msg_id)
                        .collect(),
                )
            }),
        ))
    }
}

impl actix::Handler<TriggerGarbageCollection> for PendingMessages {
    type Result = ();

    fn handle(
        &mut self,
        _msg: TriggerGarbageCollection,
        _ctx: &mut actix::Context<Self>,
    ) -> Self::Result {
        if self.decrypted_messages.len() >= GARBAGE_UPPER_BOUND {
            let number_of_messages_to_delete = self.decrypted_messages.len() / 2;
            self.decrypted_messages
                .drain(0..number_of_messages_to_delete);
        }
        if self.encrypted_messages.len() >= GARBAGE_UPPER_BOUND {
            let number_of_messages_to_delete = self.encrypted_messages.len() / 2;
            self.encrypted_messages
                .drain(0..number_of_messages_to_delete);
        }
    }
}
