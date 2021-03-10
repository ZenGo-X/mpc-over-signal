use std::mem::replace;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use libsignal_protocol::error::{Result, SignalProtocolError};
use libsignal_protocol::{
    Context, Direction, IdentityKey, IdentityKeyPair, PreKeyRecord, ProtocolAddress, SenderKeyName,
    SenderKeyRecord, SessionRecord, SignedPreKeyRecord,
};
use libsignal_protocol::{
    IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
};

mod creds;
mod keys;

pub use creds::{DeviceAuth, DeviceCreds, Username};
pub use keys::{DeviceKeys, PreKey, SignedPreKey};

#[derive(Serialize, Deserialize)]
pub struct Device {
    pub creds: DeviceCreds,
    #[serde(flatten)]
    pub keys: DeviceKeys,
}

impl Device {
    pub fn new(creds: DeviceCreds, keys: DeviceKeys) -> Self {
        Self { creds, keys }
    }

    pub fn clean_signed_pre_keys_older_than(&mut self, age: Duration) {
        todo!()
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for Device {
    async fn get_identity_key_pair(&self, _ctx: Context) -> Result<IdentityKeyPair> {
        Ok(self.keys.identity_key_pair.clone())
    }

    async fn get_local_registration_id(&self, _ctx: Context) -> Result<u32> {
        Ok(self.creds.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool> {
        let was = self.keys.trusted_keys.insert(address.clone(), *identity);
        match was {
            Some(old_identity) => Ok(&old_identity != identity),
            None => Ok(false),
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
        _ctx: Context,
    ) -> Result<bool> {
        Ok(self
            .keys
            .trusted_keys
            .get(address)
            .map(|i| i == identity)
            .unwrap_or(false))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>> {
        Ok(self.keys.trusted_keys.get(address).cloned())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for Device {
    async fn get_pre_key(&self, prekey_id: u32, _ctx: Context) -> Result<PreKeyRecord> {
        self.keys
            .pre_keys
            .iter()
            .find(|k| k.id == prekey_id)
            .map(PreKeyRecord::from)
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        if self.keys.pre_keys.iter().any(|k| k.id == prekey_id) {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "save_pre_key",
                Box::new(DeviceError::PrekeyAlreadyExist(prekey_id)),
            ));
        }

        if prekey_id != record.id()? {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "save_pre_key",
                Box::new(DeviceError::PrekeyIdDoesntMatchRecordId),
            ));
        }

        self.keys.pre_keys.push(PreKey {
            id: prekey_id,
            key_pair: record.key_pair()?,
        });

        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: u32, _ctx: Context) -> Result<()> {
        let i = self
            .keys
            .pre_keys
            .iter()
            .position(|k| k.id == prekey_id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        self.keys.pre_keys.remove(i);
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for Device {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: u32,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord> {
        let key = if self.keys.signed_pre_key.id == signed_prekey_id {
            &self.keys.signed_pre_key
        } else {
            self.keys
                .old_signed_prekeys
                .iter()
                .find(|k| k.id == signed_prekey_id)
                .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?
        };

        let timestamp = key
            .created
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| {
                SignalProtocolError::ApplicationCallbackError(
                    "get_signed_pre_key",
                    Box::new(DeviceError::BrokenClocks),
                )
            })?;

        Ok(SignedPreKeyRecord::new(
            key.id,
            timestamp.as_secs(),
            &key.key_pair,
            &key.signature,
        ))
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: u32,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        let id = record.id()?;
        let timestamp = record.timestamp()?;
        let key_pair = record.key_pair()?;
        let signature = record.signature()?.into_boxed_slice();

        if signed_prekey_id != id {
            return Err(SignalProtocolError::ApplicationCallbackError(
                "save_signed_pre_key",
                Box::new(DeviceError::SignedPrekeyIdDoesntMatchRecordId),
            ));
        }

        let timestamp = Duration::from_secs(timestamp);
        let created = SystemTime::UNIX_EPOCH.checked_add(timestamp).ok_or(
            SignalProtocolError::ApplicationCallbackError(
                "save_signed_pre_key",
                Box::new(DeviceError::InvalidTimestamp),
            ),
        )?;

        let key = SignedPreKey {
            id,
            created,
            key_pair,
            signature,
        };

        if key.created > self.keys.signed_pre_key.created {
            let older_key = replace(&mut self.keys.signed_pre_key, key);
            self.keys.old_signed_prekeys.push(older_key);
        } else {
            self.keys.old_signed_prekeys.push(key);
        }

        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for Device {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>> {
        Ok(self.keys.sessions.get(address).cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<()> {
        self.keys.sessions.insert(address.clone(), record.clone());
        Ok(())
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for Device {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        self.keys
            .sender_keys
            .insert(sender_key_name.clone(), record.clone());
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>> {
        Ok(self.keys.sender_keys.get(sender_key_name).cloned())
    }
}

#[derive(Debug, Error)]
enum DeviceError {
    #[error("attempt to overwrite existing pre key with id {0}")]
    PrekeyAlreadyExist(u32),
    #[error("invalid arguments: prekey_id != record.id()")]
    PrekeyIdDoesntMatchRecordId,
    #[error("invalid arguments: signed_prekey_id != record.id()")]
    SignedPrekeyIdDoesntMatchRecordId,
    #[error("system clocks are broken")]
    BrokenClocks,
    #[error("signed pre key birthdate cannot be represented as system time")]
    InvalidTimestamp,
}
