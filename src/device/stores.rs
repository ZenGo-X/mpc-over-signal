use std::collections::HashMap;
use std::mem::replace;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use thiserror::Error;

use libsignal_protocol::error::{Result, SignalProtocolError};
use libsignal_protocol::{
    Context, Direction, IdentityKey, IdentityKeyPair, PreKeyRecord, ProtocolAddress, SenderKeyName,
    SenderKeyRecord, SessionRecord, SignedPreKeyRecord,
};
use libsignal_protocol::{
    IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
};

use super::keys::{PreKey, SignedPreKey};

pub struct DeviceIdentityKeyStore<'d> {
    pub identity_key_pair: &'d IdentityKeyPair,
    pub local_registration_id: u32,
    pub trusted_keys: &'d mut HashMap<ProtocolAddress, IdentityKey>,
}

#[async_trait(?Send)]
impl<'a> IdentityKeyStore for DeviceIdentityKeyStore<'a> {
    async fn get_identity_key_pair(&self, _ctx: Context) -> Result<IdentityKeyPair> {
        Ok(self.identity_key_pair.clone())
    }

    async fn get_local_registration_id(&self, _ctx: Context) -> Result<u32> {
        Ok(self.local_registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool> {
        let address =
            ProtocolAddress::new(address.name().to_ascii_lowercase(), address.device_id());
        let was = self.trusted_keys.insert(address, *identity);
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
        let address =
            ProtocolAddress::new(address.name().to_ascii_lowercase(), address.device_id());
        Ok(self
            .trusted_keys
            .get(&address)
            .map(|i| i == identity)
            .unwrap_or(false))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>> {
        let address =
            ProtocolAddress::new(address.name().to_ascii_lowercase(), address.device_id());
        Ok(self.trusted_keys.get(&address).cloned())
    }
}

pub struct DevicePreKeyStore<'d> {
    pub pre_keys: &'d mut Vec<PreKey>,
}

#[async_trait(?Send)]
impl<'d> PreKeyStore for DevicePreKeyStore<'d> {
    async fn get_pre_key(&self, prekey_id: u32, _ctx: Context) -> Result<PreKeyRecord> {
        self.pre_keys
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
        if self.pre_keys.iter().any(|k| k.id == prekey_id) {
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

        self.pre_keys.push(PreKey {
            id: prekey_id,
            key_pair: record.key_pair()?,
        });

        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: u32, _ctx: Context) -> Result<()> {
        let i = self
            .pre_keys
            .iter()
            .position(|k| k.id == prekey_id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        self.pre_keys.remove(i);
        Ok(())
    }
}

pub struct DeviceSignedPreKeyStore<'d> {
    pub signed_pre_key: &'d mut SignedPreKey,
    pub old_signed_prekeys: &'d mut Vec<SignedPreKey>,
}

#[async_trait(?Send)]
impl<'d> SignedPreKeyStore for DeviceSignedPreKeyStore<'d> {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: u32,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord> {
        let key = if self.signed_pre_key.id == signed_prekey_id {
            &self.signed_pre_key
        } else {
            self.old_signed_prekeys
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

        if key.created > self.signed_pre_key.created {
            let older_key = replace(self.signed_pre_key, key);
            self.old_signed_prekeys.push(older_key);
        } else {
            self.old_signed_prekeys.push(key);
        }

        Ok(())
    }
}

pub struct DeviceSessionStore<'d> {
    pub sessions: &'d mut HashMap<ProtocolAddress, SessionRecord>,
}

#[async_trait(?Send)]
impl<'d> SessionStore for DeviceSessionStore<'d> {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>> {
        let address =
            ProtocolAddress::new(address.name().to_ascii_lowercase(), address.device_id());
        Ok(self.sessions.get(&address).cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<()> {
        let address =
            ProtocolAddress::new(address.name().to_ascii_lowercase(), address.device_id());
        self.sessions.insert(address, record.clone());
        Ok(())
    }
}

pub struct DeviceSenderKeyStore<'d> {
    pub sender_keys: &'d mut HashMap<SenderKeyName, SenderKeyRecord>,
}

#[async_trait(?Send)]
impl<'d> SenderKeyStore for DeviceSenderKeyStore<'d> {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<()> {
        self.sender_keys
            .insert(sender_key_name.clone(), record.clone());
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>> {
        Ok(self.sender_keys.get(sender_key_name).cloned())
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
