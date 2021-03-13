use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;

use serde::{de, ser, Deserialize, Serialize};

use libsignal_protocol::{
    IdentityKey, IdentityKeyPair, PrivateKey, PublicKey, SenderKeyRecord, SessionRecord,
};

pub trait Serializable: Sized {
    type Error: fmt::Display;

    fn what() -> &'static str;
    fn serialize(&self) -> Result<Box<[u8]>, Self::Error>;
    fn deserialize(bytes: &[u8]) -> Result<Self, Self::Error>;
}

impl Serializable for IdentityKeyPair {
    type Error = libsignal_protocol::SignalProtocolError;

    fn what() -> &'static str {
        "identity key pair"
    }

    fn serialize(&self) -> Result<Box<[u8]>, Self::Error> {
        Ok(self.serialize())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::Error> {
        IdentityKeyPair::try_from(bytes)
    }
}

impl Serializable for IdentityKey {
    type Error = libsignal_protocol::SignalProtocolError;

    fn what() -> &'static str {
        "identity public key"
    }

    fn serialize(&self) -> Result<Box<[u8]>, Self::Error> {
        Ok(self.serialize())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::Error> {
        IdentityKey::try_from(bytes)
    }
}

impl Serializable for PublicKey {
    type Error = libsignal_protocol::SignalProtocolError;

    fn what() -> &'static str {
        "public key"
    }

    fn serialize(&self) -> Result<Box<[u8]>, Self::Error> {
        Ok(self.serialize())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::Error> {
        PublicKey::deserialize(bytes)
    }
}

impl Serializable for PrivateKey {
    type Error = libsignal_protocol::SignalProtocolError;

    fn what() -> &'static str {
        "private key"
    }

    fn serialize(&self) -> Result<Box<[u8]>, Self::Error> {
        Ok(self.serialize().into_boxed_slice())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::Error> {
        PrivateKey::deserialize(bytes)
    }
}

impl Serializable for SessionRecord {
    type Error = libsignal_protocol::SignalProtocolError;

    fn what() -> &'static str {
        "session"
    }

    fn serialize(&self) -> Result<Box<[u8]>, Self::Error> {
        self.serialize().map(|b| b.into_boxed_slice())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::Error> {
        SessionRecord::deserialize(bytes)
    }
}

impl Serializable for SenderKeyRecord {
    type Error = libsignal_protocol::SignalProtocolError;

    fn what() -> &'static str {
        "sender key"
    }

    fn serialize(&self) -> Result<Box<[u8]>, Self::Error> {
        self.serialize().map(|b| b.into_boxed_slice())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::Error> {
        SenderKeyRecord::deserialize(bytes)
    }
}

pub fn serialize<S, T>(obj: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: ser::Serializer,
    T: Serializable,
{
    s.serialize_str(&base64::encode(
        obj.serialize().map_err(ser::Error::custom)?,
    ))
}

pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Serializable,
{
    struct Visitor<T>(PhantomData<T>);

    impl<'de, T: Serializable> serde::de::Visitor<'de> for Visitor<T> {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "base64 encoded {}", T::what())
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = base64::decode(v)
                .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"base64 string"))?;
            T::deserialize(bytes.as_slice()).map_err(de::Error::custom)
        }
    }

    d.deserialize_str(Visitor::<T>(PhantomData))
}

pub fn debug_fmt<T>(obj: &T, f: &mut fmt::Formatter) -> fmt::Result
where
    T: Serializable,
{
    let bytes = obj.serialize().map_err(|_| fmt::Error)?;
    write!(f, "{}", base64::encode(bytes))
}
