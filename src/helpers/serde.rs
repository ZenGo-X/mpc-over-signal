use std::collections::HashMap;
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::{cmp, fmt, hash};

use libsignal_protocol::{
    IdentityKey, IdentityKeyPair, KeyPair, PrivateKey, ProtocolAddress, SenderKeyName,
    SenderKeyRecord, SessionRecord,
};

use serde::de::{self, Unexpected};
use serde::ser;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

mod libsignal_serializable {
    use super::*;

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
        S: Serializer,
        T: Serializable,
    {
        s.serialize_str(&base64::encode(
            obj.serialize().map_err(ser::Error::custom)?,
        ))
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
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
                    .map_err(|_| E::invalid_value(Unexpected::Str(v), &"base64 string"))?;
                T::deserialize(bytes.as_slice()).map_err(de::Error::custom)
            }
        }

        d.deserialize_str(Visitor::<T>(PhantomData))
    }
}

pub mod identity_key_pair {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Wrapper(#[serde(with = "self")] IdentityKeyPair);

    impl From<IdentityKeyPair> for Wrapper {
        fn from(kp: IdentityKeyPair) -> Self {
            Wrapper(kp)
        }
    }

    impl From<Wrapper> for IdentityKeyPair {
        fn from(w: Wrapper) -> Self {
            w.0
        }
    }

    pub fn serialize<S>(identity: &IdentityKeyPair, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        libsignal_serializable::serialize(identity, s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<IdentityKeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        libsignal_serializable::deserialize::<'de, D, _>(d)
    }
}

pub mod identity_key {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Wrapper(#[serde(with = "self")] IdentityKey);

    impl From<IdentityKey> for Wrapper {
        fn from(kp: IdentityKey) -> Self {
            Wrapper(kp)
        }
    }

    impl From<Wrapper> for IdentityKey {
        fn from(w: Wrapper) -> Self {
            w.0
        }
    }

    pub fn serialize<S>(identity: &IdentityKey, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        libsignal_serializable::serialize(identity, s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<IdentityKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        libsignal_serializable::deserialize::<'de, D, _>(d)
    }
}

pub mod key_pair {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Wrapper(#[serde(with = "self")] KeyPair);

    impl From<KeyPair> for Wrapper {
        fn from(kp: KeyPair) -> Self {
            Wrapper(kp)
        }
    }

    impl From<Wrapper> for KeyPair {
        fn from(w: Wrapper) -> Self {
            w.0
        }
    }

    pub fn serialize<S>(key_pair: &KeyPair, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        libsignal_serializable::serialize(&key_pair.private_key, s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<KeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        let sk: PrivateKey = libsignal_serializable::deserialize::<'de, D, _>(d)?;
        let pk = sk.public_key().map_err(de::Error::custom)?;
        Ok(KeyPair::new(pk, sk))
    }
}

pub mod session_record {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Wrapper(#[serde(with = "self")] SessionRecord);

    impl From<SessionRecord> for Wrapper {
        fn from(s: SessionRecord) -> Self {
            Wrapper(s)
        }
    }

    impl From<Wrapper> for SessionRecord {
        fn from(w: Wrapper) -> Self {
            w.0
        }
    }

    pub fn serialize<S>(session: &SessionRecord, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        libsignal_serializable::serialize(session, s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<SessionRecord, D::Error>
    where
        D: Deserializer<'de>,
    {
        libsignal_serializable::deserialize::<'de, D, _>(d)
    }
}

pub mod sender_key_record {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Wrapper(#[serde(with = "self")] SenderKeyRecord);

    impl From<SenderKeyRecord> for Wrapper {
        fn from(key: SenderKeyRecord) -> Self {
            Wrapper(key)
        }
    }

    impl From<Wrapper> for SenderKeyRecord {
        fn from(w: Wrapper) -> Self {
            w.0
        }
    }

    pub fn serialize<S>(key: &SenderKeyRecord, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        libsignal_serializable::serialize(key, s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<SenderKeyRecord, D::Error>
    where
        D: Deserializer<'de>,
    {
        libsignal_serializable::deserialize::<'de, D, _>(d)
    }
}

pub mod protocol_address {
    use super::*;

    #[derive(Serialize, Deserialize, Eq, PartialEq, Hash)]
    pub struct Wrapper {
        name: String,
        device_id: u32,
    }

    impl From<Wrapper> for ProtocolAddress {
        fn from(w: Wrapper) -> Self {
            ProtocolAddress::new(w.name, w.device_id)
        }
    }

    impl From<ProtocolAddress> for Wrapper {
        fn from(a: ProtocolAddress) -> Self {
            Wrapper {
                name: a.name().into(),
                device_id: a.device_id(),
            }
        }
    }

    pub fn serialize<S>(address: &ProtocolAddress, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Wrapper::serialize(&Wrapper::from(address.clone()), s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<ProtocolAddress, D::Error>
    where
        D: Deserializer<'de>,
    {
        Wrapper::deserialize(d).map(ProtocolAddress::from)
    }
}

pub mod sender_key_name {
    use super::*;
    use libsignal_protocol::SignalProtocolError;

    #[derive(Deserialize, Serialize, Eq, PartialEq, Hash)]
    #[serde(transparent)]
    pub struct Wrapper(#[serde(with = "self")] SenderKeyName);

    impl From<Wrapper> for SenderKeyName {
        fn from(w: Wrapper) -> Self {
            w.0
        }
    }

    impl From<SenderKeyName> for Wrapper {
        fn from(name: SenderKeyName) -> Self {
            Wrapper(name)
        }
    }

    #[derive(Serialize, Deserialize)]
    struct SerializableRepresentation {
        group_id: String,
        sender: protocol_address::Wrapper,
    }

    pub fn serialize<S>(name: &SenderKeyName, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let group_id = name.group_id().map_err(ser::Error::custom)?;
        let sender = name.sender().map_err(ser::Error::custom)?.into();
        SerializableRepresentation { group_id, sender }.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<SenderKeyName, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = SerializableRepresentation::deserialize(d)?;
        SenderKeyName::new(repr.group_id, repr.sender.into()).map_err(de::Error::custom)
    }
}

pub mod base64_encoded {
    use super::*;

    pub fn serialize<S, T>(bytes: T, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        s.serialize_str(&base64::encode(&bytes))
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: From<Vec<u8>>,
    {
        struct Visitor<T>(PhantomData<T>);

        impl<'de, T> serde::de::Visitor<'de> for Visitor<T>
        where
            T: From<Vec<u8>>,
        {
            type Value = T;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "base64 encoded bytes")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes = base64::decode(v)
                    .map_err(|_| E::invalid_value(Unexpected::Str(v), &"base64 string"))?;
                Ok(T::from(bytes))
            }
        }

        d.deserialize_str(Visitor::<T>(PhantomData))
    }
}

pub mod hash_map {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    #[serde(bound(
        serialize = "K: cmp::Eq + hash::Hash + Serialize, V: Serialize",
        deserialize = "K: cmp::Eq + hash::Hash + Deserialize<'de>, V: Deserialize<'de>"
    ))]
    pub struct Wrapper<K, V>(HashMap<K, V>);

    impl<K1, K2, V1, V2> From<HashMap<K1, V1>> for Wrapper<K2, V2>
    where
        K2: From<K1> + cmp::Eq + hash::Hash,
        V2: From<V1>,
    {
        fn from(m: HashMap<K1, V1>) -> Wrapper<K2, V2> {
            Wrapper(
                m.into_iter()
                    .map(|(k, v)| (K2::from(k), V2::from(v)))
                    .collect(),
            )
        }
    }

    impl<K1, K2, V1, V2> From<Wrapper<K1, V1>> for HashMap<K2, V2>
    where
        K2: From<K1> + cmp::Eq + hash::Hash,
        V2: From<V1>,
    {
        fn from(m: Wrapper<K1, V1>) -> HashMap<K2, V2> {
            m.0.into_iter()
                .map(|(k, v)| (K2::from(k), V2::from(v)))
                .collect()
        }
    }

    pub struct UsingWrappers<K, V>(PhantomData<(K, V)>);

    impl<K1, V1> UsingWrappers<K1, V1> {
        pub fn serialize<S, K2, V2>(map: &HashMap<K2, V2>, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            K1: From<K2> + cmp::Eq + hash::Hash + Serialize,
            V1: From<V2> + Serialize,
            HashMap<K2, V2>: Clone,
        {
            Wrapper::<K1, V1>::from(map.clone()).serialize(s)
        }

        pub fn deserialize<'de, D, K2, V2>(d: D) -> Result<HashMap<K2, V2>, D::Error>
        where
            D: Deserializer<'de>,
            K1: cmp::Eq + hash::Hash + Deserialize<'de>,
            V1: Deserialize<'de>,
            K2: From<K1> + cmp::Eq + hash::Hash,
            V2: From<V1>,
        {
            Wrapper::<K1, V1>::deserialize(d).map(HashMap::<K2, V2>::from)
        }
    }
}
