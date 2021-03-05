use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;

use libsignal_protocol::{IdentityKeyPair, KeyPair, PrivateKey};

use serde::de::{Error, Unexpected};
use serde::{Deserializer, Serializer};

pub mod identity_key_pair {
    use super::*;

    pub fn serialize<S>(identity: &IdentityKeyPair, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&base64::encode(identity.serialize()))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<IdentityKeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = IdentityKeyPair;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "base64 encoded identity key pair")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let bytes = base64::decode(v)
                    .map_err(|_| E::invalid_value(Unexpected::Str(v), &"base64 string"))?;
                IdentityKeyPair::try_from(bytes.as_slice()).map_err(Error::custom)
            }
        }

        d.deserialize_str(Visitor)
    }
}

pub mod key_pair {
    use super::*;

    pub fn serialize<S>(key_pair: &KeyPair, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&base64::encode(key_pair.private_key.serialize()))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<KeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = KeyPair;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "base64 encoded private key")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let bytes = base64::decode(v)
                    .map_err(|_| E::invalid_value(Unexpected::Str(v), &"base64 string"))?;
                let sk = PrivateKey::deserialize(bytes.as_slice()).map_err(Error::custom)?;
                let pk = sk.public_key().map_err(|e| {
                    E::custom(format!("calculate public key for given private key: {}", e))
                })?;
                Ok(KeyPair::new(pk, sk))
            }
        }

        d.deserialize_str(Visitor)
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
                E: Error,
            {
                let bytes = base64::decode(v)
                    .map_err(|_| E::invalid_value(Unexpected::Str(v), &"base64 string"))?;
                Ok(T::from(bytes))
            }
        }

        d.deserialize_str(Visitor::<T>(PhantomData))
    }
}
