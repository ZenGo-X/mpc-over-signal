use std::fmt;

use libsignal_protocol::{IdentityKey, PublicKey};

use super::libsignal_serializable;

pub fn hide_content<T>(_: &T, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "[hidden]")
}

pub fn base64_encoded(bytes: impl AsRef<[u8]>, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", base64::encode(bytes))
}

pub fn identity_key(identity: &IdentityKey, f: &mut fmt::Formatter) -> fmt::Result {
    libsignal_serializable::debug_fmt(identity, f)
}

pub fn public_key(pk: &PublicKey, f: &mut fmt::Formatter) -> fmt::Result {
    libsignal_serializable::debug_fmt(pk, f)
}
