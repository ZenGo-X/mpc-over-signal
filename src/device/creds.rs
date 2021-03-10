use std::fmt;

use derivative::Derivative;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct DeviceCreds {
    pub username: Username,
    pub registration_id: u32,
    /// Password is intentionally hidden to prevent it from misusing
    #[derivative(Debug(format_with = "crate::helpers::fmt::hide_content"))]
    password_64: String,
}

impl DeviceCreds {
    pub fn new(username: Username, password_64: String, registration_id: u32) -> Self {
        Self {
            username,
            registration_id,
            password_64,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Username {
    pub name: String,
    pub device_id: u32,
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.name, self.device_id)
    }
}

pub trait DeviceAuth: Sized {
    /// Sets auth header using device creds
    fn device_auth(self, creds: &DeviceCreds) -> Self;
}

impl DeviceAuth for awc::ClientRequest {
    fn device_auth(self, creds: &DeviceCreds) -> Self {
        self.basic_auth(&creds.username, Some(&creds.password_64))
    }
}
