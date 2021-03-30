use awc::Client;

mod create_device;
mod device_keys;
mod link_device;
mod receive_messages;
mod send_message;
mod sub_protocol;
mod whoami;

pub use link_device::{DecryptedProvision, ProvisioningUrl};

#[derive(Clone)]
pub struct WebAPIClient {
    pub server_host: String,
    pub http_client: Client,
}

impl WebAPIClient {
    fn ws_host(&self) -> String {
        self.server_host
            .replace("http://", "ws://")
            .replace("https://", "wss://")
    }
}
