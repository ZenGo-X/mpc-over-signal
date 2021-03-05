use std::time::Duration;

use actix_http::client::Connector;
use anyhow::{anyhow, Result};
use awc::Client;

pub fn default_http_client() -> Result<Client> {
    let mut root_certs = rustls::RootCertStore::empty();
    root_certs
        .add_pem_file(&mut &include_bytes!("../../signal-server.pem")[..])
        .map_err(|()| anyhow!("read root ca"))?;

    let mut tls_config = rustls::ClientConfig::new();
    tls_config.root_store = root_certs;

    let client = awc::Client::builder()
        .connector(
            Connector::new()
                .rustls(tls_config.into())
                .timeout(Duration::from_secs(30))
                .finish(),
        )
        .disable_timeout()
        .finish();

    Ok(client)
}
