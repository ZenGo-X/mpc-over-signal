use std::convert::TryFrom;

use anyhow::{anyhow, bail, ensure, Context, Result};
use derivative::Derivative;
use futures::{SinkExt, StreamExt};
use prost::Message as _;
use serde::{Deserialize, Serialize};

use actix_http::client::Connector;
use awc::ws::{Frame, Message};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/signalservice.rs"));
}

use block_modes::BlockMode;
use proto::web_socket_message::Type;
use rand::rngs::OsRng;
use rand::Rng;
use std::time::Duration;

#[actix_rt::main]
async fn main() -> Result<()> {
    // Generate provision cipher
    let provision_cipher = libsignal_protocol::KeyPair::generate(&mut OsRng);

    // Connect to provisioning API
    let mut root_certs = rustls::RootCertStore::empty();
    root_certs
        .add_pem_file(&mut &include_bytes!("../signal-server.pem")[..])
        .map_err(|()| anyhow!("read root ca"))?;

    let mut tls_config = rustls::ClientConfig::new();
    tls_config.root_store = root_certs;

    let (_resp, mut conn) = awc::Client::builder()
        .connector(Connector::new().rustls(tls_config.into()).timeout(Duration::from_secs(30)).finish())
        .disable_timeout()
        .finish()
        .ws("wss://textsecure-service.whispersystems.org/v1/websocket/provisioning/?agent=mpc-over-signal&version=0.1")
        .connect()
        .await
        .map_err(|e| anyhow!("connecting to Signal Provisioning API: {:?}", e))?;

    // Receive provisioning address
    let msg = conn
        .next()
        .await
        .context("receiving address")?
        .context("receiving address")?;
    let msg = match msg {
        Frame::Binary(msg) => msg,
        _ => bail!("unexpected msg: {:?}", msg),
    };

    let req = proto::WebSocketMessage::decode(msg.as_ref()).context("parse address req")?;
    ensure!(
        req.r#type() == Type::Request,
        "expected to receive request, received {:?}",
        req.r#type()
    );
    ensure!(req.request.is_some(), "missing request body");

    let req = req.request.expect("guaranteed by ensure! above");
    let req_id = req.id;
    ensure!(
        req.verb() == "PUT" && req.path() == "/v1/address",
        "expected PUT /v1/address request, received {} {}",
        req.verb(),
        req.path(),
    );

    let req = proto::ProvisioningUuid::decode(req.body()).context("parse request body")?;
    let public_key_bytes = provision_cipher.public_key.serialize();
    let provisioning_url = format!(
        "tsdevice:/?uuid={}&pub_key={}",
        req.uuid(),
        urlencoding::encode(&base64::encode(&public_key_bytes))
    );

    let resp = proto::WebSocketMessage {
        r#type: Some(Type::Response as _),
        request: None,
        response: Some(proto::WebSocketResponseMessage {
            id: req_id,
            status: Some(200),
            message: Some("OK".into()),
            headers: vec![],
            body: None,
        }),
    };
    let mut resp_bytes: Vec<u8> = vec![];
    resp.encode(&mut resp_bytes).context("encode response")?;
    conn.send(Message::Binary(resp_bytes.into()))
        .await
        .context("send response")?;

    // Display provisioning url
    println!("Provisioning url: {}", provisioning_url);
    println!("QR code:");
    qr2term::print_qr(&provisioning_url).context("print QR code")?;

    // Receive provisioning message
    let msg = conn
        .next()
        .await
        .context("receiving provisioning message")?
        .context("receiving provisioning message")?;
    let msg = match msg {
        Frame::Binary(msg) => msg,
        _ => bail!("unexpected msg: {:?}", msg),
    };

    let req = proto::WebSocketMessage::decode(msg.as_ref()).context("parse address req")?;
    ensure!(
        req.r#type() == Type::Request,
        "expected to receive request, received {:?}",
        req.r#type()
    );
    ensure!(req.request.is_some(), "missing request body");

    let req = req.request.expect("guaranteed by ensure! above");
    let req_id = req.id;
    ensure!(
        req.verb() == "PUT" && req.path() == "/v1/message",
        "expected PUT /v1/message request, received {} {}",
        req.verb(),
        req.path(),
    );

    let req = proto::ProvisionEnvelope::decode(req.body()).context("parse request body")?;

    let resp = proto::WebSocketMessage {
        r#type: Some(Type::Response as _),
        request: None,
        response: Some(proto::WebSocketResponseMessage {
            id: req_id,
            status: Some(200),
            message: Some("OK".into()),
            headers: vec![],
            body: None,
        }),
    };
    let mut resp_bytes: Vec<u8> = vec![];
    resp.encode(&mut resp_bytes).context("encode response")?;
    conn.send(Message::Binary(resp_bytes.into()))
        .await
        .context("send response")?;
    SinkExt::close(&mut conn)
        .await
        .context("close provision connection")?;

    let provision = decrypt_provision_message(provision_cipher, req)?;

    println!("Received provision: {:#?}", provision);

    let device = create_device(
        &mut OsRng,
        &provision,
        "Transport-over-signal device".into(),
    )
    .await?;

    println!("Created device: {:#?}", device);

    Ok(())
}

#[derive(Derivative)]
#[derivative(Debug)]
struct DecryptedProvision {
    #[derivative(Debug = "ignore")]
    identity_key_pair: libsignal_protocol::IdentityKeyPair,
    number: String,
    uuid: String,
    provisioning_code: String,
    user_agent: String,
    read_receipts: bool,
    #[derivative(Debug = "ignore")]
    profile_key: Option<Vec<u8>>,
}

fn decrypt_provision_message(
    key_pair: libsignal_protocol::KeyPair,
    msg: proto::ProvisionEnvelope,
) -> Result<DecryptedProvision> {
    use aes::Aes256;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, Cbc};
    use hmac::{Hmac, Mac, NewMac};
    use sha2::Sha256;

    let master_ephemeral = libsignal_protocol::PublicKey::deserialize(msg.public_key())
        .map_err(|e| anyhow!("deserialize master ephemeral key: {}", e))?;
    let msg: &[u8] = msg.body();

    ensure!(msg.len() >= 1 + 16 + 32, "message too small");
    ensure!(msg[0] == 1, "bad version number on ProvisioningMessage");

    let iv = &msg[1..16 + 1];
    let mac = &msg[msg.len() - 32..];
    let iv_and_ciphertext = &msg[..msg.len() - 32];
    let ciphertext = &msg[16 + 1..msg.len() - 32];

    let agreement = key_pair
        .private_key
        .calculate_agreement(&master_ephemeral)
        .map_err(|e| anyhow!("calculate agreement: {}", e))?;

    let key = libsignal_protocol::HKDF::new(3)
        .map_err(|e| anyhow!("create hkdf: {}", e))?
        .derive_secrets(&agreement, b"TextSecure Provisioning Message", 64)
        .map_err(|e| anyhow!("calculate hkdf: {}", e))?;
    let decryption_key = &key[..32];
    let verification_key = &key[32..64];

    let mut verification =
        Hmac::<Sha256>::new_varkey(&verification_key).map_err(|e| anyhow!("create hmac: {}", e))?;
    verification.update(iv_and_ciphertext);
    verification
        .verify(mac)
        .map_err(|_| anyhow!("invalid mac"))?;

    let mut plaintext = vec![0u8; ciphertext.len()];
    plaintext.copy_from_slice(ciphertext);

    let plaintext = Cbc::<Aes256, Pkcs7>::new_var(decryption_key, iv)
        .context("init aes-cbc")?
        .decrypt(&mut plaintext)
        .context("decrypt provision message")?;

    let msg = proto::ProvisionMessage::decode(&*plaintext).context("decode provision message")?;

    let priv_key = libsignal_protocol::PrivateKey::deserialize(msg.identity_key_private())
        .map_err(|e| anyhow!("decode identity private key: {}", e))?;
    let identity_key_pair = libsignal_protocol::IdentityKeyPair::try_from(priv_key)
        .map_err(|e| anyhow!("convert private key to identity key pair: {}", e))?;

    Ok(DecryptedProvision {
        identity_key_pair,
        number: msg.number.unwrap_or_default(),
        provisioning_code: msg.provisioning_code.unwrap_or_default(),
        user_agent: msg.user_agent.unwrap_or_default(),
        read_receipts: msg.read_receipts.unwrap_or_default(),
        profile_key: msg.profile_key,
        uuid: msg.uuid.unwrap_or_default(),
    })
}

#[derive(Debug)]
struct Device {
    pub username: String,
    pub device_id: u64,
    pub password_64: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateDeviceRequest {
    pub name: String,
    pub fetches_messages: bool,
    pub registration_id: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateDeviceResponse {
    pub device_id: u64,
}

async fn create_device<R: rand::Rng + rand::CryptoRng>(
    rnd: &mut R,
    provision: &DecryptedProvision,
    device_name: String,
) -> Result<Device> {
    use awc::http::StatusCode;

    let mut password = [0u8; 16];
    rnd.fill_bytes(&mut password);
    let mut password_64 = base64::encode(password);
    password_64.drain(password_64.len() - 2..);

    let registration_id = rnd.gen::<u16>() & 0x3fff;

    let request_body = CreateDeviceRequest {
        name: device_name,
        fetches_messages: false,
        registration_id,
    };

    let mut root_certs = rustls::RootCertStore::empty();
    root_certs
        .add_pem_file(&mut &include_bytes!("../signal-server.pem")[..])
        .map_err(|()| anyhow!("read root ca"))?;

    let mut tls_config = rustls::ClientConfig::new();
    tls_config.root_store = root_certs;

    let mut response = awc::Client::builder()
        .connector(
            Connector::new()
                .rustls(tls_config.into())
                .timeout(Duration::from_secs(30))
                .finish(),
        )
        .disable_timeout()
        .finish()
        .put(format!(
            "https://textsecure-service.whispersystems.org/v1/devices/{}",
            provision.provisioning_code
        ))
        .basic_auth(&provision.number, Some(&password_64))
        .send_json(&request_body)
        .await
        .map_err(|e| anyhow!("creating new device: {}", e))?;

    ensure!(
        response.status() == StatusCode::OK,
        "creating new device: server returned {}",
        response.status()
    );

    let created_device: CreateDeviceResponse =
        response.json().await.context("parse server response")?;

    Ok(Device {
        username: format!("{}.{}", provision.number, created_device.device_id),
        device_id: created_device.device_id,
        password_64,
    })
}
