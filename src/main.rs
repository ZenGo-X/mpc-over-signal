use anyhow::{anyhow, Context, Result};
use rand::rngs::OsRng;
use structopt::StructOpt;

use actix::utils::Condition;
use futures::channel::oneshot;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

use crate::device::Device;
use libsignal_protocol::{ProtocolAddress, PublicKey};
use std::path::Path;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/signalservice.rs"));
}

mod cli;
mod device;
mod helpers;
mod webapi;

#[actix_rt::main]
async fn main() -> Result<()> {
    let args: cli::App = StructOpt::from_args();

    match args.cmd {
        cli::Cmd::Login(args) => login(args).await,
        cli::Cmd::Whoami(args) => whoami(args).await,
        cli::Cmd::TrustTo(args) => add_trust(args).await,
        cli::Cmd::Me(args) => me(args).await,
    }
}

async fn login(args: cli::Login) -> Result<()> {
    let mut rnd = OsRng;
    let rnd = &mut rnd;

    let client = webapi::default_http_client().context("construct default http client")?;
    let client = &client;

    let mut provisioning_url_event = Condition::default();
    let provisioning_url = provisioning_url_event.wait();
    let (provisioning_msg_event, provisioning_msg) = oneshot::channel();

    println!("Establishing provisioning channel...");
    actix::spawn(async {
        let _ = provisioning_msg_event.send(
            webapi::link_device(
                &mut OsRng,
                &webapi::default_http_client().unwrap(),
                provisioning_url_event,
            )
            .await,
        );
    });

    let provisioning_url = provisioning_url
        .await
        .context("obtaining provisioning url")?;

    println!();
    println!("To continue, scan following QR code using Signal app on your phone.");
    println!("On Android: Signal Settings → Linked Devices → '+' Button");
    println!("On iOS:     Signal Settings → Linked Devices → Link New Device");
    println!();

    qr2term::print_qr(provisioning_url.to_string()).context("render provisioning QR code")?;

    let provisioning_msg = provisioning_msg
        .await
        .context("obtaining provisioning message")??;

    println!("Received provisioning message: {:#?}", provisioning_msg);
    println!("Registering device...");

    let creds = webapi::create_device(
        rnd,
        client,
        &provisioning_msg,
        "MPC-over-Signal device".into(),
    )
    .await
    .context("register device")?;

    println!("Created device: {:#?}", creds);
    println!("Generating device keys...");

    let device_keys = device::DeviceKeys::generate(&mut OsRng, provisioning_msg.identity_key_pair)
        .context("generate device keys")?;

    println!("Registering device keys...");

    webapi::submit_device_keys(client, &creds, &device_keys)
        .await
        .context("submit generated keys")?;

    // Save keys
    device_write(&Device::new(creds, device_keys), args.keys, false).await?;

    Ok(())
}

async fn whoami(args: cli::Whoami) -> Result<()> {
    let device = device_read(args.keys).await?;

    let client = webapi::default_http_client().context("construct default http client")?;
    let response = webapi::whoami(&client, &device.creds)
        .await
        .context("performing request")?;

    println!("{:#?}", response);
    Ok(())
}

async fn add_trust(args: cli::AddTrust) -> Result<()> {
    let mut device = device_read(&args.keys).await?;

    let address = ProtocolAddress::new(args.name, args.device_id);
    let public_key = base64::decode(args.public_key_64)
        .context("invalid public key: malformed base64 string")?;
    let public_key =
        PublicKey::deserialize(&public_key).map_err(|e| anyhow!("invalid public key: {}", e))?;

    device.keys.trusted_keys.insert(address, public_key.into());

    device_write(&device, args.keys, true).await?;

    Ok(())
}

async fn me(args: cli::Me) -> Result<()> {
    let device = device_read(args.keys).await?;

    let pk = base64::encode(device.keys.identity_key_pair.public_key().serialize());

    println!("Your name      : {}", device.creds.username.name);
    println!("     device_id : {}", device.creds.username.device_id);
    println!("     public key: {}", pk);
    println!();
    println!("You can add this device to another mpc-over-signal instance's");
    println!("list of trusted parties via following command:");
    println!(
        "  mpc-over-signal trust-to {} {} {}",
        device.creds.username.name, device.creds.username.device_id, pk
    );
    println!();

    Ok(())
}

async fn device_read(path: impl AsRef<Path>) -> Result<Device> {
    let device = tokio::fs::read(path)
        .await
        .context("read secret keys file")?;
    serde_json::from_slice(&device).context("parse secret keys file")
}

async fn device_write(device: &Device, path: impl AsRef<Path>, may_overwrite: bool) -> Result<()> {
    let device_content = serde_json::to_vec_pretty(device).context("serialize device")?;

    let mut options = OpenOptions::new();

    #[cfg(unix)]
    options.mode(0o600);
    options.write(true);
    if may_overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let mut device_file = options
        .open(path)
        .await
        .context("cannot create keys file")?;

    device_file
        .write_all(&device_content)
        .await
        .context("write keys file")?;

    Ok(())
}
