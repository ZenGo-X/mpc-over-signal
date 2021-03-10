use anyhow::{Context, Result};
use rand::rngs::OsRng;
use structopt::StructOpt;

use actix::utils::Condition;
use futures::channel::oneshot;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

use crate::device::Device;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/signalservice.rs"));
}

mod cli;
mod device;
mod device_keys;
mod helpers;
mod webapi;

#[actix_rt::main]
async fn main() -> Result<()> {
    let args: cli::App = StructOpt::from_args();

    match args.cmd {
        cli::Cmd::Login(args) => login(args).await,
        cli::Cmd::Whoami(args) => whoami(args).await,
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

    let device_keys =
        device_keys::DeviceKeys::generate(&mut OsRng, provisioning_msg.identity_key_pair)
            .context("generate device keys")?;

    println!("Registering device keys...");

    webapi::submit_device_keys(client, &creds, &device_keys)
        .await
        .context("submit generated keys")?;

    // Save keys
    let device = Device::new(creds, device_keys);
    let keys_content = serde_json::to_vec_pretty(&device).context("serialize device keys")?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut keys_file = options
        .open(args.keys)
        .await
        .context("cannot create keys file")?;

    keys_file
        .write_all(&keys_content)
        .await
        .context("write keys file")?;

    Ok(())
}

async fn whoami(args: cli::Whoami) -> Result<()> {
    let keys = tokio::fs::read(args.keys)
        .await
        .context("read secret keys file")?;
    let keys: Device = serde_json::from_slice(&keys).context("parse secret keys file")?;

    let client = webapi::default_http_client().context("construct default http client")?;
    let response = webapi::whoami(&client, &keys.creds)
        .await
        .context("performing request")?;

    println!("{:#?}", response);
    Ok(())
}
