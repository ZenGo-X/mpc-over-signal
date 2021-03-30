use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use structopt::StructOpt;

use futures::channel::oneshot;

use rand::rngs::OsRng;

#[derive(Debug, StructOpt)]
pub struct Args {
    #[structopt(long, default_value = "MPC-over-Signal device")]
    pub device_name: String,
    /// A successful login will produce keys file containing sensitive information that should be
    /// kept in secret! File will include: identity secret key, encryption/decryption keys, etc.
    #[structopt(long, default_value = "secrets.json")]
    pub secrets_file: PathBuf,
}

#[actix::main]
async fn main() -> Result<()> {
    let Args {
        device_name,
        secrets_file,
    } = StructOpt::from_args();

    let (provision_url_tx, provision_url) = oneshot::channel();
    let (device_tx, device) = oneshot::channel();

    let signal_client = mpc_over_signal::SignalClient::new()?;
    actix::spawn(async move {
        let device = signal_client
            .login(&mut OsRng, provision_url_tx, device_name)
            .await;
        let _ = device_tx.send(device);
    });

    match provision_url.await {
        Ok(url) => {
            println!();
            println!("To continue, scan following QR code using Signal app on your phone.");
            println!("On Android: Signal Settings → Linked Devices → '+' Button");
            println!("On iOS:     Signal Settings → Linked Devices → Link New Device");
            println!();
            qr2term::print_qr(url.to_string()).context("render provisioning QR code")?;
        }
        Err(_e) => {
            // Actual error will be received below
        }
    }

    let device = match device.await {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            bail!("signing in failed: {}", e)
        }
        Err(canceled) => {
            bail!("signing in future was canceled: {}", canceled);
        }
    };

    let me = device.me();

    println!();
    println!("You successfully logged in.");
    println!("Your name:                {}", me.addr.name());
    println!("Your device id:           {}", me.addr.device_id());
    println!(
        "Your identity public key: {}",
        base64::encode(me.public_key.serialize())
    );

    mpc_over_signal::DeviceStore::new(device)
        .save_no_overwrite(secrets_file)
        .await?;

    Ok(())
}
