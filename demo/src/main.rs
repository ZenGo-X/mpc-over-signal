use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use structopt::StructOpt;

use futures::channel::oneshot;
use futures::StreamExt;

use rand::rngs::OsRng;

use bls::basic_bls::BLSSignature;
use bls::threshold_bls::state_machine::keygen::{Keygen, LocalKey};
use bls::threshold_bls::state_machine::sign::Sign;
use curv::elliptic::curves::bls12_381::{g1::GE as GE1, g2::GE as GE2};
use curv::elliptic::curves::traits::ECPoint;
use mpc_over_signal::{DeviceStore, Group, ParticipantIdentity, SignalClient};

mod cli;
use cli::Cmd;

#[actix::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args: cli::App = StructOpt::from_args();
    match args.command {
        Cmd::Login(args) => login(args).await,
        Cmd::Me(args) => me(args).await,
        Cmd::Keygen(args) => keygen(args).await,
        Cmd::Sign(args) => sign(args).await,
        Cmd::Verify(args) => verify(args).await,
    }
}

async fn login(args: cli::LoginArgs) -> Result<()> {
    let signal_client = signal_client(args.server)
        .await
        .context("constructing signal client")?;

    let (provision_url_tx, provision_url) = oneshot::channel();
    let (device_tx, device) = oneshot::channel();
    let device_name = args.device_name;
    actix::spawn(async move {
        let device = signal_client
            .login(&mut OsRng, provision_url_tx, device_name)
            .await
            .context("login failed");
        let _ = device_tx.send(device);
    });

    match provision_url.await {
        Ok(url) => {
            println!();
            println!("To continue, scan following QR code using Signal app on your phone.");
            println!("On Android: Signal Settings → Linked Devices → '+' Button");
            println!("On iOS:     Signal Settings → Linked Devices → Link New Device");
            println!();
            qr2term::print_qr(url.to_string()).context("printing QR code")?
        }
        Err(_e) => {
            // real error will be discovered below
        }
    }

    let device = device.await.context("retrieving device")??;
    DeviceStore::new(device)
        .save_no_overwrite(args.secrets.path)
        .await
        .context("save secrets")?;

    println!();
    println!("MPC device successfully created");

    Ok(())
}

async fn me(args: cli::MeArgs) -> Result<()> {
    let device = DeviceStore::from_file(args.secrets.path)
        .await
        .context("read device from file")?;
    let device = device.read().await;
    let me = device.me();
    if args.json {
        let json = serde_json::to_string(&me).context("serialize")?;
        println!("{}", json);
    } else {
        println!("Name:       {}", me.addr.name());
        println!("Device ID:  {}", me.addr.device_id());
        println!("Public key: {}", base64::encode(me.public_key.serialize()));
    }
    Ok(())
}

async fn keygen(args: cli::KeygenArgs) -> Result<()> {
    let signal_client = signal_client(args.server)
        .await
        .context("constructing signal client")?;
    let mut device_secrets = DeviceStore::from_file(&args.secrets.path)
        .await
        .context("read device from file")?;
    let me = device_secrets.read().await.me();

    let group = read_group(args.group).await.context("read group")?;
    let my_ind = match group.party_index(&me.addr) {
        Some(i) => i,
        None => bail!("group must contain this party too"),
    };

    ensure!(
        group.parties_count() == args.parties,
        "protocol expected to have {} parties (from `-n` option), but group file contains {} parties",
        args.parties, group.parties_count()
    );
    ensure!(args.parties > 1, "at least two parties required");
    ensure!(
        args.parties >= args.threshold,
        "threshold value is more than number of parties"
    );

    let public_key = keygen_run(
        signal_client,
        device_secrets.clone(),
        group,
        me,
        my_ind,
        args.threshold,
        args.parties,
        args.output,
    )
    .await;

    if let Err(err) = device_secrets.save(args.secrets.path).await {
        tracing::event!(tracing::Level::ERROR, %err, "Failed to save secrets to file");
    }

    println!("Public key: {}", hex::encode(public_key?));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn keygen_run(
    signal_client: SignalClient,
    device_secrets: DeviceStore,
    group: Group,
    me: ParticipantIdentity,
    i: u16,
    t: u16,
    n: u16,
    output: impl AsRef<Path>,
) -> Result<Vec<u8>> {
    device_secrets
        .write()
        .await
        .trust_to(&group)
        .context("adding trust to the group")?;

    let mut signal_client = signal_client
        .start_listening_for_incoming_messages(device_secrets)
        .await
        .context("connecting to signal api")?;
    let (incoming, outgoing) = signal_client
        .join_computation(me.addr, group)
        .await
        .context("join computation")?;
    let incoming = incoming.fuse();

    let initial = Keygen::new(i, t, n).context("create initial state")?;
    let local_key = round_based::AsyncProtocol::new(initial, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("execute keygen protocol: {}", e))?;

    save_local_key(&local_key, output)
        .await
        .context("save local key to file")?;

    let public_key = ECPoint::pk_to_key_slice(&local_key.public_key());
    Ok(public_key)
}

async fn sign(args: cli::SignArgs) -> Result<()> {
    let signal_client = signal_client(args.server)
        .await
        .context("constructing signal client")?;
    let mut device_secrets = DeviceStore::from_file(&args.secrets.path)
        .await
        .context("read device from file")?;
    let me = device_secrets.read().await.me();

    let group = read_group(args.group).await.context("read group")?;
    let my_ind = match group.party_index(&me.addr) {
        Some(i) => i,
        None => bail!("group must contain this party too"),
    };

    let local_key = read_local_key(args.local_key)
        .await
        .context("read local key")?;

    let signature = sign_run(
        signal_client,
        device_secrets.clone(),
        group,
        me,
        my_ind,
        local_key,
        args.digits,
    )
    .await;

    if let Err(err) = device_secrets.save(args.secrets.path).await {
        tracing::event!(tracing::Level::ERROR, %err, "Failed to save secrets to file");
    }

    println!("Signature: {}", hex::encode(signature?));
    Ok(())
}

async fn sign_run(
    signal_client: SignalClient,
    device_secrets: DeviceStore,
    group: Group,
    me: ParticipantIdentity,
    i: u16,
    local_key: LocalKey,
    message: Vec<u8>,
) -> Result<Vec<u8>> {
    let n = group.parties_count();
    let mut signal_client = signal_client
        .start_listening_for_incoming_messages(device_secrets)
        .await
        .context("connecting to signal api")?;
    let (incoming, outgoing) = signal_client
        .join_computation(me.addr, group)
        .await
        .context("join computation")?;
    let incoming = incoming.fuse();

    let initial =
        Sign::new(message, i, n, local_key).context("constructing signing initial state")?;
    let (_, sig) = round_based::AsyncProtocol::new(initial, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("executing signing: {}", e))?;

    let public_key = ECPoint::pk_to_key_slice(&sig.sigma);
    Ok(public_key)
}

async fn verify(args: cli::VerifyArgs) -> Result<()> {
    let public_key =
        hex::decode(args.public_key).context("public key is not valid hex encoded string")?;
    let signature =
        hex::decode(args.signature).context("signature key is not valid hex encoded string")?;

    let signature = GE1::from_bytes(&signature)
        .map_err(|e| anyhow!("signature is not valid g1 point: {:?}", e))?;
    let public_key = GE2::from_bytes(&public_key)
        .map_err(|e| anyhow!("public key is not valid g2 point: {:?}", e))?;

    let valid = BLSSignature { sigma: signature }.verify(&args.digits, &public_key);
    if valid {
        println!("Signature is valid");
    } else {
        bail!("Signature is not valid");
    }

    Ok(())
}

async fn signal_client(server: cli::SignalServer) -> Result<SignalClient> {
    let mut builder = SignalClient::builder()?;
    builder.set_server_host(server.host)?;

    if let Some(cert) = server.certificate {
        let cert = tokio::fs::read(cert).await.context("read certificate")?;

        let mut root_certs = rustls::RootCertStore::empty();
        root_certs
            .add_pem_file(&mut cert.as_slice())
            .map_err(|()| anyhow!("parse certificate"))?;

        let mut tls_config = rustls::ClientConfig::new();
        tls_config.root_store = root_certs;

        let client = awc::Client::builder()
            .connector(
                awc::Connector::new()
                    .rustls(tls_config.into())
                    .timeout(Duration::from_secs(30))
                    .finish(),
            )
            .disable_timeout()
            .finish();

        builder.set_http_client(client);
    }

    Ok(builder.finish())
}

async fn read_group(path: impl AsRef<Path>) -> Result<Group> {
    let file_content = tokio::fs::read(path).await.context("read group file")?;
    let parties_raw =
        serde_json::Deserializer::from_slice(&file_content).into_iter::<ParticipantIdentity>();
    let mut parties = vec![];
    for (i, party) in parties_raw.enumerate() {
        parties.push(party.context(format!("parse {} party", i))?)
    }
    Ok(Group::new(parties))
}

async fn save_local_key(local_key: &LocalKey, output: impl AsRef<Path>) -> Result<()> {
    let serialized = serde_json::to_vec_pretty(local_key).context("serialize")?;
    tokio::fs::write(output, serialized).await.context("write")
}

async fn read_local_key(path: impl AsRef<Path>) -> Result<LocalKey> {
    let content = tokio::fs::read(path).await.context("read")?;
    serde_json::from_slice(&content).context("deserialize")
}
