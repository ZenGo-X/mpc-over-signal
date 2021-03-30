use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::time;

use tracing::{event, Level};

use libsignal_protocol::{IdentityKey, ProtocolAddress};
use mpc_over_signal::{DeviceStore, Group, ParticipantIdentity, SignalClient};

#[derive(StructOpt)]
struct Args {
    #[structopt(long)]
    destination: String,
    #[structopt(long)]
    destination_device: u32,
    #[structopt(long)]
    destination_identity: String,
    #[structopt(long)]
    secrets_file: PathBuf,
    #[structopt(long)]
    #[structopt(conflicts_with = "pong")]
    ping: bool,
    #[structopt(long)]
    #[structopt(conflicts_with = "ping")]
    pong: bool,
}

#[derive(StructOpt)]
enum Kind {
    Ping,
    Pong,
}

#[derive(Serialize, Deserialize, Debug)]
enum Msg {
    Ping { i: u16 },
    Pong { i: u16 },
}

#[actix::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args: Args = StructOpt::from_args();

    let mut secrets = DeviceStore::from_file(&args.secrets_file).await?;
    let me = { secrets.read().await.me() };

    let remote_address = ProtocolAddress::new(args.destination, args.destination_device);
    let remote_public_key =
        base64::decode(args.destination_identity).context("decode base64 identity key")?;
    let remote_public_key = IdentityKey::decode(&remote_public_key)
        .map_err(|e| anyhow!("parse identity key: {}", e))?;
    let group = Group::new(vec![
        ParticipantIdentity {
            addr: remote_address.clone(),
            public_key: remote_public_key,
        },
        me.clone(),
    ]);

    let me_ind = group.party_index(&me.addr).unwrap();
    let other_ind = group.party_index(&remote_address).unwrap();

    secrets.write().await.trust_to(&group)?;

    let mut client = SignalClient::new()?
        .start_listening_for_incoming_messages(secrets.clone())
        .await?;
    let (incoming, outgoing) = client.join_computation(me.addr, group).await?;

    let ping_pong: Pin<Box<dyn Future<Output = Result<()>>>> = if args.ping {
        Box::pin(ping(me_ind, other_ind, incoming, outgoing))
    } else if args.pong {
        Box::pin(pong(me_ind, other_ind, incoming, outgoing))
    } else {
        bail!("no --ping or --pong were specified");
    };

    let result: Result<()>;
    tokio::select! {
        r = ping_pong => {
            result = r
        },
        r = tokio::signal::ctrl_c() => {
            result = r
                .context("receiving ctrl-c signal")
                .and(Err(anyhow!("ping pong was terminated by Ctrl-C")))
        }
    }

    event!(Level::TRACE, "ping pong finished, save secrets");
    if let Err(e) = secrets.save(args.secrets_file).await {
        event!(Level::ERROR, err = %e, "can't save new secrets to file")
    }

    result
}

async fn ping(
    sender: u16,
    receiver: u16,
    mut incoming: impl Stream<Item = Result<round_based::Msg<Msg>>> + Unpin,
    mut outgoing: impl Sink<round_based::Msg<Msg>, Error = anyhow::Error> + Unpin,
) -> Result<()> {
    for i in 1.. {
        let m = round_based::Msg {
            sender,
            receiver: Some(receiver),
            body: Msg::Ping { i },
        };
        event!(Level::INFO, msg = ?m, "Send");

        outgoing.send(m).await?;

        let msg = incoming.next().await.context("received eof")??;
        event!(Level::INFO, ?msg, "Recv");

        time::sleep(time::Duration::from_secs(5)).await;
    }
    Ok(())
}

async fn pong(
    sender: u16,
    receiver: u16,
    mut incoming: impl Stream<Item = Result<round_based::Msg<Msg>>> + Unpin,
    mut outgoing: impl Sink<round_based::Msg<Msg>, Error = anyhow::Error> + Unpin,
) -> Result<()> {
    loop {
        let msg = incoming.next().await.context("received eof")??;
        event!(Level::INFO, ?msg, "Recv");

        if let Msg::Ping { i } = msg.body {
            let response = round_based::Msg {
                sender,
                receiver: Some(receiver),
                body: Msg::Pong { i },
            };
            event!(Level::INFO, msg = ?response, "Send");
            outgoing.send(response).await?;
        }
    }
}
