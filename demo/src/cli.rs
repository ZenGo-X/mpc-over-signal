use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
/// Demo CLI
pub struct App {
    #[structopt(long)]
    pub debug: bool,
    #[structopt(subcommand)]
    pub command: Cmd,
}

#[derive(StructOpt, Debug)]
pub enum Cmd {
    #[structopt(display_order = 1)]
    Login(LoginArgs),
    #[structopt(display_order = 2)]
    Me(MeArgs),
    #[structopt(display_order = 3)]
    Keygen(KeygenArgs),
    #[structopt(display_order = 4)]
    Sign(SignArgs),
    #[structopt(display_order = 5)]
    Verify(VerifyArgs),
}

#[derive(StructOpt, Debug)]
pub struct SignalServer {
    /// Signal Server URL
    ///
    /// Allows overriding Signal Server URL in case if you're using own-hosted Signal Server
    #[structopt(
        long = "signal-host",
        default_value = "https://textsecure-service.whispersystems.org/",
        display_order = 21
    )]
    pub host: String,
    /// Path to PEM-encoded certificate
    ///
    /// Sets root of trust in establishing secure connection to server. By default, original
    /// Signal Server certificate is used.
    #[structopt(long = "signal-cert", display_order = 22)]
    pub certificate: Option<PathBuf>,
}

#[derive(StructOpt, Debug)]
pub struct SecretsFile {
    /// Path to file containing sensitive information like secrets keys and tokens
    ///
    /// Keep it in secret! Information in this file can be used to perform actions on behalf of
    /// your account: send, receive messages, edit profile info, etc.
    #[structopt(
        long = "secrets-file",
        default_value = "secrets.json",
        display_order = 20
    )]
    pub path: PathBuf,
}

#[derive(StructOpt, Debug)]
/// Pairs your Signal app account with MPC device that will be used to send and receive MPC messages
///
/// You will be prompted to scan QR code that allow us linking with your Signal account. New device
/// will be displayed in "Linked Devices" in Signal app on your phone and you'll be able to unlink
/// it at any moment.
///
/// Not that after logging in, this app will receive your private identity and profile keys and
/// will save them in `secrets-file` (see `--secrets-file` option).
pub struct LoginArgs {
    /// Device name that will be associated with a new device
    ///
    /// It will be displayed in "Linked Devices" in Signal app on your phone.
    #[structopt(long, default_value = "MPC-over-Signal device", display_order = 1)]
    pub device_name: String,
    #[structopt(flatten)]
    pub secrets: SecretsFile,
    #[structopt(flatten)]
    pub server: SignalServer,
}

#[derive(StructOpt, Debug)]
/// Prints information about MPC device: account name, device id, public key
pub struct MeArgs {
    /// Prints your visit card in json format
    #[structopt(long)]
    pub json: bool,
    #[structopt(flatten)]
    pub secrets: SecretsFile,
}

#[derive(StructOpt, Debug)]
/// Distributed key generation
pub struct KeygenArgs {
    /// Threshold value `t`.
    ///
    /// `t`+1 parties will be required to perform signing
    #[structopt(short = "t", long, display_order = 1)]
    pub threshold: u16,
    /// Number of parties involved in keygen
    #[structopt(short = "n", long, display_order = 1)]
    pub parties: u16,
    /// Path to file containing addresses and public keys of every party of the protocol
    #[structopt(long, display_order = 2)]
    pub group: PathBuf,
    /// Path to file where to save resulting local party key
    ///
    /// If file already exist, it will be overwritten
    #[structopt(short, long, display_order = 3)]
    pub output: PathBuf,

    #[structopt(flatten)]
    pub secrets: SecretsFile,
    #[structopt(flatten)]
    pub server: SignalServer,
}

#[derive(StructOpt, Debug)]
/// Threshold signing
pub struct SignArgs {
    /// Path to local secret key file obtained after keygen
    #[structopt(long, display_order = 1)]
    pub local_key: PathBuf,

    /// Path to file containing addresses and public keys of every party of the signing protocol
    #[structopt(long, display_order = 2)]
    pub group: PathBuf,

    /// Message to sign
    #[structopt(long, parse(from_str), display_order = 3)]
    pub digits: Bytes,

    #[structopt(flatten)]
    pub secrets: SecretsFile,
    #[structopt(flatten)]
    pub server: SignalServer,
}

type Bytes = Vec<u8>;

#[derive(StructOpt, Debug)]
/// Locally verifies that message matches signature
pub struct VerifyArgs {
    /// Public key which was used to sign message
    #[structopt(long)]
    pub public_key: String,
    /// Signature
    #[structopt(long)]
    pub signature: String,
    /// Being verified message
    #[structopt(long, parse(from_str))]
    pub digits: Bytes,
}
