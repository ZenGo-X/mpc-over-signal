use std::path::PathBuf;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "cli", about = "MPC over Signal")]
pub struct App {
    #[structopt(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, StructOpt)]
pub enum Cmd {
    /// Logins to Signal by linking to application on your phone
    Login(Login),
    Whoami(Whoami),
    TrustTo(AddTrust),
    Me(Me),
    Send(SendMessage),
}

#[derive(Debug, StructOpt)]
pub struct Login {
    /// A successful login will produce keys file containing sensitive information that should be
    /// kept in secret! File will include: identity secret key, encryption/decryption keys, etc.
    #[structopt(long, default_value = "secret-keys.json")]
    pub keys: PathBuf,
}

#[derive(Debug, StructOpt)]
pub struct Whoami {
    /// Path to a file containing device private keys
    #[structopt(long, default_value = "secret-keys.json")]
    pub keys: PathBuf,
}

#[derive(Debug, StructOpt)]
pub struct AddTrust {
    #[structopt(index = 1)]
    pub name: String,
    #[structopt(index = 2)]
    pub device_id: u32,
    #[structopt(index = 3, name = "public_key")]
    pub public_key_64: String,

    /// Path to a file containing device private keys
    #[structopt(long, default_value = "secret-keys.json")]
    pub keys: PathBuf,
}

#[derive(Debug, StructOpt)]
pub struct Me {
    /// Path to a file containing device private keys
    #[structopt(long, default_value = "secret-keys.json")]
    pub keys: PathBuf,
}

#[derive(Debug, StructOpt)]
pub struct SendMessage {
    #[structopt(index = 1)]
    pub receiver_name: String,
    #[structopt(index = 2)]
    pub receiver_device_id: u32,
    #[structopt(index = 3)]
    pub message: String,

    /// Path to a file containing device private keys
    #[structopt(long, default_value = "secret-keys.json")]
    pub keys: PathBuf,
}
